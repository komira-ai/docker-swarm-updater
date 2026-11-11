//! The deploy runner end to end (docs/design.md sections 3.2 to 3.6): a release served by
//! the fake release server, verified with a test signing chain, pushed to the fake registry
//! and rolled out by the fake Swarm. A test waits for a deploy's end on the state store's own
//! change notifications, never on a timer.

mod fetching;
mod restart;
mod retention;
mod update;

use std::path::Path;

use dsu_core::config::{Config, ServiceConfig};
use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_core::record::{CallerRecord, ErrorToken, NewRecord, Phase, Record, State};
use dsu_core::state::ServiceState;
use dsu_docker::DockerClient;
use dsu_server::fetch::roots_from_pem;
use dsu_testkit::docker::{Outcome, UpdateScript};
use dsu_testkit::mint::{Authority, Spec, signed_at};
use dsu_testkit::oci::{BuiltImage, OciImage};
use dsu_testkit::registry::{FakeRegistry, Mode};
use dsu_testkit::release::{ReleaseServer, Route};
use jiff::SignedDuration;
use serde_json::{Value, json};

use crate::harness::*;
use crate::support::FakeNetwork;

/// A release of one service: its image, its bundle and where the release server serves them.
struct Rel {
    service: &'static str,
    tag: String,
    file: String,
    image: BuiltImage,
    bundle: Vec<u8>,
    image_route: Option<Route>,
    bundle_route: Option<Route>,
    /// Further paths the release server answers (the targets of redirects).
    extra: Vec<(String, Route)>,
}

fn service_config(name: &str) -> ServiceConfig {
    let text = config_text(Path::new("/unused"), REGISTRY);
    let config = Config::parse(&text).unwrap();
    config
        .service(&ServiceName::parse(name).unwrap())
        .unwrap()
        .clone()
}

impl Rel {
    /// A good release of `service`: an image named by `label`, signed at [`signed_at`].
    fn new(authority: &Authority, service: &'static str, label: &str) -> Rel {
        Rel::made(
            authority,
            service,
            label,
            "v1",
            OciImage::new(&format!("{service}-{label}")).build(),
            |_| {},
        )
    }

    /// A release of `image` under release tag `tag`, its bundle's spec changed by `edit`.
    fn made(
        authority: &Authority,
        service: &'static str,
        label: &str,
        tag: &str,
        image: BuiltImage,
        edit: impl FnOnce(&mut Spec),
    ) -> Rel {
        let file = format!("{service}-{label}-linux-x86_64.image.tar");
        let tar_digest = Digest::from_sha256(sha2::Sha256::digest(&image.tar).into());
        let mut spec = Spec::github(&service_config(service).signer, &file, &tar_digest);
        edit(&mut spec);
        let bundle = authority.bundle(&spec).to_string().into_bytes();
        Rel {
            service,
            tag: tag.to_owned(),
            file,
            image,
            bundle,
            image_route: None,
            bundle_route: None,
            extra: Vec::new(),
        }
    }

    /// A release signed `by` before (negative) or after (positive) [`signed_at`].
    fn signed(
        authority: &Authority,
        service: &'static str,
        label: &str,
        by: SignedDuration,
    ) -> Rel {
        let image = OciImage::new(&format!("{service}-{label}")).build();
        Rel::made(authority, service, label, "v1", image, |spec| {
            spec.signed_at = signed_at() + by;
        })
    }

    fn digest(&self) -> Digest {
        self.image.manifest_digest.clone()
    }

    fn path(&self) -> String {
        format!(
            "/example-org/{}/releases/download/{}/{}",
            self.service, self.tag, self.file
        )
    }

    fn url(&self) -> String {
        format!("https://github.com{}", self.path())
    }

    /// The paths the release server answers and what it answers.
    fn routes(&self) -> Vec<(String, Route)> {
        let mut routes = vec![
            (
                self.path(),
                self.image_route
                    .clone()
                    .unwrap_or_else(|| Route::File(self.image.tar.clone())),
            ),
            (
                format!("{}.sigstore.json", self.path()),
                self.bundle_route
                    .clone()
                    .unwrap_or_else(|| Route::File(self.bundle.clone())),
            ),
        ];
        routes.extend(self.extra.clone());
        routes
    }

    fn body(&self) -> Vec<u8> {
        self.body_with(|_| {})
    }

    fn body_with(&self, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut body = json!({
            "image_digest": self.digest(),
            "image_url": self.url(),
            "bundle_url": format!("{}.sigstore.json", self.url()),
            "version": "1.0",
        });
        edit(&mut body);
        body.to_string().into_bytes()
    }

    fn reference(&self, registry: &str) -> String {
        format!("{registry}/{}@{}", self.service, self.digest())
    }
}

use sha2::Digest as _;

/// A registry, a release server and the environment of one updater, started together.
struct World {
    env: Env,
    registry: FakeRegistry,
    server: ReleaseServer,
}

impl World {
    /// Starts the world with the releases `build` makes from the environment's trusted chain.
    async fn new(mode: Mode, build: impl FnOnce(&Authority) -> Vec<Rel>) -> (World, Vec<Rel>) {
        let registry = FakeRegistry::start(mode).await;
        let env = Env::with_registry(&registry.addr()).await;
        let releases = build(&env.authority);
        let routes: Vec<(String, Route)> = releases.iter().flat_map(Rel::routes).collect();
        let server = ReleaseServer::start(
            routes
                .iter()
                .map(|(p, r)| (p.as_str(), r.clone()))
                .collect(),
        )
        .await;
        (
            World {
                env,
                registry,
                server,
            },
            releases,
        )
    }

    async fn one(build: impl FnOnce(&Authority) -> Rel) -> (World, Rel) {
        let (world, mut releases) = World::new(Mode::Normal, |a| vec![build(a)]).await;
        (world, releases.remove(0))
    }

    /// The options of an updater whose downloads reach the release server.
    fn options(&self) -> Options {
        Options {
            network: std::sync::Arc::new(FakeNetwork::new(self.server.port()).allowed()),
            tls_roots: roots_from_pem(self.server.ca_pem().as_bytes()).unwrap(),
            ..Options::default()
        }
    }

    /// A new updater process on the environment's state directory.
    async fn updater(&self) -> Updater {
        Updater::start(&self.env, self.options()).await
    }

    fn docker(&self) -> &dsu_testkit::docker::FakeDocker {
        self.env.docker()
    }

    fn script(&self, outcome: Outcome) {
        self.docker().set_script(UpdateScript::new(outcome));
    }

    /// The Docker client a test reads Swarm with; reading is what lets the fake's update go on.
    fn swarm(&self) -> DockerClient {
        DockerClient::new(self.docker().socket())
    }

    fn downloads(&self) -> Vec<String> {
        match std::fs::read_dir(self.env.state_dir().join("downloads")) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

async fn post(u: &Updater, rel: &Rel) -> Reply {
    post_body(u, rel, rel.body()).await
}

async fn post_body(u: &Updater, rel: &Rel, body: Vec<u8>) -> Reply {
    u.as_caller(&caller(rel.service), "POST", &deploys(rel.service), &body)
        .await
}

/// Deploys `rel` as its service's caller and waits for the record to end.
async fn run(u: &Updater, rel: &Rel) -> Record {
    let reply = post(u, rel).await;
    assert_eq!(
        reply.status,
        202,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    finished(&u.app, &deploy_id(&reply)).await
}

fn outcome(record: &Record) -> (State, Option<ErrorToken>) {
    (record.state, record.error.as_ref().map(|e| e.token))
}

fn phases(record: &Record) -> Vec<Phase> {
    record.steps.iter().map(|s| s.phase).collect()
}

async fn service_state(u: &Updater, name: &str) -> ServiceState {
    u.app
        .store
        .service_state(&ServiceName::parse(name).unwrap())
        .await
}

/// A running record of `service` for `digest` that went through `phases`, as a killed process
/// leaves it.
fn crafted(
    service: &str,
    digest: &Digest,
    id: &str,
    phases: &[Phase],
    now: jiff::Timestamp,
) -> Record {
    let mut record = Record::start(NewRecord {
        id: DeployId::parse(id).unwrap(),
        service: ServiceName::parse(service).unwrap(),
        swarm_service: format!("{service}_server"),
        image_digest: digest.clone(),
        version: "1.0".into(),
        caller: CallerRecord::Operator,
        allow_older: false,
        now,
    });
    for phase in phases {
        record.enter_phase(*phase, now).unwrap();
    }
    record.signed_time = Some(signed_at());
    record
}

const TO_WAITING: [Phase; 5] = [
    Phase::Fetching,
    Phase::Verifying,
    Phase::Pushing,
    Phase::Updating,
    Phase::Waiting,
];

#[tokio::test]
async fn a_good_release_converges_and_the_update_changes_three_fields() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let before = w.docker().service("app_server");
    let u = w.updater().await;
    let reply = post(&u, &rel).await;
    assert_eq!(reply.status, 202);
    let id = deploy_id(&reply);
    let record = finished(&u.app, &id).await;

    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::Updating,
            Phase::Waiting
        ]
    );
    assert!(record.steps.iter().all(|s| s.ended.is_some()));
    assert_eq!(record.phase, Phase::Done);
    assert_eq!(record.signed_time, Some(signed_at()));
    assert!(record.ended.is_some());
    let notes: Vec<&str> = record
        .steps
        .iter()
        .map(|s| s.note.as_deref().unwrap_or(""))
        .collect();
    assert!(notes[0].starts_with("image "), "{notes:?}");
    assert!(
        notes[1].starts_with("signed 2026-10-01T12:00:00Z"),
        "{notes:?}"
    );
    assert_eq!(
        notes[2],
        format!("pushed {}", rel.reference(&w.env.registry))
    );
    assert!(notes[4].starts_with("tasks: t1 running on "), "{notes:?}");

    // The registry holds the manifest by its digest, exactly as it was in the tar.
    let (media_type, bytes) = w.registry.manifest("app", &rel.digest()).unwrap();
    assert_eq!(
        (media_type.as_str(), &bytes),
        (rel.image.media_type, &rel.image.manifest)
    );

    // Swarm got the spec it had, with the image and the two labels changed.
    let updates = w.docker().updates();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].version, before.index);
    let mut expected = before.spec.clone();
    expected["TaskTemplate"]["ContainerSpec"]["Image"] = json!(rel.reference(&w.env.registry));
    expected["Labels"]["org.docker-swarm-updater.deploy"] = json!(id.as_str());
    expected["Labels"]["org.docker-swarm-updater.digest"] = json!(rel.digest());
    assert_ne!(updates[0].body, before.spec);
    assert_eq!(updates[0].body, expected);

    // The service's state: floor, converged list, what was pushed, no snapshot left.
    let state = service_state(&u, "app").await;
    assert_eq!(state.floor, Some(signed_at()));
    assert_eq!(state.converged_digests(), [rel.digest()]);
    assert!(state.pushed.contains(&rel.digest()));
    assert!(state.failed.is_empty());
    assert!(state.pending.is_none());
    // The downloaded files are gone.
    assert!(w.downloads().is_empty());

    // Status says the same, and so does the file.
    let status = u
        .as_caller(&caller("app"), "GET", &format!("/v1/deploys/{id}"), b"")
        .await;
    assert_eq!(status.json(), serde_json::to_value(&record).unwrap());
}

#[tokio::test]
async fn the_same_digest_after_it_converged_is_200_and_fetches_and_updates_nothing() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    let first = run(&u, &rel).await;
    let requests = w.server.requests().len();
    let updates = w.docker().updates().len();
    let again = post(&u, &rel).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.json()["id"], first.id.as_str());
    assert_eq!(again.json()["state"], "converged");
    assert_eq!(w.server.requests().len(), requests);
    assert_eq!(w.docker().updates().len(), updates);
}

#[tokio::test]
async fn the_same_digest_while_it_runs_is_200_and_another_digest_is_busy() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "app", "a"), Rel::new(a, "app", "b")]
    })
    .await;
    w.script(Outcome::NeverEnds);
    let u = w.updater().await;
    let first = post(&u, &rels[0]).await;
    let id = deploy_id(&first);
    wait_record(&u.app, &id, |r| r.phase == Phase::Waiting).await;
    let (requests, updates) = (w.server.requests().len(), w.docker().updates().len());

    let again = post(&u, &rels[0]).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.json()["id"], id.as_str());
    assert_eq!(again.json()["state"], "running");
    let other = post(&u, &rels[1]).await;
    assert_eq!((other.status, other.error().as_str()), (409, "busy"));
    assert!(
        other.json()["detail"]
            .as_str()
            .unwrap()
            .contains(id.as_str())
    );
    assert_eq!(
        (w.server.requests().len(), w.docker().updates().len()),
        (requests, updates)
    );
}

#[tokio::test]
async fn two_services_deploy_at_once_and_both_converge() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "app", "a"), Rel::new(a, "web", "a")]
    })
    .await;
    let u = w.updater().await;
    let (app, web) = (post(&u, &rels[0]).await, post(&u, &rels[1]).await);
    assert_eq!((app.status, web.status), (202, 202));
    let app = finished(&u.app, &deploy_id(&app)).await;
    let web = finished(&u.app, &deploy_id(&web)).await;
    assert_eq!(outcome(&app), (State::Converged, None));
    assert_eq!(outcome(&web), (State::Converged, None));
    assert!(w.registry.manifest("app", &rels[0].digest()).is_some());
    assert!(w.registry.manifest("web", &rels[1].digest()).is_some());
}

#[tokio::test]
async fn a_deploy_waits_to_be_asked_again_only_until_its_service_is_free() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "app", "a"), Rel::new(a, "app", "b")]
    })
    .await;
    let u = w.updater().await;
    assert_eq!(run(&u, &rels[0]).await.state, State::Converged);
    // The lock is gone with the final record: another digest of the service runs.
    assert_eq!(run(&u, &rels[1]).await.state, State::Converged);
}
