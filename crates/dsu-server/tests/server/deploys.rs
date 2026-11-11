//! The deploy runner end to end (docs/design.md sections 3.2 to 3.6): a release served by
//! the fake release server, verified with a test signing chain, pushed to the fake registry
//! and rolled out by the fake Swarm. A test waits for a deploy's end on the state store's own
//! change notifications, never on a timer.

use std::path::Path;

use dsu_core::config::{Config, ServiceConfig};
use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_core::record::{CallerRecord, ErrorToken, NewRecord, Phase, Record, State};
use dsu_core::state::ServiceState;
use dsu_core::swarm::Snapshot;
use dsu_docker::DockerClient;
use dsu_server::clock::Clock as _;
use dsu_server::fetch::{READ_TIMEOUT, roots_from_pem};
use dsu_server::runner::{RunnerError, recover};
use dsu_testkit::docker::{FakeTask, FakeUpdateStatus, Outcome, UpdateScript};
use dsu_testkit::mint::{Authority, Evidence, Identity, Spec, claim, signed_at};
use dsu_testkit::oci::{BuiltImage, Flaw, OciImage};
use dsu_testkit::registry::{Event, FakeRegistry, Mode};
use dsu_testkit::release::{ReleaseServer, Route};
use jiff::SignedDuration;
use serde_json::{Value, json};

use crate::harness::*;
use crate::support::{FakeDisk, FakeNetwork, HookDisk};

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

// fetch rows

#[tokio::test]
async fn fetch_rows_end_in_failed_records_and_leave_no_files() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let mut missing_image = Rel::new(a, "app", "a");
        missing_image.image_route = Some(Route::Status(404));
        let mut missing_bundle = Rel::new(a, "app", "b");
        missing_bundle.bundle_route = Some(Route::Status(404));
        let mut elsewhere = Rel::new(a, "app", "c");
        elsewhere.image_route = Some(Route::Redirect {
            status: 302,
            location: "https://evil.example/app.tar".into(),
        });
        let mut big_bundle = Rel::new(a, "web", "a");
        big_bundle.bundle_route = Some(Route::File(vec![0; 1024 * 1024 + 1]));
        let mut big_image = Rel::new(a, "web", "b");
        big_image.image_route = Some(Route::File(vec![0; 1024 * 1024 + 1]));
        vec![
            missing_image,
            missing_bundle,
            elsewhere,
            big_bundle,
            big_image,
        ]
    })
    .await;
    let u = w.updater().await;
    let expected = [
        ErrorToken::FetchFailed,
        ErrorToken::FetchFailed,
        ErrorToken::UrlNotAllowed,
        ErrorToken::TooLarge,
        ErrorToken::TooLarge,
    ];
    for (rel, token) in rels.iter().zip(expected) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.phase, Phase::Done);
        assert_eq!(record.steps.last().unwrap().phase, Phase::Fetching);
        // The downloaded files are removed, and the digest is not blocked.
        assert!(w.downloads().is_empty());
        assert!(
            !service_state(&u, rel.service)
                .await
                .is_failed(&rel.digest())
        );
    }
    // Nothing reached the registry or Swarm.
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

// bundle rows

#[tokio::test]
async fn a_bundle_of_another_workflow_fails_and_blocks_the_digest_until_the_operator_clears_it() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let image = OciImage::new("app-a").build();
        let mut signer = service_config("app").signer;
        signer.workflow = ".github/workflows/other.yml".into();
        let bad = Rel::made(a, "app", "a", "v1", image.clone(), |spec| {
            spec.identity = Identity::for_signer(&signer, "push");
        });
        let good = Rel::made(a, "app", "a", "v2", image, |_| {});
        vec![bad, good]
    })
    .await;
    let (bad, good) = (&rels[0], &rels[1]);
    let u = w.updater().await;
    let record = run(&u, bad).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::BundleSigner))
    );
    assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
    assert!(service_state(&u, "app").await.is_failed(&bad.digest()));

    // The same digest is refused, from either release, until the operator clears it.
    let retry = post(&u, good).await;
    assert_eq!(
        (retry.status, retry.error().as_str()),
        (409, "previously_failed")
    );
    let cleared = u
        .as_operator(
            "DELETE",
            &format!("/v1/services/app/failed/{}", good.digest()),
            b"",
        )
        .await;
    assert_eq!(cleared.status, 204);
    let record = run(&u, good).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(w.registry.manifest("app", &good.digest()).is_some());
}

#[tokio::test]
async fn a_bundle_with_only_a_timestamp_converges_and_one_with_no_time_fails() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let timestamp = Rel::made(
            a,
            "app",
            "a",
            "v1",
            OciImage::new("app-a").build(),
            |spec| spec.evidence = Evidence::Timestamp,
        );
        let neither = Rel::made(
            a,
            "app",
            "b",
            "v1",
            OciImage::new("app-b").build(),
            |spec| spec.evidence = Evidence::Neither,
        );
        vec![timestamp, neither]
    })
    .await;
    let u = w.updater().await;
    let record = run(&u, &rels[0]).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(record.signed_time, Some(signed_at()));
    let record = run(&u, &rels[1]).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::BundleChain))
    );
    assert!(service_state(&u, "app").await.is_failed(&rels[1].digest()));
}

#[tokio::test]
async fn a_tar_of_another_digest_fails_without_blocking_the_asked_digest() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    let asked = Digest::from_sha256([9; 32]);
    let body = rel.body_with(|b| b["image_digest"] = json!(asked));
    let reply = post_body(&u, &rel, body.clone()).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::DigestMismatch))
    );
    assert!(service_state(&u, "app").await.failed.is_empty());
    // The retry runs (and fails the same way); it is not refused.
    let retry = post_body(&u, &rel, body).await;
    assert_eq!(retry.status, 202);
    finished(&u.app, &deploy_id(&retry)).await;
}

// tar rows

#[tokio::test]
async fn tar_rows_end_in_failed_records_and_block_their_digest() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        let other_platform = OciImage::new("app-a").platform("linux", "arm64").build();
        let missing_blob = OciImage::new("app-b").flaw(Flaw::MissingBlob).build();
        vec![
            Rel::made(a, "app", "a", "v1", other_platform, |_| {}),
            Rel::made(a, "app", "b", "v1", missing_blob, |_| {}),
        ]
    })
    .await;
    let u = w.updater().await;
    for (rel, token) in rels
        .iter()
        .zip([ErrorToken::PlatformMismatch, ErrorToken::TarInvalid])
    {
        let record = run(&u, rel).await;
        assert_eq!(outcome(&record), (State::Failed, Some(token)));
        assert!(service_state(&u, "app").await.is_failed(&rel.digest()));
    }
    assert!(w.registry.events().is_empty());
}

// the fetch row, one release per case: each ends in the record the table names

/// A world with one release of `app` as `build` makes it. The updater reaches the release
/// server through `network` (the allowed hosts resolve to the documentation address, then
/// `network` may change that) and writes through `disk`; the config is the text `config`
/// returns for the harness config.
async fn fetch_world(
    build: impl FnOnce(&mut Rel),
    network: impl FnOnce(FakeNetwork) -> FakeNetwork,
    disk: std::sync::Arc<dyn dsu_server::fetch::Disk>,
    config: impl FnOnce(String) -> String,
) -> (World, Updater, Rel) {
    let (w, rel) = World::one(|a| {
        let mut rel = Rel::new(a, "app", "a");
        build(&mut rel);
        rel
    })
    .await;
    let text = std::fs::read_to_string(&w.env.config_path).unwrap();
    std::fs::write(&w.env.config_path, config(text)).unwrap();
    let options = Options {
        network: std::sync::Arc::new(network(FakeNetwork::new(w.server.port()).allowed())),
        disk,
        ..w.options()
    };
    let u = Updater::start(&w.env, options).await;
    (w, u, rel)
}

/// A redirect to the allowed host `objects.githubusercontent.com` at `path`.
fn redirect_to(path: &str) -> Route {
    Route::Redirect {
        status: 302,
        location: format!("https://objects.githubusercontent.com{path}"),
    }
}

/// What a deploy that ended in the fetching phase leaves: no files, no failed digest, and
/// nothing sent to the registry or Swarm.
async fn assert_refused_before_the_registry(w: &World, u: &Updater, rel: &Rel) {
    assert!(w.downloads().is_empty());
    assert!(!service_state(u, "app").await.is_failed(&rel.digest()));
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

#[tokio::test]
async fn fetch_rows_a_short_body_and_a_redirect_to_an_allowed_host() {
    // A short body: fetch_failed.
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(Route::ShortBody {
                body: rel.image.tar[..100].to_vec(),
                declared: rel.image.tar.len(),
            })
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert_refused_before_the_registry(&w, &u, &rel).await;

    // A redirect to an allowed host is followed: converged.
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(redirect_to("/blob/app.tar"));
            rel.extra = vec![("/blob/app.tar".into(), Route::File(rel.image.tar.clone()))];
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(w.registry.manifest("app", &rel.digest()).is_some());
    assert!(
        w.server
            .requests()
            .iter()
            .any(|r| r.path == "/blob/app.tar")
    );
}

#[tokio::test]
async fn fetch_rows_a_stalled_read_ends_on_the_clock() {
    let (w, u, rel) = fetch_world(
        |rel| {
            rel.image_route = Some(Route::Stall {
                sent: rel.image.tar[..100].to_vec(),
                declared: rel.image.tar.len(),
            })
        },
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    let id = deploy_id(&post(&u, &rel).await);
    w.server.stalled().await;
    let record = w.env.clock.pump(READ_TIMEOUT, finished(&u.app, &id)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.contains("read"));
    assert_refused_before_the_registry(&w, &u, &rel).await;
}

#[tokio::test]
async fn fetch_rows_redirects_the_rules_refuse_are_url_not_allowed() {
    // To `http`, to a host that resolves to loopback, to a shared address, a loop, and six
    // hops; five hops are followed.
    let hops = |n: usize| {
        move |rel: &mut Rel| {
            rel.image_route = Some(redirect_to("/hop/1"));
            rel.extra = (1..=n)
                .map(|i| {
                    let route = if i == n {
                        Route::File(rel.image.tar.clone())
                    } else {
                        redirect_to(&format!("/hop/{}", i + 1))
                    };
                    (format!("/hop/{i}"), route)
                })
                .collect();
        }
    };
    type Build = Box<dyn FnOnce(&mut Rel)>;
    type Net = fn(FakeNetwork) -> FakeNetwork;
    let cases: Vec<(&str, Build, Net)> = vec![
        (
            "http",
            Box::new(|rel| {
                rel.image_route = Some(Route::Redirect {
                    status: 302,
                    location: "http://objects.githubusercontent.com/x".into(),
                })
            }),
            |n| n,
        ),
        (
            "loopback",
            Box::new(|rel| rel.image_route = Some(redirect_to("/blob"))),
            |n| n.host("objects.githubusercontent.com", &["127.0.0.1"]),
        ),
        (
            "shared address",
            Box::new(|rel| rel.image_route = Some(redirect_to("/blob"))),
            |n| n.host("objects.githubusercontent.com", &["100.64.0.1"]),
        ),
        (
            "a loop",
            Box::new(|rel| {
                rel.image_route = Some(redirect_to("/loop"));
                rel.extra = vec![("/loop".into(), redirect_to("/loop"))];
            }),
            |n| n,
        ),
        ("six hops", Box::new(hops(6)), |n| n),
    ];
    for (what, build, network) in cases {
        let (w, u, rel) = fetch_world(
            build,
            network,
            std::sync::Arc::new(dsu_server::fetch::SystemDisk),
            |t| t,
        )
        .await;
        let record = run(&u, &rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(ErrorToken::UrlNotAllowed)),
            "{what}"
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Fetching);
        assert_refused_before_the_registry(&w, &u, &rel).await;
    }
    // Five hops are the most that are followed.
    let (w, u, rel) = fetch_world(
        hops(5),
        |n| n,
        std::sync::Arc::new(dsu_server::fetch::SystemDisk),
        |t| t,
    )
    .await;
    assert_eq!(run(&u, &rel).await.state, State::Converged);
    assert!(w.registry.manifest("app", &rel.digest()).is_some());
}

#[tokio::test]
async fn fetch_rows_a_disk_below_min_free_bytes_and_a_write_failing_midway() {
    const MIN: u64 = 1_000_000;
    let raised = |t: String| t.replace("min_free_bytes = 0", &format!("min_free_bytes = {MIN}"));
    // The disk keeps `MIN` bytes free after the bundle and the tar, exactly: the deploy
    // converges; one byte less and it is fetch_failed.
    for (short_by, want) in [
        (0, (State::Converged, None)),
        (1, (State::Failed, Some(ErrorToken::FetchFailed))),
    ] {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let free = MIN + (rel.bundle.len() + rel.image.tar.len()) as u64 - short_by;
        std::fs::write(
            &w.env.config_path,
            raised(std::fs::read_to_string(&w.env.config_path).unwrap()),
        )
        .unwrap();
        let u = Updater::start(
            &w.env,
            Options {
                disk: std::sync::Arc::new(FakeDisk::new(free)),
                ..w.options()
            },
        )
        .await;
        let record = run(&u, &rel).await;
        assert_eq!(outcome(&record), want, "short by {short_by}");
        if short_by == 1 {
            assert!(record.error.unwrap().detail.contains("disk"));
            assert_refused_before_the_registry(&w, &u, &rel).await;
        }
    }
    // A write that fails in the middle of the tar: fetch_failed, and no partial file.
    let disk = std::sync::Arc::new(FakeDisk::new(u64::MAX).failing_at(4));
    let (w, u, rel) = fetch_world(
        |rel| rel.image_route = Some(Route::File(vec![7; 2 << 20])),
        |n| n,
        disk.clone(),
        |t| t,
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.contains("the disk failed"));
    assert_eq!(disk.chunks(), 4);
    assert_refused_before_the_registry(&w, &u, &rel).await;
}

// the bundle row, one release per case

#[tokio::test]
async fn bundle_rows_end_in_failed_records_and_block_the_digest() {
    let signer = || service_config("app").signer;
    let signed_by = |edit: fn(&mut dsu_core::config::Signer)| {
        move |spec: &mut Spec| {
            let mut signer = signer();
            edit(&mut signer);
            spec.identity = Identity::for_signer(&signer, "push");
        }
    };
    type Edit = Box<dyn FnOnce(&mut Spec)>;
    let cases: Vec<(&str, ErrorToken, Edit)> = vec![
        (
            "tar changed after signing",
            ErrorToken::BundleSubject,
            Box::new(|spec| spec.subjects[0].sha256 = Digest::from_sha256([7; 32]).hex().into()),
        ),
        (
            "a valid bundle of another artifact of the same release",
            ErrorToken::BundleSubject,
            Box::new(|spec| spec.subjects[0].name = "other-1.0-linux-x86_64.image.tar".into()),
        ),
        (
            "another workflow",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| {
                s.workflow = ".github/workflows/other.yml".into()
            })),
        ),
        (
            "another ref",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| s.git_ref = "refs/heads/feature".into())),
        ),
        (
            "another repository id",
            ErrorToken::BundleSigner,
            Box::new(signed_by(|s| s.repository_id = "4242".into())),
        ),
        (
            "another trigger",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity = Identity::for_signer(&service_config("app").signer, "pull_request")
            }),
        ),
        (
            "a self-hosted runner",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity
                    .claims
                    .insert(claim::RUNNER_ENVIRONMENT, "self-hosted".into());
            }),
        ),
        (
            "a run of another repository",
            ErrorToken::BundleSigner,
            Box::new(|spec| {
                spec.identity.claims.insert(
                    claim::RUN_INVOCATION_URI,
                    "https://github.com/example-org/other/actions/runs/7".into(),
                );
            }),
        ),
        (
            "an altered log entry",
            ErrorToken::BundleChain,
            Box::new(|spec| spec.evidence = Evidence::AlteredLog),
        ),
        (
            "neither a log entry nor a timestamp",
            ErrorToken::BundleChain,
            Box::new(|spec| spec.evidence = Evidence::Neither),
        ),
    ];
    let count = cases.len() + 2;
    let (w, rels) = World::new(Mode::Normal, |a| {
        let mut rels: Vec<Rel> = cases
            .into_iter()
            .enumerate()
            .map(|(i, (_, _, edit))| {
                let label = format!("c{i}");
                let image = OciImage::new(&format!("app-{label}")).build();
                Rel::made(a, "app", &label, "v1", image, edit)
            })
            .collect();
        // Not a Sigstore bundle at all, and a chain from another root.
        let mut not_json = Rel::new(a, "app", "j1");
        not_json.bundle_route = Some(Route::File(b"not json".to_vec()));
        rels.push(not_json);
        let image = OciImage::new("app-j2").build();
        rels.push(Rel::made(
            &Authority::public_good(),
            "app",
            "j2",
            "v1",
            image,
            |_| {},
        ));
        rels
    })
    .await;
    assert_eq!(rels.len(), count);
    let wanted: Vec<ErrorToken> = [
        ErrorToken::BundleSubject,
        ErrorToken::BundleSubject,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleSigner,
        ErrorToken::BundleChain,
        ErrorToken::BundleChain,
        ErrorToken::BundleInvalid,
        ErrorToken::BundleChain,
    ]
    .into();
    let u = w.updater().await;
    for (rel, token) in rels.iter().zip(wanted) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
        // Found after `index.json` named the digest: it is blocked.
        assert!(
            service_state(&u, "app").await.is_failed(&rel.digest()),
            "{}",
            rel.file
        );
        assert!(w.downloads().is_empty());
    }
    assert!(w.registry.events().is_empty());
    assert!(w.docker().updates().is_empty());
}

#[tokio::test]
async fn tar_rows_a_wrong_index_two_manifests_and_a_mis_hashed_blob() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        [
            ("a", Flaw::IndexDigestDiffers),
            ("b", Flaw::TwoManifests),
            ("c", Flaw::MisHashedBlob),
        ]
        .into_iter()
        .map(|(label, flaw)| {
            let image = OciImage::new(&format!("app-{label}")).flaw(flaw).build();
            Rel::made(a, "app", label, "v1", image, |_| {})
        })
        .collect()
    })
    .await;
    let u = w.updater().await;
    // `digest_mismatch` and `tar_invalid` for two manifests are found before the digest is
    // known to be the tar's, so they do not block it; a mis-hashed blob is found after.
    let wanted = [
        (ErrorToken::DigestMismatch, false),
        (ErrorToken::TarInvalid, false),
        (ErrorToken::TarInvalid, true),
    ];
    for (rel, (token, blocked)) in rels.iter().zip(wanted) {
        let record = run(&u, rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(token)),
            "{}",
            rel.file
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Verifying);
        assert_eq!(
            service_state(&u, "app").await.is_failed(&rel.digest()),
            blocked,
            "{}",
            rel.file
        );
    }
    assert!(w.registry.events().is_empty());
}

// downgrade

#[tokio::test]
async fn an_older_release_is_refused_for_a_caller_and_accepted_for_the_operator() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![
            Rel::new(a, "app", "a"),
            Rel::signed(a, "app", "b", SignedDuration::from_secs(-90)),
        ]
    })
    .await;
    let u = w.updater().await;
    assert_eq!(run(&u, &rels[0]).await.state, State::Converged);
    let record = run(&u, &rels[1]).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::OlderThanRunning))
    );
    assert_eq!(
        record.signed_time,
        Some(signed_at() - SignedDuration::from_secs(90))
    );
    let state = service_state(&u, "app").await;
    assert!(state.failed.is_empty(), "the operator's retry must run");
    assert_eq!(state.floor, Some(signed_at()));
    assert_eq!(w.docker().updates().len(), 1);
    assert!(w.registry.manifest("app", &rels[1].digest()).is_none());

    let body = rels[1].body_with(|b| b["allow_older"] = json!(true));
    let reply = u.as_operator("POST", &deploys("app"), &body).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(record.allow_older);
    let note = record.steps[1].note.as_deref().unwrap();
    assert!(note.contains("older than the running release"), "{note}");
    assert!(note.contains("allow_older"), "{note}");
    assert_eq!(
        service_state(&u, "app").await.floor,
        Some(signed_at() - SignedDuration::from_secs(90))
    );
}

// registry

#[tokio::test]
async fn a_registry_that_fails_or_answers_another_digest_leaves_swarm_alone() {
    for mode in [Mode::FailBlobUpload, Mode::AnswerOtherDigest] {
        let (w, mut rels) = World::new(mode, |a| vec![Rel::new(a, "app", "a")]).await;
        let rel = rels.remove(0);
        let u = w.updater().await;
        let record = run(&u, &rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(ErrorToken::RegistryFailed)),
            "{mode:?}"
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Pushing);
        assert!(w.docker().updates().is_empty());
        let state = service_state(&u, "app").await;
        assert!(state.failed.is_empty() && state.floor.is_none());
        assert!(w.downloads().is_empty());
    }
}

// Swarm

#[tokio::test]
async fn a_rolled_back_update_is_rolled_back_and_its_digest_is_blocked() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::RollsBack);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::RolledBack, Some(ErrorToken::SwarmRolledBack))
    );
    let state = service_state(&u, "app").await;
    assert!(state.is_failed(&rel.digest()));
    assert!(state.floor.is_none() && state.converged.is_empty() && state.pending.is_none());
    let retry = post(&u, &rel).await;
    assert_eq!(
        (retry.status, retry.error().as_str()),
        (409, "previously_failed")
    );
}

#[tokio::test]
async fn a_paused_update_is_paused_and_names_the_failing_task() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::Pauses);
    let mut failing = FakeTask::running("t2", "new");
    failing.state = "failed".into();
    failing.error = Some("task: non-zero exit (1)".into());
    w.docker()
        .set_tasks("app_server", vec![FakeTask::running("t1", "old"), failing]);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Paused, Some(ErrorToken::SwarmPaused))
    );
    let note = record.steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("t2 failed on new (task: non-zero exit (1))"),
        "{note}"
    );
    assert!(note.contains("t1 running on old"), "{note}");
    let state = service_state(&u, "app").await;
    assert!(state.failed.is_empty() && state.pending.is_none());
}

#[tokio::test]
async fn a_timeout_ends_the_deploy_and_asks_swarm_for_nothing_more() {
    let (w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    w.script(Outcome::NeverEnds);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Failed, Some(ErrorToken::Timeout)));
    assert!(record.error.as_ref().unwrap().detail.contains("60 seconds"));
    // Only the update itself was sent: no rollback, no second update.
    assert_eq!(w.docker().updates().len(), 1);
    let state = service_state(&u, "web").await;
    assert!(state.failed.is_empty() && state.pending.is_none());
}

#[tokio::test]
async fn a_docker_that_goes_away_while_waiting_is_retried_until_the_timeout() {
    let (mut w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    w.script(Outcome::NeverEnds);
    let u = w.updater().await;
    let reply = post(&u, &rel).await;
    let id = deploy_id(&reply);
    wait_record(&u.app, &id, |r| r.phase == Phase::Waiting).await;
    w.env.docker = None;
    let record = finished(&u.app, &id).await;
    assert_eq!(outcome(&record), (State::Failed, Some(ErrorToken::Timeout)));
    let note = record.steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("the last read of the service failed"),
        "{note}"
    );
}

#[tokio::test]
async fn without_a_timeout_a_late_completion_still_converges() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let mut script = UpdateScript::new(Outcome::Converges);
    script.updating_reads = 200;
    w.docker().set_script(script);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
}

#[tokio::test]
async fn a_version_conflict_is_retried_once() {
    for (conflicts, want) in [
        (1, (State::Converged, None)),
        (2, (State::Failed, Some(ErrorToken::SwarmRefused))),
    ] {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let mut script = UpdateScript::new(Outcome::Converges);
        script.conflicts = conflicts;
        w.docker().set_script(script);
        let u = w.updater().await;
        let record = run(&u, &rel).await;
        assert_eq!(outcome(&record), want, "{conflicts} conflicts");
        let updates = w.docker().updates();
        assert_eq!(updates.len(), 2);
        // The second attempt quotes the version of a fresh read.
        assert_eq!(updates[1].version, updates[0].version + 1);
        if conflicts == 2 {
            assert!(record.error.unwrap().detail.contains("out of sequence"),);
            assert!(service_state(&u, "app").await.pending.is_none());
        }
    }
}

#[tokio::test]
async fn an_update_swarm_refuses_is_swarm_refused() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::Refuses("the service is locked".into()));
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::SwarmRefused))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .contains("the service is locked")
    );
    assert_eq!(record.steps.last().unwrap().phase, Phase::Updating);
    assert!(!service_state(&u, "app").await.is_failed(&rel.digest()));
}

#[tokio::test]
async fn a_swarm_service_that_does_not_exist_is_swarm_refused() {
    let (w, rel) = World::one(|a| Rel::new(a, "ghost", "a")).await;
    let u = w.updater().await;
    let reply = u
        .as_caller(&caller("ghost"), "POST", &deploys("ghost"), &rel.body())
        .await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::SwarmRefused))
    );
}

#[tokio::test]
async fn a_stale_terminal_state_from_an_earlier_update_is_ignored() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let earlier = w.env.clock.now() - SignedDuration::from_hours(1);
    w.docker().set_update_status(
        "app_server",
        FakeUpdateStatus {
            state: "rollback_completed".into(),
            started_at: earlier,
            message: "an earlier rollback".into(),
        },
    );
    let mut script = UpdateScript::new(Outcome::Converges);
    script.stale_reads = 5;
    script.updating_reads = 2;
    w.docker().set_script(script);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(service_state(&u, "app").await.failed.is_empty());
}

// restart

#[tokio::test]
async fn a_restart_in_the_fetching_phase_fails_the_deploy_and_the_caller_asks_again() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    // The first process never gets an answer from the release server.
    let first = Updater::start(&w.env, Options::default()).await;
    let id = deploy_id(&post(&first, &rel).await);
    wait_record(&first.app, &id, |r| r.phase == Phase::Fetching).await;
    first.stop().await.unwrap();
    let leftover = w.env.state_dir().join("downloads").join("d-left");
    std::fs::create_dir_all(&leftover).unwrap();
    std::fs::write(leftover.join("image.tar"), b"partial").unwrap();

    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(w.docker().updates().is_empty());
    assert!(!service_state(&second, "app").await.is_failed(&rel.digest()));
    assert!(w.downloads().is_empty(), "leftover downloads are removed");
    let again = run(&second, &rel).await;
    assert_eq!(outcome(&again), (State::Converged, None));
}

/// A first process that left a deploy of `rel` waiting on a Swarm update that never ends.
async fn left_waiting(w: &World, rel: &Rel) -> DeployId {
    w.script(Outcome::NeverEnds);
    let first = w.updater().await;
    let id = deploy_id(&post(&first, rel).await);
    wait_record(&first.app, &id, |r| r.phase == Phase::Waiting).await;
    first.stop().await.unwrap();
    id
}

#[tokio::test]
async fn a_restart_while_swarm_still_updates_resumes_the_wait() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let id = left_waiting(&w, &rel).await;
    let second = w.updater().await;
    // Swarm is still updating: the record is running, and its service is locked.
    let record = second.app.store.record(&id).await.unwrap();
    assert_eq!(record.state, State::Running);
    let other = Rel::new(&w.env.authority, "app", "z");
    let busy = post(&second, &other).await;
    assert_eq!((busy.status, busy.error().as_str()), (409, "busy"));
    w.script(Outcome::Converges);
    let record = finished(&second.app, &id).await;
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
    let state = service_state(&second, "app").await;
    assert_eq!(state.floor, Some(signed_at()));
    assert!(state.pending.is_none());
    assert_eq!(
        w.docker().updates().len(),
        1,
        "the update is not asked for again"
    );
}

#[tokio::test]
async fn a_restart_after_swarm_settled_ends_the_record_at_start() {
    let cases = [
        (Outcome::Converges, (State::Converged, None)),
        (
            Outcome::RollsBack,
            (State::RolledBack, Some(ErrorToken::SwarmRolledBack)),
        ),
        (
            Outcome::Pauses,
            (State::Paused, Some(ErrorToken::SwarmPaused)),
        ),
    ];
    for (settles, want) in cases {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let id = left_waiting(&w, &rel).await;
        // Swarm finishes while no updater runs; reading the service lets the fake go on.
        w.script(settles);
        w.swarm().inspect_service("app_server").await.unwrap();
        let second = w.updater().await;
        let record = second.app.store.record(&id).await.unwrap();
        assert_eq!(outcome(&record), want);
        let state = service_state(&second, "app").await;
        assert_eq!(state.is_failed(&rel.digest()), want.0 == State::RolledBack);
        assert!(state.pending.is_none());
        assert_eq!(state.floor.is_some(), want.0 == State::Converged);
    }
}

#[tokio::test]
async fn a_restart_finds_a_spec_no_update_of_the_deploy_explains() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let first = w.updater().await;
    let now = first.app.clock.now();
    let id = "d-aaaaaaaaaaaaaaaaaaaaaaaaaa";
    first
        .app
        .store
        .put_record(&crafted("app", &rel.digest(), id, &TO_WAITING, now))
        .await
        .unwrap();
    // Swarm's spec was changed by hand: no update of this deploy ever ran.
    let snapshot = Snapshot {
        version_index: w.docker().service("app_server").index,
        read_at: now,
    };
    first
        .app
        .store
        .update_service(&ServiceName::parse("app").unwrap(), |s| {
            s.set_pending(DeployId::parse(id).unwrap(), snapshot);
        })
        .await
        .unwrap();
    first.stop().await.unwrap();

    let second = w.updater().await;
    let record = second
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(service_state(&second, "app").await.pending.is_none());
}

#[tokio::test]
async fn a_restart_ends_a_record_whose_service_is_no_longer_configured() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let first = w.updater().await;
    let id = "d-bbbbbbbbbbbbbbbbbbbbbbbbbb";
    first
        .app
        .store
        .put_record(&crafted(
            "removed",
            &rel.digest(),
            id,
            &[Phase::Fetching],
            first.app.clock.now(),
        ))
        .await
        .unwrap();
    first.stop().await.unwrap();
    let second = w.updater().await;
    let record = second
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .contains("no longer configured")
    );
}

#[tokio::test]
async fn a_restart_that_cannot_read_swarm_does_not_settle_anything() {
    let (mut w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    let id = "d-cccccccccccccccccccccccccc";
    u.app
        .store
        .put_record(&crafted(
            "app",
            &rel.digest(),
            id,
            &TO_WAITING,
            u.app.clock.now(),
        ))
        .await
        .unwrap();
    w.env.docker = None;
    let error = recover(&u.app).await.unwrap_err();
    assert!(matches!(error, RunnerError::Docker { .. }), "{error}");
    assert!(error.to_string().contains(id));
    let record = u
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(record.state, State::Running);
}

// self-update

/// The environment of an updater that runs as the Swarm service of `app`.
fn as_app_server(w: &World) {
    w.docker().add_container(
        "dsu-test-host",
        &[("com.docker.swarm.service.name", "app_server")],
    );
}

#[tokio::test]
async fn a_self_update_hands_off_and_the_next_process_settles_it_converged() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    let id = left_waiting(&w, &rel).await;
    let record = finished_or_running(&w, &id).await;
    // The self-update goes from pushing to handed_off, never through updating.
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::HandedOff,
            Phase::Waiting
        ]
    );
    w.script(Outcome::Converges);
    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(w.docker().updates().len(), 1);
    assert_eq!(service_state(&second, "app").await.floor, Some(signed_at()));
}

/// The record `id` as the files hold it, read by a short-lived store.
async fn finished_or_running(w: &World, id: &DeployId) -> Record {
    let bytes =
        std::fs::read(w.env.state_dir().join("deploys").join(format!("{id}.json"))).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a_self_update_that_swarm_rolls_back_is_settled_rolled_back_by_the_old_image() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    let id = left_waiting(&w, &rel).await;
    w.script(Outcome::RollsBack);
    w.swarm().inspect_service("app_server").await.unwrap();
    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(
        outcome(&record),
        (State::RolledBack, Some(ErrorToken::SwarmRolledBack))
    );
    assert!(service_state(&second, "app").await.is_failed(&rel.digest()));
}

#[tokio::test]
async fn a_record_handed_off_before_swarm_answered_is_waited_for_from_handed_off() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    w.script(Outcome::NeverEnds);
    let first = w.updater().await;
    let now = first.app.clock.now();
    let id = DeployId::parse("d-dddddddddddddddddddddddddd").unwrap();
    first
        .app
        .store
        .put_record(&crafted(
            "app",
            &rel.digest(),
            id.as_str(),
            &[
                Phase::Fetching,
                Phase::Verifying,
                Phase::Pushing,
                Phase::HandedOff,
            ],
            now,
        ))
        .await
        .unwrap();
    // The update was accepted by Swarm, then the process went away before it waited.
    let client = w.swarm();
    let view = client.inspect_service("app_server").await.unwrap();
    let snapshot = Snapshot {
        version_index: view.version_index,
        read_at: now,
    };
    first
        .app
        .store
        .update_service(&ServiceName::parse("app").unwrap(), |s| {
            s.set_pending(id.clone(), snapshot);
        })
        .await
        .unwrap();
    let image = rel.reference(&w.env.registry);
    client
        .update_service(&view, &image, &id, &rel.digest())
        .await
        .unwrap();
    first.stop().await.unwrap();

    let second = w.updater().await;
    // While it resumes, no other deploy runs next to a self-update.
    let other = Rel::new(&w.env.authority, "web", "a");
    let busy = post(&second, &other).await;
    assert_eq!(
        (busy.status, busy.error().as_str()),
        (409, "self_update_busy")
    );
    w.script(Outcome::Converges);
    let record = finished(&second.app, &id).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::HandedOff,
            Phase::Waiting
        ]
    );
}

// retention

/// Deploys `rels` one after the other, each converging.
async fn converge_all(u: &Updater, rels: &[Rel]) -> Vec<Record> {
    let mut records = Vec::new();
    for rel in rels {
        let record = run(u, rel).await;
        assert_eq!(outcome(&record), (State::Converged, None), "{}", rel.file);
        records.push(record);
    }
    records
}

fn six() -> impl FnOnce(&Authority) -> Vec<Rel> {
    |a| {
        ["a", "b", "c", "d", "e", "f"]
            .into_iter()
            .map(|label| Rel::new(a, "app", label))
            .collect()
    }
}

#[tokio::test]
async fn retention_keeps_the_running_the_previous_and_the_last_three_and_deletes_the_rest() {
    let (w, rels) = World::new(Mode::Normal, six()).await;
    let u = w.updater().await;
    let records = converge_all(&u, &rels).await;
    // Running f, previous e, the last three b..d besides them: only `a` goes.
    let deleted: Vec<Event> = w
        .registry
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::ManifestDeleted { .. }))
        .collect();
    assert_eq!(
        deleted,
        [Event::ManifestDeleted {
            repository: "app".into(),
            digest: rels[0].digest()
        }]
    );
    assert!(w.registry.manifest("app", &rels[0].digest()).is_none());
    for rel in &rels[1..] {
        assert!(w.registry.manifest("app", &rel.digest()).is_some());
    }
    let state = service_state(&u, "app").await;
    assert!(!state.pushed.contains(&rels[0].digest()));
    assert_eq!(state.pushed.len(), 5);
    let note = records[5].steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("retention: deleted 1 manifests, 0 could not be deleted"),
        "{note}"
    );
    // Earlier converges deleted nothing.
    assert!(
        !records[4]
            .steps
            .last()
            .unwrap()
            .note
            .clone()
            .unwrap()
            .contains("retention")
    );
}

#[tokio::test]
async fn a_manifest_the_registry_will_not_delete_is_kept_and_noted_not_failed() {
    let (w, rels) = World::new(Mode::FailDelete, six()).await;
    let u = w.updater().await;
    let records = converge_all(&u, &rels).await;
    let note = records[5].steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("deleted 0 manifests, 1 could not be deleted"),
        "{note}"
    );
    assert!(w.registry.manifest("app", &rels[0].digest()).is_some());
    // It stays in the pushed set, so the next converge tries again.
    assert!(
        service_state(&u, "app")
            .await
            .pushed
            .contains(&rels[0].digest())
    );
}

// the operator

#[tokio::test]
async fn the_operator_deploys_a_release_end_to_end() {
    let (w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    let u = w.updater().await;
    let reply = u.as_operator("POST", &deploys("web"), &rel.body()).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(record.caller, CallerRecord::Operator);
}

// the state directory and the downloads

#[tokio::test]
async fn a_state_directory_that_stops_working_ends_the_deploy_and_frees_the_service() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "app", "a"), Rel::new(a, "app", "b")]
    })
    .await;
    let deploys_dir = w.env.state_dir().join("deploys");
    let saved = w.env.dir.path().join("deploys-saved");
    // The image's first chunk is written: the record can no longer be written.
    let hook_dir = (deploys_dir.clone(), saved.clone());
    let disk = HookDisk::new(move |chunk| {
        if chunk == 2 {
            std::fs::rename(&hook_dir.0, &hook_dir.1).unwrap();
        }
    });
    let u = Updater::start(
        &w.env,
        Options {
            disk: std::sync::Arc::new(disk),
            ..w.options()
        },
    )
    .await;
    let reply = post(&u, &rels[0]).await;
    assert_eq!(reply.status, 202);
    u.app.wait_deploys().await;
    // Nothing more was asked of Swarm or the registry, the snapshot is clear and the
    // service is free again; the record could not say so and is left for the next start.
    assert!(w.docker().updates().is_empty() && w.registry.events().is_empty());
    assert!(service_state(&u, "app").await.pending.is_none());
    assert!(w.downloads().is_empty());
    std::fs::rename(&saved, &deploys_dir).unwrap();
    let next = post(&u, &rels[1]).await;
    assert_eq!(next.status, 202);
    assert_eq!(
        finished(&u.app, &deploy_id(&next)).await.state,
        State::Converged
    );
}

#[tokio::test]
async fn a_downloads_directory_that_cannot_be_created_is_fetch_failed() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    std::fs::write(w.env.state_dir().join("downloads"), b"not a directory").unwrap();
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.starts_with("cannot create "));
}

#[tokio::test]
async fn a_bundle_that_vanishes_after_the_download_is_fetch_failed() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let downloads = w.env.state_dir().join("downloads");
    let disk = HookDisk::new(move |chunk| {
        if chunk == 1 {
            for dir in std::fs::read_dir(&downloads).unwrap() {
                let _ = std::fs::remove_file(dir.unwrap().path().join("bundle.sigstore.json"));
            }
        }
    });
    let u = Updater::start(
        &w.env,
        Options {
            disk: std::sync::Arc::new(disk),
            ..w.options()
        },
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .starts_with("cannot read the downloaded bundle")
    );
}
