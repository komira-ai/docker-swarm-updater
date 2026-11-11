//! API rows for admission: refused requests, URLs, the operator, idempotency and Swarm errors.

use crate::harness::*;
use dsu_core::ids::{DeployId, ServiceName};
use dsu_core::record::{CallerRecord, NewRecord, Phase, Record};
use dsu_testkit::docker::FakeTask;
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn a_refused_request_writes_no_record() {
    let (env, u) = setup().await;
    let (app, web) = (caller("app"), caller("web"));
    u.app
        .store
        .update_service(&ServiceName::parse("app").unwrap(), |s| {
            s.add_failed(digest(8))
        })
        .await
        .unwrap();
    let body = |n: u8, edit: fn(&mut Value)| deploy_body("app", n, edit);
    let spent = u.token_with(&app, "spent", 300);
    assert_eq!(
        u.call(PROXY, "GET", LIST, Some(spent.clone()), b"")
            .await
            .status,
        200
    );
    let signer = |b: &mut Value| {
        b["signer"] = json!({
            "repository": "example-org/other",
            "workflow": ".github/workflows/artifacts.yml",
            "ref": "refs/heads/main",
        })
    };
    /// What is asked, as which peer, with which claims and body; the token that refuses it.
    type Refusal<'a> = (&'a str, u32, Option<String>, Vec<u8>, &'a str);
    let refusals: Vec<Refusal> = vec![
        (
            "bad_peer",
            OTHER,
            Some(u.token(&app)),
            body(5, |_| {}),
            "bad_peer",
        ),
        ("no_claims", PROXY, None, body(5, |_| {}), "no_claims"),
        (
            "expired",
            PROXY,
            Some(u.token_with(&app, "old", -1)),
            body(5, |_| {}),
            "expired",
        ),
        ("replayed", PROXY, Some(spent), body(5, |_| {}), "replayed"),
        (
            "not_allowed",
            PROXY,
            Some(u.token(&web)),
            body(5, |_| {}),
            "not_allowed",
        ),
        (
            "bad body",
            PROXY,
            Some(u.token(&app)),
            b"{".to_vec(),
            "bad_request",
        ),
        (
            "allow_older",
            PROXY,
            Some(u.token(&app)),
            body(5, |b| b["allow_older"] = json!(true)),
            "bad_request",
        ),
        (
            "signer",
            PROXY,
            Some(u.token(&app)),
            body(5, signer),
            "signer_mismatch",
        ),
        (
            "url",
            PROXY,
            Some(u.token(&app)),
            body(5, |b| {
                b["image_url"] = json!(
                    "https://github.com/other/app/releases/download/v1/app-1.0-linux-x86_64.image.tar"
                )
            }),
            "url_not_allowed",
        ),
        (
            "failed list",
            PROXY,
            Some(u.token(&app)),
            body(8, |_| {}),
            "previously_failed",
        ),
        (
            "too large",
            PROXY,
            Some(u.token(&app)),
            vec![b' '; 16 * 1024 + 1],
            "payload_too_large",
        ),
    ];
    for (what, uid, claims, body, token) in refusals {
        let r = u.call(uid, "POST", &deploys("app"), claims, &body).await;
        assert_eq!(r.error(), token, "{what}");
        assert!(env.state_files("deploys").is_empty(), "{what}");
    }
    let r = u
        .call(
            PROXY,
            "POST",
            &deploys("nope"),
            Some(u.token(&app)),
            &body(5, |_| {}),
        )
        .await;
    assert_eq!(r.error(), "unknown_service");
    assert!(env.state_files("deploys").is_empty());
    // A deploy that is accepted is the only record; the busy refusal next to it adds none.
    let r = u
        .as_caller(&app, "POST", &deploys("app"), &body(5, |_| {}))
        .await;
    assert_eq!(r.status, 202);
    let r = u
        .as_caller(&app, "POST", &deploys("app"), &body(6, |_| {}))
        .await;
    assert_eq!(r.error(), "busy");
    assert_eq!(env.state_files("deploys").len(), 1);
}

#[tokio::test]
async fn url_rows() {
    let (_env, u) = setup().await;
    let app = caller("app");
    let good =
        "https://github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar";
    let bad_images = [
        "https://github.com/other/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/other/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/../app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/v%31/app-1.0-linux-x86_64.image.tar",
        "https://github.com:8443/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://user@github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar?x=1",
        "https://github.com/example-org/app/releases/download/v1/app-1.0-linux-arm64.image.tar",
        "http://github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar#x",
        "https://github.com/example-org/app/releases/download/./app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/v1\\x/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download//app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/download/v1/x/app-1.0-linux-x86_64.image.tar",
        "https://github.com/example-org/app/releases/v1/app-1.0-linux-x86_64.image.tar",
        "https://www.github.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://github.com.example.test/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "https://objects.githubusercontent.com/example-org/app/releases/download/v1/app-1.0-linux-x86_64.image.tar",
        "not a url",
    ];
    for image in bad_images {
        let r = u
            .as_caller(
                &app,
                "POST",
                &deploys("app"),
                &deploy_body("app", 5, |b| {
                    b["image_url"] = json!(image);
                    b["bundle_url"] = json!(format!("{image}.sigstore.json"));
                }),
            )
            .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (403, "url_not_allowed"),
            "{image}"
        );
    }
    // A refusal is a 403 and writes no record.
    assert!(_env.state_files("deploys").is_empty());
    // A bundle URL that is not the image's plus .sigstore.json.
    for bundle in [
        format!("{good}.sig"),
        "https://github.com/example-org/app/releases/download/v1/other.sigstore.json".to_owned(),
    ] {
        let r = u
            .as_caller(
                &app,
                "POST",
                &deploys("app"),
                &deploy_body("app", 5, |b| b["bundle_url"] = json!(bundle)),
            )
            .await;
        assert_eq!(r.error(), "url_not_allowed", "{bundle}");
    }
}

#[tokio::test]
async fn request_target_rows() {
    let (_env, u) = setup().await;
    u.set_peer(0);
    let id = "d-aaaaaaaaaaaaaaaaaaaaaaaaaa";
    let targets = [
        "/v1/services/%2e%2e/deploys".to_owned(),
        "/v1/services/../deploys".to_owned(),
        "/v1//services".to_owned(),
        "//v1/services".to_owned(),
        "/v1/services/".to_owned(),
        "/v1/services/App/deploys".to_owned(),
        "/v1/services?x=1".to_owned(),
        "/v1/services/app/deploys?x=1".to_owned(),
        format!("/v1/deploys/{id}/"),
        "/v1/nothing".to_owned(),
        "*".to_owned(),
        "http://dsu/v1/services".to_owned(),
    ];
    for target in targets {
        let r = raw(u.socket(), &http("GET", &target, &[], b"")).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (404, "not_found"),
            "{target}"
        );
        assert_eq!(r.headers["content-type"], "application/json");
    }
    // A known path with another method: 405 naming the method it answers.
    for (method, target, allow) in [
        ("GET", deploys("app"), "POST"),
        ("POST", LIST.to_owned(), "GET"),
        (
            "GET",
            format!("/v1/services/app/failed/sha256:{}", "0".repeat(64)),
            "DELETE",
        ),
        ("POST", "/v1/health".to_owned(), "GET"),
        ("DELETE", format!("/v1/deploys/{id}"), "GET"),
    ] {
        let r = raw(u.socket(), &http(method, &target, &[], b"")).await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (405, "method_not_allowed"),
            "{target}"
        );
        assert_eq!(r.headers["allow"], allow);
    }
}

#[tokio::test]
async fn the_local_operator_deploys_any_service_and_is_named_in_the_record() {
    let (env, u) = setup().await;
    for name in ["app", "web", "ghost"] {
        let r = u
            .as_operator("POST", &deploys(name), &deploy_body(name, 9, |_| {}))
            .await;
        assert_eq!(r.status, 202, "{name}");
        let record = r.json();
        assert_eq!(record["caller"], "operator (uid 0)");
        assert_eq!(record["service"], name);
        assert_eq!(record["swarm_service"], format!("{name}_server"));
        assert_eq!(
            (record["state"].as_str(), record["phase"].as_str()),
            (Some("running"), Some("queued"))
        );
        assert_eq!(record["image_digest"], digest(9).as_str());
        assert!(record["id"].as_str().unwrap().starts_with("d-"));
        assert!(record.get("allow_older").is_none());
        // The deploy waits in its fetching phase, the downloader never being answered.
        wait_record(&u.app, &deploy_id(&r), |r| r.phase == Phase::Fetching).await;
    }
    assert_eq!(env.state_files("deploys").len(), 3);
}

#[tokio::test]
async fn the_operator_may_allow_older_and_the_record_says_so() {
    let (_env, u) = setup().await;
    let body = deploy_body("app", 10, |b| b["allow_older"] = json!(true));
    let r = u.as_operator("POST", &deploys("app"), &body).await;
    assert_eq!(r.status, 202);
    assert_eq!(r.json()["allow_older"], true);
}

#[tokio::test]
async fn a_caller_is_named_in_the_record_and_the_record_is_a_file() {
    let (env, u) = setup().await;
    let app = caller("app");
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(r.status, 202);
    let record = r.json();
    assert_eq!(
        record["caller"],
        json!({
            "repository": "example-org/app",
            "job_workflow_ref": DEPLOY_WORKFLOW,
            "ref": "refs/heads/main",
            "environment": "production",
            "run_id": "77",
        })
    );
    let id = record["id"].as_str().unwrap();
    wait_record(&u.app, &deploy_id(&r), |r| r.phase == Phase::Fetching).await;
    assert_eq!(env.state_files("deploys"), [format!("{id}.json")]);
    let on_disk: Value = serde_json::from_slice(
        &std::fs::read(env.state_dir().join("deploys").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    let status = u
        .as_caller(&app, "GET", &format!("/v1/deploys/{id}"), b"")
        .await;
    assert_eq!((status.status, status.json()), (200, on_disk.clone()));
    assert_eq!(on_disk["phase"], "fetching");
    assert_eq!(on_disk["caller"], record["caller"]);
}

#[tokio::test]
async fn idempotency_and_concurrency_rows() {
    let (_env, u) = setup().await;
    let (app, web) = (caller("app"), caller("web"));
    let first = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(first.status, 202);
    let id = first.json()["id"].clone();
    // The same digest while it runs: 200 with that record, no second record.
    let again = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(
        (again.status, again.json()["id"].clone()),
        (200, id.clone())
    );
    // Another digest of the service: busy, naming the running id.
    let other = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 6, |_| {}),
        )
        .await;
    assert_eq!((other.status, other.error().as_str()), (409, "busy"));
    assert!(
        other.json()["detail"]
            .as_str()
            .unwrap()
            .contains(id.as_str().unwrap())
    );
    // Another service at once: accepted.
    let web_deploy = u
        .as_caller(
            &web,
            "POST",
            &deploys("web"),
            &deploy_body("web", 5, |_| {}),
        )
        .await;
    assert_eq!(web_deploy.status, 202);
}

fn converged_record(service: &str, n: u8, id: &str) -> Record {
    let now = "2026-10-01T00:00:00Z".parse().unwrap();
    let mut record = Record::start(NewRecord {
        id: DeployId::parse(id).unwrap(),
        service: ServiceName::parse(service).unwrap(),
        swarm_service: format!("{service}_server"),
        image_digest: digest(n),
        version: "1.0".into(),
        caller: CallerRecord::Operator,
        allow_older: false,
        now,
    });
    record.enter_phase(Phase::Updating, now).unwrap();
    record.finish_converged(now).unwrap();
    record
}

#[tokio::test]
async fn a_converged_digest_that_swarm_runs_on_every_task_is_200() {
    let (env, u) = setup().await;
    let app = caller("app");
    let record = converged_record("app", 1, "d-bbbbbbbbbbbbbbbbbbbbbbbbbb");
    u.app.store.put_record(&record).await.unwrap();
    // Swarm runs digest 1 on its one task: 200 with that record, nothing started.
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 1, |_| {}),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["id"], "d-bbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert_eq!(env.state_files("deploys").len(), 1);
    // A task on another image: the deploy runs again.
    env.docker().set_tasks(
        "app_server",
        vec![
            FakeTask::running("t1", &app_image(1)),
            FakeTask::running("t2", &app_image(7)),
        ],
    );
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 1, |_| {}),
        )
        .await;
    assert_eq!(r.status, 202);
}

#[tokio::test]
async fn a_converged_digest_with_no_tasks_or_no_swarm_service_runs_again() {
    let (env, u) = setup().await;
    u.app
        .store
        .put_record(&converged_record("app", 1, "d-bbbbbbbbbbbbbbbbbbbbbbbbbb"))
        .await
        .unwrap();
    u.app
        .store
        .put_record(&converged_record(
            "ghost",
            1,
            "d-cccccccccccccccccccccccccc",
        ))
        .await
        .unwrap();
    env.docker().set_tasks("app_server", vec![]);
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 1, |_| {}))
        .await;
    assert_eq!(r.status, 202, "no tasks run it");
    let r = u
        .as_operator("POST", &deploys("ghost"), &deploy_body("ghost", 1, |_| {}))
        .await;
    assert_eq!(r.status, 202, "Swarm has no such service");
}

#[tokio::test]
async fn docker_down_is_503_where_swarm_is_asked() {
    let mut env = Env::new().await;
    let u = Updater::start(&env, Options::default()).await;
    u.app
        .store
        .put_record(&converged_record("app", 1, "d-bbbbbbbbbbbbbbbbbbbbbbbbbb"))
        .await
        .unwrap();
    env.docker = None;
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 1, |_| {}))
        .await;
    assert_eq!((r.status, r.error().as_str()), (503, "unavailable"));
    let r = u.as_operator("GET", LIST, b"").await;
    assert_eq!((r.status, r.error().as_str()), (503, "unavailable"));
    let r = u.as_operator("GET", "/v1/health", b"").await;
    assert_eq!((r.status, r.error().as_str()), (503, "unavailable"));
}
