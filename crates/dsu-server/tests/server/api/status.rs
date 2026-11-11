//! API rows for status, the lists, health, the state directory and shutdown.

use crate::harness::*;
use dsu_core::ids::ServiceName;
use dsu_testkit::docker::{FakeTask, FakeUpdateStatus};
use serde_json::json;

use super::*;

#[tokio::test]
async fn self_update_rows() {
    let env = Env::new().await;
    env.docker().add_container(
        "dsu-test-host",
        &[("com.docker.swarm.service.name", "app_server")],
    );
    let u = Updater::start(&env, Options::default()).await;
    // The updater is the Swarm service of `app`. While another service deploys, a
    // self-update is refused.
    let r = u
        .as_operator("POST", &deploys("web"), &deploy_body("web", 5, |_| {}))
        .await;
    assert_eq!(r.status, 202);
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 5, |_| {}))
        .await;
    assert_eq!((r.status, r.error().as_str()), (409, "self_update_busy"));
    // A deploy of the same service and digest as the running one is the idempotent 200.
    let r = u
        .as_operator("POST", &deploys("web"), &deploy_body("web", 5, |_| {}))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(env.state_files("deploys").len(), 1, "no second record");
    assert!(env.docker().updates().is_empty(), "nothing asked of Swarm");

    // The other way round: while the self-update runs, any other deploy is refused.
    let env = Env::new().await;
    env.docker().add_container(
        "dsu-test-host",
        &[("com.docker.swarm.service.name", "app_server")],
    );
    let u = Updater::start(&env, Options::default()).await;
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 5, |_| {}))
        .await;
    assert_eq!(r.status, 202);
    let r = u
        .as_operator("POST", &deploys("web"), &deploy_body("web", 5, |_| {}))
        .await;
    assert_eq!((r.status, r.error().as_str()), (409, "self_update_busy"));
    // Another digest of the self service itself is `busy`.
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 6, |_| {}))
        .await;
    assert_eq!(r.error(), "busy");
}

#[tokio::test]
async fn status_of_an_unknown_deploy_is_404() {
    let (_env, u) = setup().await;
    let r = u
        .as_operator("GET", "/v1/deploys/d-aaaaaaaaaaaaaaaaaaaaaaaaaa", b"")
        .await;
    assert_eq!((r.status, r.error().as_str()), (404, "unknown_deploy"));
}

#[tokio::test]
async fn list_reports_swarm_the_state_and_the_trusted_root() {
    let (env, u) = setup().await;
    let app = caller("app");
    env.docker().set_tasks(
        "app_server",
        vec![
            FakeTask::running("t1", &app_image(1)),
            FakeTask::running("t2", &app_image(1)),
            FakeTask::running("t3", &app_image(3)),
            FakeTask::running("t4", "registry.example/not-pinned:latest"),
        ],
    );
    env.docker().set_update_status(
        "app_server",
        FakeUpdateStatus {
            state: "completed".into(),
            started_at: "2026-10-01T00:00:00Z".parse().unwrap(),
            message: "done".into(),
        },
    );
    let started = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 8, |_| {}))
        .await;
    let id = started.json()["id"].as_str().unwrap().to_owned();
    let name = ServiceName::parse("app").unwrap();
    u.app
        .store
        .update_service(&name, |s| {
            s.add_failed(digest(4));
            s.floor = Some("2026-10-01T12:00:00Z".parse().unwrap());
        })
        .await
        .unwrap();
    let r = u.as_caller(&app, "GET", LIST, b"").await;
    assert_eq!(r.status, 200);
    let body = r.json();
    assert_eq!(
        body["services"],
        json!([{
            "service": "app",
            "swarm_service": "app_server",
            "running_digests": [digest(1), digest(3)],
            "update_state": "completed",
            "last_deploy": id,
            "failed_digests": [digest(4)],
            "floor": "2026-10-01T12:00:00Z",
        }])
    );
    // The test authority's keys are valid from `authority_start` with no end.
    assert_eq!(
        body["trusted_root_newest_key"],
        json!({"from": dsu_testkit::mint::authority_start().to_string()})
    );
    // A service Swarm has not got: no digests, no update state; a service never deployed:
    // no last deploy.
    let r = u.as_operator("GET", LIST, b"").await;
    let ghost = &r.json()["services"][2];
    assert_eq!(ghost["service"], "ghost");
    assert_eq!(ghost["running_digests"], json!([]));
    assert!(ghost.get("update_state").is_none() && ghost.get("last_deploy").is_none());
}

#[tokio::test]
async fn the_failed_list_is_cleared_by_the_operator_only() {
    let (_env, u) = setup().await;
    let app = caller("app");
    let name = ServiceName::parse("app").unwrap();
    u.app
        .store
        .update_service(&name, |s| s.add_failed(digest(5)))
        .await
        .unwrap();
    let path = format!("/v1/services/app/failed/{}", digest(5));
    // A retry of the failed digest: 409.
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (409, "previously_failed"));
    // Through the proxy: 403.
    let r = u.as_caller(&app, "DELETE", &path, b"").await;
    assert_eq!((r.status, r.error().as_str()), (403, "not_allowed"));
    // Not in the list, and an unknown service: 404.
    let r = u
        .as_operator(
            "DELETE",
            &format!("/v1/services/app/failed/{}", digest(6)),
            b"",
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (404, "not_found"));
    let r = u
        .as_operator(
            "DELETE",
            &format!("/v1/services/nope/failed/{}", digest(5)),
            b"",
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (404, "unknown_service"));
    // The operator clears it: 204, and the next deploy runs.
    let r = u.as_operator("DELETE", &path, b"").await;
    assert_eq!(r.status, 204);
    assert!(r.body.is_empty());
    assert_eq!(r.headers["content-type"], "application/json");
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(r.status, 202);
    let r = u.as_operator("DELETE", &path, b"").await;
    assert_eq!(r.status, 404, "cleared once");
}

#[tokio::test]
async fn health_rows() {
    let (env, u) = setup().await;
    let r = u.call(OTHER, "GET", "/v1/health", None, b"").await;
    assert_eq!((r.status, r.json()), (200, json!({"ok": true})));
    // Docker answers an error: 503.
    env.docker().set_ping_status(500);
    let r = u.call(OTHER, "GET", "/v1/health", None, b"").await;
    assert_eq!((r.status, r.error().as_str()), (503, "unavailable"));
    env.docker().set_ping_status(200);
    assert_eq!(
        u.call(OTHER, "GET", "/v1/health", None, b"").await.status,
        200
    );
    // The state directory is gone: 503.
    std::fs::remove_dir_all(env.state_dir()).unwrap();
    let r = u.call(OTHER, "GET", "/v1/health", None, b"").await;
    assert_eq!((r.status, r.error().as_str()), (503, "unavailable"));
    assert!(
        r.json()["detail"]
            .as_str()
            .unwrap()
            .contains("state directory")
    );
}

#[tokio::test]
async fn a_state_directory_that_fails_to_write_is_500() {
    let (env, u) = setup().await;
    std::fs::remove_dir_all(env.state_dir()).unwrap();
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 5, |_| {}))
        .await;
    assert_eq!((r.status, r.error().as_str()), (500, "internal"));
    // The failed write took no lock: the same request is not `busy`.
    let r = u
        .as_operator("POST", &deploys("app"), &deploy_body("app", 5, |_| {}))
        .await;
    assert_eq!(r.error(), "internal");
}

#[tokio::test]
async fn the_server_stops_when_told() {
    let (_env, u) = setup().await;
    assert!(u.stop().await.is_ok());
}
