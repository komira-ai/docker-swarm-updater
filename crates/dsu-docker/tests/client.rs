//! The real client against the fake Docker API in a temporary directory, and against raw
//! sockets that answer badly.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failed unwrap is a failed test"
)]

use std::path::{Path, PathBuf};

use dsu_core::ids::{DeployId, Digest};
use dsu_docker::{
    DEPLOY_LABEL, DIGEST_LABEL, DockerClient, DockerError, SWARM_SERVICE_NAME_LABEL, updated_spec,
};
use dsu_testkit::docker::{
    FakeDocker, FakeService, FakeTask, FakeUpdateStatus, Outcome, RecordedUpdate, UpdateScript,
};
use jiff::Timestamp;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

const OLD: &str = "registry:5000/example-org/app@sha256:1111111111111111111111111111111111111111111111111111111111111111";
const NEW: &str = "registry:5000/example-org/app@sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn ts(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn deploy_id() -> DeployId {
    DeployId::from_random([7; 16])
}

fn digest() -> Digest {
    Digest::from_sha256([2; 32])
}

struct Env {
    _dir: tempfile::TempDir,
    fake: FakeDocker,
    client: DockerClient,
}

async fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let fake = FakeDocker::start(dir.path(), ts("2026-10-01T00:00:00Z")).await;
    fake.add_service(FakeService::new("svc1", "app_server", OLD));
    let client = DockerClient::new(fake.socket());
    Env {
        _dir: dir,
        fake,
        client,
    }
}

/// The JSON pointers of the leaves where `a` and `b` differ.
fn differences(path: &str, a: &Value, b: &Value, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                differences(
                    &format!("{path}/{key}"),
                    x.get(key).unwrap_or(&Value::Null),
                    y.get(key).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        _ if a != b => out.push(path.to_owned()),
        _ => {}
    }
}

fn http_response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A socket that answers every request with `response` and closes the connection.
async fn raw_server(dir: &Path, response: Vec<u8>) -> DockerClient {
    let socket = dir.join("raw.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    DockerClient::new(socket)
}

#[tokio::test]
async fn ping_answers_and_reports_an_unwell_daemon() {
    let env = env().await;
    assert_eq!(env.client.socket(), env.fake.socket());
    env.client.ping().await.unwrap();
    env.fake.set_ping_status(503);
    let err = env.client.ping().await.unwrap_err();
    assert!(
        matches!(&err, DockerError::Unexpected { status: 503, message, .. } if message == "OK"),
        "{err}"
    );
    assert!(err.to_string().contains("GET /_ping"));
}

#[tokio::test]
async fn inspect_reads_a_service_by_name_and_by_id() {
    let env = env().await;
    let by_name = env.client.inspect_service("app_server").await.unwrap();
    let by_id = env.client.inspect_service("svc1").await.unwrap();
    assert_eq!(by_name, by_id);
    assert_eq!(by_name.id, "svc1");
    assert_eq!(by_name.version_index, 1);
    assert_eq!(by_name.image, OLD);
    assert_eq!(by_name.previous_image, None);
    assert_eq!(by_name.update_status, None);
    assert_eq!(by_name.deploy_label, None);
    assert_eq!(by_name.digest_label, None);
    assert_eq!(by_name.spec["Mode"]["Replicated"]["Replicas"], 1);
    assert_eq!(
        by_name.spec["TaskTemplate"]["Resources"]["Limits"]["MemoryBytes"],
        268_435_456
    );
}

#[tokio::test]
async fn inspect_reads_the_update_status_and_the_previous_image() {
    let env = env().await;
    let mut service = FakeService::new("svc2", "other", NEW);
    service.previous_spec = Some(FakeService::new("svc2", "other", OLD).spec);
    service.spec["Labels"] = json!({DEPLOY_LABEL: "d-abc", DIGEST_LABEL: "sha256:abc", "n": 1});
    env.fake.add_service(service);
    env.fake.set_update_status(
        "other",
        FakeUpdateStatus {
            state: "rollback_completed".to_owned(),
            started_at: ts("2026-10-02T03:04:05.123456789Z"),
            message: "rollback completed".to_owned(),
        },
    );
    let view = env.client.inspect_service("other").await.unwrap();
    assert_eq!(view.previous_image.as_deref(), Some(OLD));
    assert_eq!(view.deploy_label.as_deref(), Some("d-abc"));
    assert_eq!(view.digest_label.as_deref(), Some("sha256:abc"));
    let status = view.update_status.unwrap();
    assert_eq!(status.state, "rollback_completed");
    assert_eq!(
        status.started_at,
        Some(ts("2026-10-02T03:04:05.123456789Z"))
    );
    assert_eq!(status.message.as_deref(), Some("rollback completed"));
}

#[tokio::test]
async fn names_with_reserved_characters_round_trip() {
    let env = env().await;
    env.fake
        .add_service(FakeService::new("svc3", "odd name/é~._-", OLD));
    let view = env.client.inspect_service("odd name/é~._-").await.unwrap();
    assert_eq!(view.id, "svc3");
}

#[tokio::test]
async fn inspect_of_a_missing_service_is_service_not_found() {
    let env = env().await;
    let err = env.client.inspect_service("nope").await.unwrap_err();
    assert!(
        matches!(&err, DockerError::ServiceNotFound { service } if service == "nope"),
        "{err}"
    );
    assert_eq!(err.to_string(), "docker service \"nope\" not found");
}

#[tokio::test]
async fn inspect_refuses_a_service_without_an_image() {
    let env = env().await;
    let mut service = FakeService::new("svc4", "bare", OLD);
    service.spec["TaskTemplate"] = json!({"ContainerSpec": {}});
    env.fake.add_service(service);
    let err = env.client.inspect_service("bare").await.unwrap_err();
    assert!(matches!(
        err,
        DockerError::Malformed {
            what: "TaskTemplate.ContainerSpec.Image"
        }
    ));
}

#[tokio::test]
async fn an_update_changes_the_image_and_two_labels_and_nothing_else() {
    let env = env().await;
    let before = env.client.inspect_service("app_server").await.unwrap();
    env.client
        .update_service(&before, NEW, &deploy_id(), &digest())
        .await
        .unwrap();

    let updates = env.fake.updates();
    assert_eq!(updates.len(), 1);
    let RecordedUpdate {
        service,
        version,
        body,
    } = &updates[0];
    assert_eq!((service.as_str(), *version), ("svc1", 1));
    let mut changed = Vec::new();
    differences("", &before.spec, body, &mut changed);
    assert_eq!(
        changed,
        [
            format!("/Labels/{DEPLOY_LABEL}"),
            format!("/Labels/{DIGEST_LABEL}"),
            "/TaskTemplate/ContainerSpec/Image".to_owned()
        ]
    );
    assert_eq!(
        body,
        &updated_spec(&before.spec, NEW, &deploy_id(), &digest()).unwrap()
    );

    let after = env.client.inspect_service("app_server").await.unwrap();
    assert_eq!(after.version_index, 2);
    assert_eq!(after.image, NEW);
    assert_eq!(after.previous_image.as_deref(), Some(OLD));
    assert_eq!(after.deploy_label.as_deref(), Some(deploy_id().as_str()));
    assert_eq!(after.digest_label.as_deref(), Some(digest().as_str()));
    assert_eq!(after.spec["Labels"]["com.example.team"], "platform");
}

#[test]
fn updated_spec_creates_missing_labels_and_refuses_malformed_specs() {
    let id = deploy_id();
    let digest = digest();
    let container = json!({"ContainerSpec": {"Image": OLD, "Env": ["A=1"]}});

    for spec in [
        json!({"TaskTemplate": container}),
        json!({"TaskTemplate": container, "Labels": null}),
    ] {
        let out = updated_spec(&spec, NEW, &id, &digest).unwrap();
        assert_eq!(
            out,
            json!({
                "TaskTemplate": {"ContainerSpec": {"Image": NEW, "Env": ["A=1"]}},
                "Labels": {DEPLOY_LABEL: id.as_str(), DIGEST_LABEL: digest.as_str()},
            })
        );
    }

    let kept = json!({"TaskTemplate": container, "Labels": {"a": "b", DEPLOY_LABEL: "old"}});
    let out = updated_spec(&kept, NEW, &id, &digest).unwrap();
    assert_eq!(out["Labels"]["a"], "b");
    assert_eq!(out["Labels"][DEPLOY_LABEL], id.as_str());

    let not_object = updated_spec(&json!([1]), NEW, &id, &digest).unwrap_err();
    assert!(matches!(
        not_object,
        DockerError::Malformed { what: "Spec" }
    ));
    for spec in [
        json!({}),
        json!({"TaskTemplate": {}}),
        json!({"TaskTemplate": {"ContainerSpec": "x"}}),
        json!({"TaskTemplate": 3}),
    ] {
        let err = updated_spec(&spec, NEW, &id, &digest).unwrap_err();
        assert!(
            matches!(
                err,
                DockerError::Malformed {
                    what: "TaskTemplate.ContainerSpec"
                }
            ),
            "{spec}"
        );
    }
    let labels = updated_spec(
        &json!({"TaskTemplate": container, "Labels": [1]}),
        NEW,
        &id,
        &digest,
    )
    .unwrap_err();
    assert!(matches!(labels, DockerError::Malformed { what: "Labels" }));
    assert!(labels.to_string().contains("Labels"));
}

#[tokio::test]
async fn update_of_a_malformed_spec_sends_nothing() {
    let env = env().await;
    let mut view = env.client.inspect_service("app_server").await.unwrap();
    view.spec = json!({"Name": "x"});
    let err = env
        .client
        .update_service(&view, NEW, &deploy_id(), &digest())
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::Malformed { .. }));
    assert!(env.fake.updates().is_empty());
}

#[tokio::test]
async fn a_stale_version_is_a_conflict_the_caller_can_retry_once() {
    let env = env().await;
    let mut script = UpdateScript::new(Outcome::Converges);
    script.conflicts = 1;
    env.fake.set_script(script);

    let first = env.client.inspect_service("app_server").await.unwrap();
    let err = env
        .client
        .update_service(&first, NEW, &deploy_id(), &digest())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DockerError::VersionConflict { message } if message == "update out of sequence"),
        "{err}"
    );

    let second = env.client.inspect_service("app_server").await.unwrap();
    assert_eq!(second.version_index, 2);
    env.client
        .update_service(&second, NEW, &deploy_id(), &digest())
        .await
        .unwrap();
    let versions: Vec<u64> = env.fake.updates().iter().map(|u| u.version).collect();
    assert_eq!(versions, [1, 2]);
}

#[tokio::test]
async fn two_conflicts_in_a_row_are_both_conflicts() {
    let env = env().await;
    let mut script = UpdateScript::new(Outcome::Converges);
    script.conflicts = 2;
    env.fake.set_script(script);
    for _ in 0..2 {
        let view = env.client.inspect_service("app_server").await.unwrap();
        let err = env
            .client
            .update_service(&view, NEW, &deploy_id(), &digest())
            .await
            .unwrap_err();
        assert!(matches!(err, DockerError::VersionConflict { .. }));
    }
    assert_eq!(
        env.fake.service("svc1").spec["TaskTemplate"]["ContainerSpec"]["Image"],
        OLD
    );
}

#[tokio::test]
async fn other_refusals_carry_the_daemons_message() {
    let env = env().await;
    env.fake.set_script(UpdateScript::new(Outcome::Refuses(
        "rpc error: invalid image".to_owned(),
    )));
    let view = env.client.inspect_service("app_server").await.unwrap();
    let err = env
        .client
        .update_service(&view, NEW, &deploy_id(), &digest())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DockerError::Refused { status: 500, message } if message == "rpc error: invalid image"),
        "{err}"
    );

    let mut gone = view;
    gone.id = "vanished".to_owned();
    let err = env
        .client
        .update_service(&gone, NEW, &deploy_id(), &digest())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DockerError::Refused { status: 404, message } if message.contains("vanished")),
        "{err}"
    );
}

async fn read_statuses(env: &Env, reads: usize) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..reads {
        let view = env.client.inspect_service("app_server").await.unwrap();
        out.push(view.update_status.map_or("none".to_owned(), |s| s.state));
    }
    out
}

async fn start_update(env: &Env) {
    let view = env.client.inspect_service("app_server").await.unwrap();
    env.client
        .update_service(&view, NEW, &deploy_id(), &digest())
        .await
        .unwrap();
}

fn stale_status() -> FakeUpdateStatus {
    FakeUpdateStatus {
        state: "rollback_completed".to_owned(),
        started_at: ts("2026-09-15T00:00:00Z"),
        message: "old".to_owned(),
    }
}

#[tokio::test]
async fn a_converging_update_goes_stale_updating_completed_and_moves_the_tasks() {
    let env = env().await;
    env.fake.set_tasks(
        "app_server",
        vec![FakeTask::running("t1", OLD), {
            let mut failed = FakeTask::running("t2", OLD);
            failed.state = "failed".to_owned();
            failed.error = Some("boom".to_owned());
            failed
        }],
    );
    env.fake.set_update_status("svc1", stale_status());
    let mut script = UpdateScript::new(Outcome::Converges);
    script.stale_reads = 2;
    script.updating_reads = 1;
    env.fake.set_script(script);

    assert_eq!(
        read_statuses(&env, 2).await,
        ["rollback_completed", "rollback_completed"]
    );
    env.fake.set_now(ts("2026-10-01T00:00:30Z"));
    start_update(&env).await;
    assert_eq!(
        read_statuses(&env, 5).await,
        [
            "rollback_completed",
            "rollback_completed",
            "updating",
            "completed",
            "completed"
        ]
    );

    let service = env.fake.service("svc1");
    assert_eq!(
        service.update_status.as_ref().unwrap().started_at,
        ts("2026-10-01T00:00:30Z")
    );
    assert_eq!(service.index, 2);
    let tasks = env.client.running_tasks("svc1").await.unwrap();
    assert_eq!(tasks.len(), 2);
    assert!(
        tasks
            .iter()
            .all(|t| t.image == NEW && t.state == "running" && t.error.is_none())
    );
}

#[tokio::test]
async fn a_rolling_back_update_restores_the_previous_spec() {
    let env = env().await;
    env.fake
        .set_tasks("svc1", vec![FakeTask::running("t1", OLD)]);
    env.fake.set_script(UpdateScript::new(Outcome::RollsBack));
    start_update(&env).await;
    let view = env.client.inspect_service("svc1").await.unwrap();
    assert_eq!(
        view.update_status.as_ref().unwrap().state,
        "rollback_completed"
    );
    assert_eq!(view.image, OLD);
    assert_eq!(view.previous_image.as_deref(), Some(NEW));
    assert_eq!(view.version_index, 3);
    assert_eq!(view.deploy_label, None);
    assert_eq!(
        env.client.running_tasks("svc1").await.unwrap()[0].image,
        OLD
    );
}

#[tokio::test]
async fn a_pausing_update_stays_paused() {
    let env = env().await;
    env.fake.set_script(UpdateScript::new(Outcome::Pauses));
    start_update(&env).await;
    assert_eq!(read_statuses(&env, 3).await, ["paused", "paused", "paused"]);
}

#[tokio::test]
async fn an_update_that_never_ends_keeps_updating() {
    let env = env().await;
    env.fake.set_script(UpdateScript::new(Outcome::NeverEnds));
    start_update(&env).await;
    assert_eq!(
        read_statuses(&env, 3).await,
        ["updating", "updating", "updating"]
    );
}

#[tokio::test]
async fn running_tasks_filters_by_service_and_desired_state() {
    let env = env().await;
    env.fake.add_service(FakeService::new("svc9", "other", OLD));
    let mut old = FakeTask::running("t-old", OLD);
    old.desired_state = "shutdown".to_owned();
    old.state = "shutdown".to_owned();
    let mut failing = FakeTask::running("t-new", NEW);
    failing.state = "starting".to_owned();
    failing.error = Some("task: non-zero exit (1)".to_owned());
    env.fake.set_tasks("svc1", vec![old, failing]);
    env.fake
        .set_tasks("svc9", vec![FakeTask::running("t-other", OLD)]);

    let tasks = env.client.running_tasks("svc1").await.unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].id, "t-new");
    assert_eq!(tasks[0].image, NEW);
    assert_eq!(tasks[0].state, "starting");
    assert_eq!(tasks[0].error.as_deref(), Some("task: non-zero exit (1)"));
    assert!(
        env.client
            .running_tasks("missing")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn own_service_name_reads_the_swarm_label() {
    let env = env().await;
    env.fake.add_container(
        "abc123",
        &[(SWARM_SERVICE_NAME_LABEL, "app_updater"), ("x", "y")],
    );
    env.fake.add_container("plain", &[("x", "y")]);
    assert_eq!(
        env.client
            .own_service_name("abc123")
            .await
            .unwrap()
            .as_deref(),
        Some("app_updater")
    );
    assert_eq!(env.client.own_service_name("plain").await.unwrap(), None);
    assert_eq!(env.client.own_service_name("unknown").await.unwrap(), None);
}

#[tokio::test]
async fn a_container_with_null_labels_belongs_to_no_service() {
    let dir = tempfile::tempdir().unwrap();
    let client = raw_server(
        dir.path(),
        http_response(200, r#"{"Config":{"Labels":null}}"#),
    )
    .await;
    assert_eq!(client.own_service_name("h").await.unwrap(), None);
}

#[tokio::test]
async fn the_fake_answers_unknown_routes_with_404() {
    let env = env().await;
    let mut stream = tokio::net::UnixStream::connect(env.fake.socket())
        .await
        .unwrap();
    stream
        .write_all(b"GET /nope HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    assert!(
        answer.ends_with(r#"{"message":"page not found"}"#),
        "{answer}"
    );
}

#[tokio::test]
async fn the_fake_treats_a_bad_update_request_as_version_zero_with_a_null_body() {
    let env = env().await;
    let mut stream = tokio::net::UnixStream::connect(env.fake.socket())
        .await
        .unwrap();
    stream
        .write_all(b"POST /services/svc1/update HTTP/1.1\r\nHost: docker\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
        .await
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.contains("out of sequence"), "{answer}");
    let updates = env.fake.updates();
    assert_eq!((updates[0].version, &updates[0].body), (0, &Value::Null));
}

#[tokio::test]
async fn a_missing_socket_is_a_connect_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing: PathBuf = dir.path().join("none.sock");
    let err = DockerClient::new(&missing).ping().await.unwrap_err();
    assert!(
        matches!(&err, DockerError::Connect { socket, .. } if *socket == missing),
        "{err}"
    );
    assert!(err.to_string().contains("none.sock"));
}

#[tokio::test]
async fn an_over_long_name_is_a_bad_target() {
    let env = env().await;
    let err = env
        .client
        .inspect_service(&"a".repeat(70_000))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DockerError::BadTarget { request, .. } if request.starts_with("GET /services/aaa")),
        "{err}"
    );
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused() {
    let env = env().await;
    let small = env.client.clone().with_max_body(10);
    let err = small.inspect_service("app_server").await.unwrap_err();
    assert!(matches!(err, DockerError::BodyTooLarge { limit: 10, .. }));
    assert!(err.to_string().contains("longer than 10 bytes"));
    // The cap is on the whole body: a body of exactly the cap is read.
    let dir = tempfile::tempdir().unwrap();
    raw_server(dir.path(), http_response(200, "0123456789"))
        .await
        .with_max_body(10)
        .ping()
        .await
        .unwrap();
}

#[tokio::test]
async fn a_peer_that_hangs_up_is_a_transport_error() {
    let dir = tempfile::tempdir().unwrap();
    let client = raw_server(dir.path(), Vec::new()).await;
    let err = client.ping().await.unwrap_err();
    assert!(
        matches!(&err, DockerError::Transport { request, .. } if request == "GET /_ping"),
        "{err}"
    );
}

#[tokio::test]
async fn a_body_cut_short_is_a_transport_error() {
    let dir = tempfile::tempdir().unwrap();
    let client = raw_server(
        dir.path(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc".to_vec(),
    )
    .await;
    let err = client.ping().await.unwrap_err();
    assert!(matches!(err, DockerError::Transport { .. }));
}

#[tokio::test]
async fn unexpected_statuses_and_undecodable_answers_are_errors_with_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let boom = raw_server(dir.path(), http_response(500, "  boom \n")).await;
    let err = boom.inspect_service("x").await.unwrap_err();
    assert!(
        matches!(&err, DockerError::Unexpected { request, status: 500, message } if request == "GET /services/x" && message == "boom"),
        "{err}"
    );
    assert!(matches!(
        boom.running_tasks("x").await.unwrap_err(),
        DockerError::Unexpected { status: 500, .. }
    ));
    assert!(matches!(
        boom.own_service_name("x").await.unwrap_err(),
        DockerError::Unexpected { status: 500, .. }
    ));

    let dir = tempfile::tempdir().unwrap();
    let junk = raw_server(dir.path(), http_response(200, "not json")).await;
    for (name, err) in [
        ("service", junk.inspect_service("x").await.unwrap_err()),
        ("tasks", junk.running_tasks("x").await.unwrap_err()),
        ("container", junk.own_service_name("x").await.unwrap_err()),
    ] {
        assert!(
            matches!(&err, DockerError::Decode { what, .. } if *what == name),
            "{err}"
        );
    }
}

#[tokio::test]
async fn a_long_daemon_message_is_cut() {
    let dir = tempfile::tempdir().unwrap();
    let long = raw_server(
        dir.path(),
        http_response(500, &json!({"message": "x".repeat(600)}).to_string()),
    )
    .await;
    let DockerError::Unexpected { message, .. } = long.ping().await.unwrap_err() else {
        panic!("not Unexpected")
    };
    assert_eq!(message.len(), 512);
}
