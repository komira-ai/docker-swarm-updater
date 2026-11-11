//! The peer's credentials as the kernel gives them across a container boundary, and what a
//! refused peer is told and what is logged: never a silent close.

use dsu_server::peer::Credentials;

use super::*;

/// What `SO_PEERCRED` reports to a containerised updater for root on the host: pid 0 (the
/// client is outside the updater's pid namespace) and uid 0 (no user namespace remap).
const HOST_ROOT: Credentials = Credentials {
    pid: 0,
    uid: 0,
    gid: 0,
};

async fn updater(allow_local_operator: bool) -> (Env, Updater) {
    let env = Env::new().await;
    let options = Options {
        allow_local_operator,
        ..Options::default()
    };
    let updater = Updater::start(&env, options).await;
    (env, updater)
}

#[tokio::test]
async fn host_root_outside_the_pid_namespace_is_the_local_operator_with_the_flag() {
    let (_env, u) = updater(true).await;
    u.set_credentials(HOST_ROOT);
    let r = raw(u.socket(), &http("GET", LIST, &[], b"")).await;
    assert_eq!(r.status, 200);
    let r = raw(u.socket(), &http("GET", "/v1/health", &[], b"")).await;
    assert_eq!((r.status, r.json()), (200, json!({"ok": true})));
    assert_eq!(u.log_lines(), Vec::<String>::new());
}

#[tokio::test]
async fn host_root_outside_the_pid_namespace_is_refused_without_the_flag_with_a_reason() {
    let (_env, u) = updater(false).await;
    u.set_credentials(HOST_ROOT);
    let r = raw(u.socket(), &http("GET", LIST, &[], b"")).await;
    assert_eq!(r.status, 401);
    assert_eq!(
        r.json(),
        json!({
            "error": "bad_peer",
            "detail": "uid 0 is the local operator only when the updater runs with --allow-local-operator",
        })
    );
    assert_eq!(
        u.log_lines(),
        vec![
            "refused GET /v1/services from peer uid 0 gid 0 pid 0: 401 bad_peer: uid 0 is the local \
             operator only when the updater runs with --allow-local-operator"
        ]
    );
    // Health still answers it.
    let r = raw(u.socket(), &http("GET", "/v1/health", &[], b"")).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn unreadable_credentials_are_answered_401_with_the_reason_and_logged() {
    let (_env, u) = updater(true).await;
    u.fail_peer(true);
    let r = raw(u.socket(), &http("GET", LIST, &[], b"")).await;
    assert_eq!(r.status, 401);
    assert_eq!(
        r.json(),
        json!({
            "error": "bad_peer",
            "detail": "the peer's credentials cannot be read: no credentials",
        })
    );
    // Health is answered for any peer that can open the socket, and is not a refusal.
    let r = raw(u.socket(), &http("GET", "/v1/health", &[], b"")).await;
    assert_eq!((r.status, r.json()), (200, json!({"ok": true})));
    assert_eq!(
        u.log_lines(),
        vec![
            "refused GET /v1/services from peer with unreadable credentials: 401 bad_peer: the \
             peer's credentials cannot be read: no credentials"
        ]
    );
    // The next connection whose credentials are read is admitted as usual.
    u.fail_peer(false);
    assert_eq!(u.as_operator("GET", LIST, b"").await.status, 200);
}

#[tokio::test]
async fn every_peer_refusal_names_its_rule_in_the_answer_and_the_log() {
    let (_env, u) = updater(true).await;
    let app = caller("app");
    let cases = [
        (
            0,
            Some(u.token(&app)),
            "bad_peer",
            "a claims header is never accepted from uid 0",
        ),
        (
            OTHER,
            Some(u.token(&app)),
            "bad_peer",
            "a claims header is accepted only from --proxy-uid, not from uid 4321",
        ),
        (
            OTHER,
            None,
            "bad_peer",
            "a request without a claims header is accepted only from uid 0, not from uid 4321",
        ),
        (
            PROXY,
            None,
            "no_claims",
            "the request carries no claims header",
        ),
    ];
    let mut expected_log = Vec::new();
    for (uid, claims, token, detail) in cases {
        let r = u.call(uid, "GET", LIST, claims, b"").await;
        assert_eq!(r.status, 401);
        assert_eq!(r.json(), json!({"error": token, "detail": detail}));
        expected_log.push(format!(
            "refused GET /v1/services from peer uid {uid} gid {uid} pid {PEER_PID}: 401 {token}: \
             {detail}"
        ));
    }
    assert_eq!(u.log_lines(), expected_log);
}

#[tokio::test]
async fn a_403_is_logged_and_other_errors_are_not() {
    let (_env, u) = updater(true).await;
    // 403: a caller of `web` deploys `app`.
    let r = u
        .as_caller(
            &caller("web"),
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(r.status, 403);
    let detail = r.json()["detail"].as_str().unwrap().to_owned();
    // 404 and 405 are not refusals of the peer: not logged.
    assert_eq!(u.as_operator("GET", "/v1/nothing", b"").await.status, 404);
    assert_eq!(u.as_operator("PUT", LIST, b"").await.status, 405);
    assert_eq!(
        u.log_lines(),
        vec![format!(
            "refused POST /v1/services/app/deploys from peer uid {PROXY} gid {PROXY} pid \
             {PEER_PID}: 403 not_allowed: {detail}"
        )]
    );
}
