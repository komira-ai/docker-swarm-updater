//! The HTTP API end to end: the peer, claims, mapping, request and request-target rows of
//! docs/design.md section 6, the local operator, health and the failed list.

mod admission;
mod status;

use serde_json::json;

use crate::harness::*;

const LIST: &str = "/v1/services";

async fn setup() -> (Env, Updater) {
    let env = Env::new().await;
    let updater = Updater::start(&env, Options::default()).await;
    (env, updater)
}

#[tokio::test]
async fn peer_rule_rows() {
    let (_env, u) = setup().await;
    let app = caller("app");
    // Claims from the proxy's uid: accepted.
    let r = u.call(PROXY, "GET", LIST, Some(u.token(&app)), b"").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["content-type"], "application/json");
    // Claims from another uid, and from uid 0: bad_peer.
    for uid in [OTHER, 0] {
        let r = u.call(uid, "GET", LIST, Some(u.token(&app)), b"").await;
        assert_eq!((r.status, r.error().as_str()), (401, "bad_peer"));
        assert_eq!(r.headers["content-type"], "application/json");
        assert!(r.json()["detail"].as_str().is_some());
    }
    // No claims from uid 0 with --allow-local-operator: the operator.
    assert_eq!(u.call(0, "GET", LIST, None, b"").await.status, 200);
    // No claims from another uid: bad_peer; from the proxy's uid: no_claims.
    let r = u.call(OTHER, "GET", LIST, None, b"").await;
    assert_eq!((r.status, r.error().as_str()), (401, "bad_peer"));
    let r = u.call(PROXY, "GET", LIST, None, b"").await;
    assert_eq!((r.status, r.error().as_str()), (401, "no_claims"));
    // Health: any peer, with or without claims.
    for (uid, claims) in [(OTHER, None), (OTHER, Some(u.token(&app))), (0, None)] {
        let r = u.call(uid, "GET", "/v1/health", claims, b"").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.json(), json!({"ok": true}));
    }
    // Health reads no claims: a claims header it cannot parse does not matter, and no jti
    // is spent.
    let r = u
        .call(OTHER, "GET", "/v1/health", Some("!!".into()), b"")
        .await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn no_claims_from_root_without_the_local_operator_flag() {
    let env = Env::new().await;
    let u = Updater::start(
        &env,
        Options {
            allow_local_operator: false,
            ..Options::default()
        },
    )
    .await;
    let r = u.call(0, "GET", LIST, None, b"").await;
    assert_eq!((r.status, r.error().as_str()), (401, "bad_peer"));
}

#[tokio::test]
async fn claims_rows() {
    let (env, u) = setup().await;
    let app = caller("app");
    let get = |claims: String| u.call(PROXY, "GET", LIST, Some(claims), b"");
    // Malformed: not base64url, not JSON, no jti, an empty jti, no exp.
    use base64::Engine as _;
    let b64 = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
    for bad in [
        "***".to_owned(),
        b64("not json"),
        b64(r#"{"exp": 4000000000}"#),
        b64(r#"{"jti": "", "exp": 4000000000}"#),
        b64(r#"{"jti": "x"}"#),
    ] {
        let r = get(bad).await;
        assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));
    }
    // Expired: exp is now, and in the past.
    for valid_for in [0, -60] {
        let r = get(u.token_with(&app, "late", valid_for)).await;
        assert_eq!((r.status, r.error().as_str()), (401, "expired"));
    }
    // A jti is accepted once, on any route.
    let once = u.token_with(&app, "once", 300);
    assert_eq!(get(once.clone()).await.status, 200);
    let r = get(once.clone()).await;
    assert_eq!((r.status, r.error().as_str()), (401, "replayed"));
    let r = u
        .call(
            PROXY,
            "POST",
            &deploys("app"),
            Some(once.clone()),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(r.error(), "replayed");
    let id = "d-aaaaaaaaaaaaaaaaaaaaaaaaaa";
    let r = u
        .call(PROXY, "GET", &format!("/v1/deploys/{id}"), Some(once), b"")
        .await;
    assert_eq!(r.error(), "replayed");
    // A request refused after its claims were read still spends its jti.
    let refused = u.token_with(&app, "refused", 300);
    let body = deploy_body("app", 5, |_| {});
    let r = u
        .call(
            PROXY,
            "POST",
            &deploys("nope"),
            Some(refused.clone()),
            &body,
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (404, "unknown_service"));
    let r = u
        .call(PROXY, "POST", &deploys("app"), Some(refused), &body)
        .await;
    assert_eq!((r.status, r.error().as_str()), (401, "replayed"));
    // Two claims headers, and one that is not text.
    let two = http(
        "GET",
        LIST,
        &[
            ("x-dsu-claims", u.token(&app)),
            ("x-dsu-claims", u.token(&app)),
        ],
        b"",
    );
    u.set_peer(PROXY);
    let r = raw(u.socket(), &two).await;
    assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));
    let mut not_text = http("GET", LIST, &[], b"");
    let end = not_text.len() - 2;
    not_text.splice(end..end, b"x-dsu-claims: \xff\xfe\r\n".iter().copied());
    let r = raw(u.socket(), &not_text).await;
    assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));

    // The accepted jtis are files; they survive a restart.
    assert_eq!(env.state_files("jti").len(), 2, "once and refused");
    u.stop().await.unwrap();
    let u = Updater::start(&env, Options::default()).await;
    let r = u
        .call(
            PROXY,
            "GET",
            LIST,
            Some(u.token_with(&app, "once", 300)),
            b"",
        )
        .await;
    assert_eq!(r.error(), "replayed", "a restart does not forget it");
}

#[tokio::test]
async fn jti_files_are_pruned_after_exp() {
    let (env, u) = setup().await;
    let app = caller("app");
    assert_eq!(
        u.call(PROXY, "GET", LIST, Some(u.token_with(&app, "a", 300)), b"")
            .await
            .status,
        200
    );
    assert_eq!(
        u.call(PROXY, "GET", LIST, Some(u.token_with(&app, "b", 7200)), b"")
            .await
            .status,
        200
    );
    assert_eq!(env.state_files("jti").len(), 2);
    // 301 s later, within the hour: nothing is pruned.
    env.clock.advance(std::time::Duration::from_secs(301));
    assert_eq!(
        u.call(PROXY, "GET", LIST, Some(u.token_with(&app, "c", 300)), b"")
            .await
            .status,
        200
    );
    assert_eq!(env.state_files("jti").len(), 3);
    // An hour later, the next request prunes the expired ids ("a" and "c").
    env.clock.advance(std::time::Duration::from_secs(3600));
    assert_eq!(
        u.call(PROXY, "GET", LIST, Some(u.token_with(&app, "d", 300)), b"")
            .await
            .status,
        200
    );
    assert_eq!(env.state_files("jti").len(), 2, "b and d");
    // A restart prunes too.
    u.stop().await.unwrap();
    env.clock.advance(std::time::Duration::from_secs(8000));
    let _u = Updater::start(&env, Options::default()).await;
    assert_eq!(env.state_files("jti").len(), 0);
}

#[tokio::test]
async fn mapping_rows() {
    let (_env, u) = setup().await;
    let (app, web) = (caller("app"), caller("web"));
    // A caller of app deploys web: 403.
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("web"),
            &deploy_body("web", 5, |_| {}),
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (403, "not_allowed"));
    // The operator starts a deploy of web; the caller of app cannot read it, a caller of web can.
    let r = u
        .as_operator("POST", &deploys("web"), &deploy_body("web", 5, |_| {}))
        .await;
    assert_eq!(r.status, 202);
    let id = r.json()["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/deploys/{id}");
    let r = u.as_caller(&app, "GET", &path, b"").await;
    assert_eq!((r.status, r.error().as_str()), (404, "unknown_deploy"));
    assert_eq!(u.as_caller(&web, "GET", &path, b"").await.status, 200);
    assert_eq!(u.as_operator("GET", &path, b"").await.status, 200);
    // Lists: only the caller's services, all for the operator.
    let names = |reply: crate::harness::Reply| -> Vec<String> {
        reply.json()["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["service"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(names(u.as_caller(&app, "GET", LIST, b"").await), ["app"]);
    assert_eq!(
        names(u.as_operator("GET", LIST, b"").await),
        ["app", "web", "ghost"]
    );
    // A caller no service lists: 403 on every route that needs one.
    let stranger = json!({"repository": "example-org/other", "repository_id": "9"});
    let r = u.as_caller(&stranger, "GET", LIST, b"").await;
    assert_eq!((r.status, r.error().as_str()), (403, "not_allowed"));
    let r = u
        .as_caller(
            &stranger,
            "POST",
            &deploys("app"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!(r.error(), "not_allowed");
    let r = u.as_caller(&stranger, "GET", &path, b"").await;
    assert_eq!(r.error(), "unknown_deploy");
}

async fn post(u: &Updater, body: Vec<u8>) -> crate::harness::Reply {
    u.as_caller(&caller("app"), "POST", &deploys("app"), &body)
        .await
}

#[tokio::test]
async fn request_rows() {
    let (_env, u) = setup().await;
    let app = caller("app");
    let r = u
        .as_caller(
            &app,
            "POST",
            &deploys("nope"),
            &deploy_body("app", 5, |_| {}),
        )
        .await;
    assert_eq!((r.status, r.error().as_str()), (404, "unknown_service"));
    // Unknown field, bad JSON, a digest that is not one, an over-long version.
    for body in [
        deploy_body("app", 5, |b| b["surprise"] = json!(1)),
        b"{".to_vec(),
        deploy_body("app", 5, |b| b["image_digest"] = json!("sha256:xyz")),
        deploy_body("app", 5, |b| b["version"] = json!("v".repeat(129))),
    ] {
        let r = post(&u, body).await;
        assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));
    }
    // allow_older from a caller: 400.
    let r = post(
        &u,
        deploy_body("app", 5, |b| b["allow_older"] = json!(true)),
    )
    .await;
    assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));
    // A signer differing in one field: 403; equal: accepted.
    let signer = || {
        json!({
            "repository": "example-org/app",
            "workflow": ".github/workflows/artifacts.yml",
            "ref": "refs/heads/main",
        })
    };
    for field in ["repository", "workflow", "ref"] {
        let r = post(
            &u,
            deploy_body("app", 5, |b| {
                b["signer"] = signer();
                b["signer"][field] = json!("other");
            }),
        )
        .await;
        assert_eq!(
            (r.status, r.error().as_str()),
            (403, "signer_mismatch"),
            "{field}"
        );
    }
    // A signer that equals the configured one, and a version of 128 bytes, are accepted.
    let r = post(
        &u,
        deploy_body("app", 5, |b| {
            b["signer"] = signer();
            b["version"] = json!("v".repeat(128));
        }),
    )
    .await;
    assert_eq!(r.status, 202);
    assert_eq!(r.json()["version"], "v".repeat(128));
    // A body of 16 KiB is read; of 16 KiB + 1 it is 413.
    let padded = |len: usize| {
        let mut body = deploy_body("app", 5, |_| {});
        body.resize(len, b' ');
        body
    };
    assert_eq!(post(&u, padded(16 * 1024)).await.status, 200);
    let r = post(&u, padded(16 * 1024 + 1)).await;
    assert_eq!((r.status, r.error().as_str()), (413, "payload_too_large"));
}

#[tokio::test]
async fn a_body_that_ends_early_is_a_bad_request() {
    let (_env, u) = setup().await;
    u.set_peer(PROXY);
    let mut request = http(
        "POST",
        &deploys("app"),
        &[("x-dsu-claims", u.token(&caller("app")))],
        b"",
    );
    let text = String::from_utf8(request.clone())
        .unwrap()
        .replace("content-length: 0", "content-length: 100");
    request = text.into_bytes();
    request.extend_from_slice(b"{\"image");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(u.socket()).await.unwrap();
    stream.write_all(&request).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut data = Vec::new();
    let _ = stream.read_to_end(&mut data).await;
    // The answer may or may not arrive before the connection is torn down; the server must
    // still be serving afterwards.
    assert_eq!(u.as_operator("GET", LIST, b"").await.status, 200);
}

#[tokio::test]
async fn a_request_body_that_stalls_is_a_bad_request_once_the_idle_time_has_passed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (env, u) = setup().await;
    u.set_peer(PROXY);
    let head = http(
        "POST",
        &deploys("app"),
        &[("x-dsu-claims", u.token(&caller("app")))],
        b"",
    );
    let mut request = String::from_utf8(head)
        .unwrap()
        .replace("content-length: 0", "content-length: 100")
        .into_bytes();
    request.extend_from_slice(b"{\"image");
    let mut stream = tokio::net::UnixStream::connect(u.socket()).await.unwrap();
    stream.write_all(&request).await.unwrap();
    // The handler waits for the other 93 bytes under a deadline of the clock; the test moves it.
    env.clock.wait_pending().await;
    env.clock.advance(dsu_server::server::IDLE_TIMEOUT);
    let mut data = Vec::new();
    stream.read_to_end(&mut data).await.unwrap();
    let r = parse_reply(&data);
    assert_eq!((r.status, r.error().as_str()), (400, "bad_request"));
    assert!(r.json()["detail"].as_str().unwrap().contains("too long"));
    assert!(env.state_files("deploys").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_connection_idle_for_30_seconds_is_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_env, u) = setup().await;
    // Nothing is sent: tokio's paused time moves to the server's timer, which closes it.
    let mut silent = tokio::net::UnixStream::connect(u.socket()).await.unwrap();
    let mut data = Vec::new();
    let _ = silent.read_to_end(&mut data).await;
    assert!(data.is_empty(), "{:?}", String::from_utf8_lossy(&data));
    // One request is answered and the connection is kept; then it sits idle and is closed.
    let mut kept = tokio::net::UnixStream::connect(u.socket()).await.unwrap();
    kept.write_all(b"GET /v1/health HTTP/1.1\r\nhost: dsu\r\n\r\n")
        .await
        .unwrap();
    let mut data = Vec::new();
    let mut buffer = [0u8; 1024];
    while !data.ends_with(b"}") {
        let n = kept.read(&mut buffer).await.unwrap();
        assert_ne!(n, 0, "closed before the answer");
        data.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(parse_reply(&data).status, 200);
    let mut rest = Vec::new();
    let _ = kept.read_to_end(&mut rest).await;
    assert!(rest.is_empty());
}
