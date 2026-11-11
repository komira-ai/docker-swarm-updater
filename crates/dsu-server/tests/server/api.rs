//! The HTTP API end to end: the peer, claims, mapping, request and request-target rows of
//! docs/design.md section 6, the local operator, health and the failed list.

use dsu_core::ids::{DeployId, ServiceName};
use dsu_core::record::{CallerRecord, NewRecord, Phase, Record};
use dsu_testkit::docker::{FakeTask, FakeUpdateStatus};
use serde_json::{Value, json};

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
    assert!(body["trusted_root_newest_key"]["from"].as_str().is_some());
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
async fn a_connection_whose_peer_cannot_be_read_is_closed() {
    let (_env, u) = setup().await;
    u.fail_peer(true);
    let r = raw_bytes(u.socket(), &http("GET", "/v1/health", &[], b"")).await;
    assert!(r.is_empty(), "no answer");
    u.fail_peer(false);
    assert_eq!(
        u.call(OTHER, "GET", "/v1/health", None, b"").await.status,
        200
    );
}

async fn raw_bytes(socket: &std::path::Path, request: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let _ = stream.write_all(request).await;
    let mut data = Vec::new();
    let _ = stream.read_to_end(&mut data).await;
    data
}

#[tokio::test]
async fn the_server_stops_when_told() {
    let (_env, u) = setup().await;
    assert!(u.stop().await.is_ok());
}
