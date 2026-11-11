//! The real `Http` against an HTTP server on 127.0.0.1 port 0: what goes on the wire, and which
//! failures are transport errors.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

mod support;

use std::net::TcpListener;

use dsu_deploy::client::{Http, Method, Request, Response};
use dsu_deploy::http::{MAX_ANSWER_BYTES, UreqHttp};
use support::Server;

fn request(method: Method, url: String, body: Option<&[u8]>) -> Request {
    Request {
        method,
        url,
        bearer: "secret-token".to_owned(),
        body: body.map(<[u8]>::to_vec),
    }
}

#[test]
fn post_sends_the_json_body_and_the_bearer_and_reads_any_status() {
    let server = Server::start(|_, _| (409, b"{\"error\":\"busy\"}".to_vec()));
    let answer = UreqHttp::new()
        .send(&request(
            Method::Post,
            server.url("/v1/services/app/deploys"),
            Some(b"{\"a\":1}"),
        ))
        .unwrap();
    assert_eq!(
        answer,
        Response {
            status: 409,
            body: b"{\"error\":\"busy\"}".to_vec()
        }
    );
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].target, "/v1/services/app/deploys");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer secret-token")
    );
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(seen[0].body, b"{\"a\":1}");
}

#[test]
fn a_post_without_a_body_sends_an_empty_one() {
    let server = Server::start(|_, _| (202, b"{}".to_vec()));
    let answer = UreqHttp::default()
        .send(&request(Method::Post, server.url("/p"), None))
        .unwrap();
    assert_eq!(answer.status, 202);
    assert_eq!(server.seen()[0].body, b"");
}

#[test]
fn get_sends_the_bearer_and_no_body() {
    let server = Server::start(|_, target| (200, target.as_bytes().to_vec()));
    let answer = UreqHttp::new()
        .send(&request(
            Method::Get,
            server.url("/v1/deploys/d-x?audience=a"),
            None,
        ))
        .unwrap();
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body, b"/v1/deploys/d-x?audience=a");
    let seen = server.seen();
    assert_eq!(seen[0].method, "GET");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer secret-token")
    );
    assert!(seen[0].body.is_empty());
}

#[test]
fn a_redirect_is_an_answer_not_followed() {
    let server = Server::start(|_, _| (302, Vec::new()));
    let answer = UreqHttp::new()
        .send(&request(Method::Get, server.url("/x"), None))
        .unwrap();
    assert_eq!(answer.status, 302);
    assert_eq!(server.seen().len(), 1);
}

#[test]
fn an_answer_over_the_limit_is_a_transport_error() {
    let size = usize::try_from(MAX_ANSWER_BYTES).unwrap() + 1;
    let server = Server::start(move |_, _| (200, vec![b'x'; size]));
    let url = server.url("/big");
    let error = UreqHttp::new()
        .send(&request(Method::Get, url.clone(), None))
        .unwrap_err();
    assert_eq!(error.url, url);
    assert!(
        error.message.starts_with("reading the answer: "),
        "{}",
        error.message
    );

    // Exactly the limit is read.
    let size = usize::try_from(MAX_ANSWER_BYTES).unwrap();
    let server = Server::start(move |_, _| (200, vec![b'x'; size]));
    let answer = UreqHttp::new()
        .send(&request(Method::Get, server.url("/limit"), None))
        .unwrap();
    assert_eq!(answer.body.len(), size);
}

#[test]
fn a_refused_connection_is_a_transport_error() {
    // A port that was free a moment ago and has no listener now.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}/v1/services/app/deploys");
    for method in [Method::Get, Method::Post] {
        let error = UreqHttp::new()
            .send(&request(method, url.clone(), Some(b"{}")))
            .unwrap_err();
        assert_eq!(error.url, url);
        assert!(!error.message.is_empty());
    }
}
