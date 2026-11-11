//! The built binary end to end against an HTTP server on 127.0.0.1 port 0 standing in for
//! GitHub's token endpoint and the deploy front: it reads the token request's bearer from the
//! environment, and its exit code follows the deploy.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

mod support;

use std::process::Command;

use support::{DIGEST, ID, Server, error_body, record};

fn answer(method: &str, target: &str) -> (u16, Vec<u8>) {
    match (method, target) {
        ("GET", t) if t.starts_with("/token?") => (200, b"{\"value\":\"oidc-token\"}".to_vec()),
        ("POST", "/v1/services/app/deploys") => (200, record(ID, "converged", "done", None)),
        ("POST", "/v1/services/web/deploys") => (409, error_body("busy", "another deploy runs")),
        _ => (404, error_body("not_found", "no such path")),
    }
}

fn deploy(server: &Server, service: &str, bearer: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dsu-deploy"));
    command
        .args(["--endpoint", &server.url("")])
        .args(["--service", service])
        .args(["--image-digest", DIGEST])
        .args(["--image-url", "https://github.com/o/app/releases/download/v1/app-1-linux-x86_64.image.tar"])
        .args(["--bundle-url", "https://github.com/o/app/releases/download/v1/app-1-linux-x86_64.image.tar.sigstore.json"])
        .args(["--signer-repository", "o/app"])
        .args(["--signer-workflow", ".github/workflows/artifacts.yml"])
        .args(["--signer-ref", "refs/heads/main"])
        .args(["--version", "1"])
        .args(["--audience", "aud"])
        .args(["--id-token-url", &server.url("/token?api-version=2.0")])
        .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    if let Some(bearer) = bearer {
        command.env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", bearer);
    }
    command.output().unwrap()
}

#[test]
fn the_binary_deploys_with_the_bearer_from_the_environment() {
    let server = Server::start(answer);
    let output = deploy(&server, "app", Some("request-bearer"));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.ends_with(&format!("deploy {ID} converged\n")),
        "{stdout}"
    );
    let seen = server.seen();
    assert_eq!(seen[0].target, "/token?api-version=2.0&audience=aud");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer request-bearer")
    );
    assert_eq!(seen[1].authorization.as_deref(), Some("Bearer oidc-token"));
    // The bearer of the token request is never printed.
    assert!(!stdout.contains("request-bearer"));
}

#[test]
fn the_binary_exits_1_on_a_refusal_and_2_without_the_bearer() {
    let server = Server::start(answer);
    let output = deploy(&server, "web", Some("request-bearer"));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .ends_with("::error::deploy refused: 409 busy: another deploy runs\n")
    );

    let output = deploy(&server, "app", None);
    assert_eq!(output.status.code(), Some(2));
    assert!(server.seen().len() == 2, "nothing more was sent");
}
