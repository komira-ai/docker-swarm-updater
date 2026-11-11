//! The command line: which flags and environment are accepted, the plan they make, and the exit
//! codes and annotations of a run.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

mod support;

use std::ffi::OsString;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser as _;
use dsu_deploy::client::Clock as _;
use dsu_deploy::{Cli, EndpointError, SystemClock, parse_endpoint, run};
use support::{DIGEST, FakeClock, FakeHttp, ID, TOKEN_URL, answer, error_body, record};

fn args(extra: &[(&str, &str)]) -> Vec<OsString> {
    let mut flags = vec![
        ("--endpoint", "http://deploy.example:8450"),
        ("--service", "app"),
        ("--image-digest", DIGEST),
        (
            "--image-url",
            "https://github.com/o/app/releases/download/v1/app-1-linux-x86_64.image.tar",
        ),
        (
            "--bundle-url",
            "https://github.com/o/app/releases/download/v1/app-1-linux-x86_64.image.tar.sigstore.json",
        ),
        ("--signer-repository", "o/app"),
        ("--signer-workflow", ".github/workflows/artifacts.yml"),
        ("--signer-ref", "refs/heads/main"),
        ("--version", "1"),
        ("--audience", "aud"),
        ("--id-token-url", TOKEN_URL),
    ];
    for (flag, value) in extra {
        flags.retain(|(f, _)| f != flag);
        if !value.is_empty() || *flag == "--version" {
            flags.push((flag, value));
        }
    }
    let mut out = vec![OsString::from("dsu-deploy")];
    for (flag, value) in flags {
        out.push(flag.into());
        out.push(value.into());
    }
    out
}

fn go(args: Vec<OsString>, bearer: Option<&str>, http: &FakeHttp) -> (ExitCode, String) {
    let mut out = Vec::new();
    let code = run(
        args,
        bearer.map(str::to_owned),
        http,
        &FakeClock::default(),
        &mut out,
    );
    (code, String::from_utf8(out).unwrap())
}

#[test]
fn a_converged_deploy_exits_0_and_a_failed_one_exits_1_with_an_annotation() {
    let http = FakeHttp::new(vec![answer(200, record(ID, "converged", "done", None))]);
    let (code, out) = go(args(&[]), Some("bearer"), &http);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(out.ends_with(&format!("deploy {ID} converged\n")), "{out}");
    assert_eq!(http.token_requests()[0].1, "bearer");

    let http = FakeHttp::new(vec![answer(
        403,
        error_body("not_allowed", "no caller entry matches"),
    )]);
    let (code, out) = go(args(&[]), Some("bearer"), &http);
    assert_eq!(code, ExitCode::FAILURE);
    assert!(
        out.ends_with("::error::deploy refused: 403 not_allowed: no caller entry matches\n"),
        "{out}"
    );
}

#[test]
fn a_missing_or_empty_token_request_bearer_exits_2_before_anything_is_sent() {
    for bearer in [None, Some("")] {
        let http = FakeHttp::new(vec![]);
        let (code, out) = go(args(&[]), bearer, &http);
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(
            out,
            "::error::ACTIONS_ID_TOKEN_REQUEST_TOKEN is not set: the job needs `permissions: id-token: write`\n"
        );
        assert!(http.sent.borrow().is_empty());
    }
}

#[test]
fn a_version_the_updater_would_refuse_exits_2() {
    let long = "v".repeat(129);
    let cases = [
        (
            long.as_str(),
            "::error::--version: version is longer than 128 bytes\n",
        ),
        (
            "1.0\n",
            "::error::--version: version contains a control character\n",
        ),
    ];
    for (version, expected) in cases {
        let http = FakeHttp::new(vec![]);
        let (code, out) = go(args(&[("--version", version)]), Some("b"), &http);
        assert_eq!(code, ExitCode::from(2));
        assert_eq!(out, expected);
        assert!(http.sent.borrow().is_empty());
    }
    // 128 bytes is accepted.
    let http = FakeHttp::new(vec![answer(200, record(ID, "converged", "done", None))]);
    let (code, _) = go(args(&[("--version", &"v".repeat(128))]), Some("b"), &http);
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn wrong_flags_exit_2_and_help_exits_0() {
    let bad = [
        ("--service", "App"),
        ("--image-digest", "sha256:abc"),
        ("--endpoint", "ftp://deploy.example"),
        ("--id-token-url", "not a url"),
        ("--wait-minutes", "x"),
        ("--audience", ""),
        ("--signer-ref", ""),
    ];
    for (flag, value) in bad {
        let mut a = args(&[(flag, "")]);
        a.push(flag.into());
        a.push(value.into());
        let http = FakeHttp::new(vec![]);
        let (code, out) = go(a, Some("b"), &http);
        assert_eq!(code, ExitCode::from(2), "{flag} {value}: {out}");
        assert!(out.contains(flag), "{flag}: {out}");
    }
    let http = FakeHttp::new(vec![]);
    let (code, out) = go(vec!["dsu-deploy".into(), "--help".into()], None, &http);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(out.contains("--wait-minutes"));
}

#[test]
fn the_endpoint_is_a_scheme_host_and_port_only() {
    assert_eq!(
        parse_endpoint("http://deploy.example:8450/").unwrap(),
        "http://deploy.example:8450"
    );
    assert_eq!(
        parse_endpoint("https://deploy.example").unwrap(),
        "https://deploy.example"
    );
    for text in [
        "http://deploy.example/v1",
        "http://user@deploy.example",
        "http://user:pw@deploy.example",
        "http://:pw@deploy.example",
        "http://deploy.example/?q=1",
        "http://deploy.example/#f",
    ] {
        let error = parse_endpoint(text).unwrap_err();
        assert_eq!(
            error,
            EndpointError::NotBare {
                text: text.to_owned()
            }
        );
        assert_eq!(
            error.to_string(),
            format!(
                "{text:?}: give the scheme, host and port only (no user, path, query or fragment)"
            )
        );
    }
    assert_eq!(
        parse_endpoint("ftp://deploy.example")
            .unwrap_err()
            .to_string(),
        "\"ftp://deploy.example\": the scheme must be http or https"
    );
    // A host with a port and no scheme parses as the scheme `deploy.example`.
    assert_eq!(
        parse_endpoint("deploy.example:8450").unwrap_err(),
        EndpointError::Scheme {
            text: "deploy.example:8450".to_owned()
        }
    );
    assert_eq!(
        parse_endpoint("http://").unwrap_err(),
        EndpointError::NotAUrl {
            text: "http://".to_owned(),
            reason: "empty host".to_owned()
        }
    );
}

#[test]
fn the_plan_carries_the_flags_and_the_wait() {
    let plan = Cli::try_parse_from(args(&[("--wait-minutes", "5")]))
        .unwrap()
        .plan("b".to_owned())
        .unwrap();
    assert_eq!(plan.wait, Some(Duration::from_secs(300)));
    assert_eq!(plan.endpoint, "http://deploy.example:8450");
    assert_eq!(plan.service.as_str(), "app");
    assert_eq!(plan.tokens.audience, "aud");
    assert_eq!(plan.tokens.bearer, "b");
    assert_eq!(plan.tokens.url.as_str(), TOKEN_URL);
    let signer = plan.request.signer.unwrap();
    assert_eq!(
        (
            signer.repository.as_str(),
            signer.workflow.as_str(),
            signer.git_ref.as_str()
        ),
        (
            "o/app",
            ".github/workflows/artifacts.yml",
            "refs/heads/main"
        )
    );
    assert!(!plan.request.allow_older);

    let plan = Cli::try_parse_from(args(&[("--wait-minutes", "0")]))
        .unwrap()
        .plan("b".to_owned())
        .unwrap();
    assert_eq!(plan.wait, None);
    // The default is 60 minutes.
    let plan = Cli::try_parse_from(args(&[]))
        .unwrap()
        .plan("b".to_owned())
        .unwrap();
    assert_eq!(plan.wait, Some(Duration::from_secs(3600)));
}

#[test]
fn the_system_clock_counts_from_its_start_and_sleeps() {
    let clock = SystemClock::start();
    let before = clock.elapsed();
    clock.sleep(Duration::ZERO);
    assert!(clock.elapsed() >= before);
}
