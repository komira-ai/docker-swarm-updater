//! The built binary: it forwards its arguments to the library and returns its exit code.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_docker-swarm-updater"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_lists_the_verbs_and_exits_0() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    for verb in ["serve", "import", "probe"] {
        assert!(text.contains(verb), "{text}");
    }
}

#[test]
fn probe_of_a_socket_nobody_listens_on_exits_1_with_the_reason_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("none.sock");
    let output = run(&["probe", "--unix", socket.to_str().unwrap(), "/v1/health"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unhealthy")
    );
}

#[test]
fn a_refused_target_and_a_usage_error_exit_2_with_a_message() {
    let output = run(&["probe", "http://example.com/health"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("loopback")
    );
    let output = run(&["serve", "--no-such-flag"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stderr.is_empty());
}

#[test]
fn no_setting_is_read_from_the_environment() {
    let output = Command::new(env!("CARGO_BIN_EXE_docker-swarm-updater"))
        .arg("serve")
        .env("DSU_PROXY_UID", "1")
        .env("PROXY_UID", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--config")
    );
}
