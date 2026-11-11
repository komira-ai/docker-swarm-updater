//! `cargo xtask release check-output`: it passes only when the program exits 0 and prints
//! exactly the expected line. The program the tests run is the xtask binary itself, printing a
//! release version, so no system utility is involved.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use std::path::Path;
use std::process::{Command, Output};

const XTASK: &str = env!("CARGO_BIN_EXE_xtask");

fn xtask(args: &[&str]) -> Output {
    Command::new(XTASK).args(args).output().unwrap()
}

/// A workspace whose version is 0.1.0, so `release version --commit-count 3` prints
/// `version=0.1.3`.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace.package]\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    dir
}

fn check(expect: &str, program_args: &[&str]) -> Output {
    let mut args = vec!["release", "check-output", "--expect", expect, "--", XTASK];
    args.extend_from_slice(program_args);
    xtask(&args)
}

fn version_args(root: &Path) -> Vec<String> {
    ["release", "version", "--commit-count", "3", "--root"]
        .iter()
        .map(|s| (*s).to_owned())
        .chain([root.to_string_lossy().into_owned()])
        .collect()
}

#[test]
fn the_exact_line_passes() {
    let dir = workspace();
    let args = version_args(dir.path());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = check("version=0.1.3", &args);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("check-output: {XTASK} printed \"version=0.1.3\"\n")
    );
}

#[test]
fn another_line_or_a_prefix_fails_with_exit_1() {
    let dir = workspace();
    let args = version_args(dir.path());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    for expect in [
        "docker-swarm-updater 0.1.3",
        "version=0.1",
        "version=0.1.30",
    ] {
        let out = check(expect, &args);
        assert_eq!(out.status.code(), Some(1), "{expect}");
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!(
                "check-output: {XTASK} exited with exit status: 0 and printed \"version=0.1.3\\n\", not {:?}\n",
                format!("{expect}\n")
            )
        );
    }
}

#[test]
fn a_program_that_fails_fails_the_check_even_with_the_line() {
    // `release version` with an unknown flag prints nothing on stdout and exits 2.
    let out = check("", &["release", "version", "--bogus", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("check-output: {XTASK} exited with exit status: 2 and printed \"\", not \"\\n\"\n")
    );
}

#[test]
fn a_bad_command_line_or_a_missing_program_exits_2() {
    let missing = tempfile::tempdir().unwrap();
    let missing = missing
        .path()
        .join("missing")
        .to_string_lossy()
        .into_owned();
    let cases: [(&[&str], &str); 4] = [
        (
            &["release", "check-output", "--expect", "x"],
            "xtask: check-output needs `-- <program>`; usage: xtask release",
        ),
        (
            &["release", "check-output", "--expect", "x", "--"],
            "xtask: check-output needs a program after `--`; usage: xtask release",
        ),
        (
            &["release", "check-output", "--", "x"],
            "xtask: --expect is required",
        ),
        (
            &["release", "check-output", "--expect", "x", "--", &missing],
            "xtask: running ",
        ),
    ];
    for (args, message) in cases {
        let out = xtask(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            String::from_utf8(out.stderr).unwrap().starts_with(message),
            "{args:?}"
        );
    }
}
