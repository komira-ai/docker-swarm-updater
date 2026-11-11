//! The xtask binary's exit codes: 0 when every crate meets its floors, 1 when one does not,
//! 2 when the command line or an input is wrong.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use std::path::Path;
use std::process::Command;

fn setup(dir: &Path, hits: u32) -> String {
    let krate = dir.join("crates/a");
    std::fs::create_dir_all(&krate).unwrap();
    std::fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname = \"a\"\n[package.metadata.coverage]\nlines = 99.0\nbranches = 99.0\n",
    )
    .unwrap();
    let lcov = dir.join("lcov.info");
    let src = dir.join("crates/a/src/lib.rs");
    std::fs::write(
        &lcov,
        format!("SF:{}\nDA:1,{hits}\nend_of_record\n", src.display()),
    )
    .unwrap();
    lcov.to_string_lossy().into_owned()
}

fn xtask(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn exit_code_follows_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_string_lossy().into_owned();

    let lcov = setup(dir.path(), 1);
    let ok = xtask(&["coverage", "--lcov", &lcov, "--root", &root]);
    assert_eq!(ok.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("| a | 100.00% (1/1)"));

    let lcov = setup(dir.path(), 0);
    let low = xtask(&["coverage", "--lcov", &lcov, "--root", &root]);
    assert_eq!(low.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&low.stdout).contains("BELOW FLOOR"));

    let bad = xtask(&["nonsense"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).starts_with("xtask: usage"));
}

#[test]
fn layers_passes_on_this_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = xtask(&["layers", "--root", &root.to_string_lossy()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "layers: ok\n");
}

#[test]
fn layers_fails_with_exit_1_on_a_defect_and_2_on_bad_input() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("crates/a")).unwrap();
    std::fs::write(
        dir.path().join("crates/a/Cargo.toml"),
        "[package]\nname = \"a\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("layers.toml"), "").unwrap();
    let root = dir.path().to_string_lossy().into_owned();
    let out = xtask(&["layers", "--root", &root]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "layers: crate a is in no layer\n"
    );
    assert_eq!(xtask(&["layers", "--bad"]).status.code(), Some(2));
}

#[test]
fn fetch_with_a_bad_command_line_or_an_unreachable_host_exits_2() {
    assert_eq!(xtask(&["fetch"]).status.code(), Some(2));
    let hex = "0".repeat(64);
    let out = xtask(&[
        "fetch",
        "--url",
        "https://127.0.0.1:1/x",
        "--sha256",
        &hex,
        "--out",
        "unused",
    ]);
    assert_eq!(out.status.code(), Some(2));
}
