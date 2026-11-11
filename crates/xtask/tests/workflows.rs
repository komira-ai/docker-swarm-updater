//! The permission and trust boundaries of the workflows, read from the files themselves:
//!
//! - every workflow grants nothing at the top (`permissions: {}`) and pins every action by
//!   commit;
//! - `artifacts.yml` runs only on a push to `main`; each job holds exactly the permissions
//!   listed in [`ARTIFACTS_JOBS`]; only `attest` can sign (`id-token: write`,
//!   `attestations: write`), it runs only for a push to `main`, checks out nothing and runs
//!   only `sha256sum` and `cp`, so no repository code runs while it can sign; only `publish` can
//!   write (`contents: write`), it checks out nothing and runs only `gh release create`; and
//!   `publish` runs only after `verify`, which runs only after `attest`.
//!
//! [`violations`] is the check; the tests run it on the real files and on copies with one
//! boundary broken, each of which it must name.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use std::path::{Path, PathBuf};

use yaml_rust2::yaml::Hash;
use yaml_rust2::{Yaml as Value, YamlLoader};

/// Each job of artifacts.yml and the permissions it holds, exactly.
const ARTIFACTS_JOBS: [(&str, &str); 6] = [
    ("plan", "contents: read"),
    ("build", "contents: read"),
    ("sums", "contents: read"),
    (
        "attest",
        "{contents: read, id-token: write, attestations: write}",
    ),
    ("verify", "{contents: read, attestations: read}"),
    ("publish", "contents: write"),
];

fn workflows_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows")
}

fn load(name: &str) -> Value {
    yaml(&std::fs::read_to_string(workflows_dir().join(name)).unwrap())
}

/// The one document of `text`.
fn yaml(text: &str) -> Value {
    let [document] = <[Value; 1]>::try_from(YamlLoader::load_from_str(text).unwrap()).unwrap();
    document
}

/// The entry `key` of a mapping, `None` when it has no such entry.
fn get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    Some(&value[key]).filter(|v| !v.is_badvalue())
}

/// Whether `a` and `b` are the same YAML value, the entries of a mapping in any order.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Hash(a), Value::Hash(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|other| same(v, other)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        _ => a == b,
    }
}

fn steps(job: &Value) -> &[Value] {
    job["steps"].as_vec().map_or(&[], Vec::as_slice)
}

fn str_of(value: &Value) -> &str {
    value.as_str().unwrap_or("")
}

/// What every workflow must hold: nothing granted at the top, every action pinned by commit.
fn common_violations(name: &str, workflow: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if get(workflow, "permissions") != Some(&Value::Hash(Hash::new())) {
        out.push(format!("{name}: top-level permissions are not {{}}"));
    }
    for (job_name, job) in workflow["jobs"].as_hash().into_iter().flatten() {
        for step in steps(job) {
            let Some(uses) = get(step, "uses").map(str_of) else {
                continue;
            };
            let pinned = uses.split_once('@').is_some_and(|(_, pin)| {
                pin.len() == 40 && pin.bytes().all(|b| b.is_ascii_hexdigit())
            });
            if !pinned {
                out.push(format!(
                    "{name}: job {} uses {uses} without a commit pin",
                    str_of(job_name)
                ));
            }
        }
    }
    out
}

/// The boundaries of artifacts.yml.
fn violations(artifacts: &Value) -> Vec<String> {
    let mut out = common_violations("artifacts.yml", artifacts);
    if !same(&artifacts["on"], &yaml("push: {branches: [main]}")) {
        out.push("artifacts.yml: it runs on more than a push to main".into());
    }
    let jobs = artifacts["jobs"].as_hash().cloned().unwrap_or_default();
    let names: Vec<&str> = jobs.keys().map(str_of).collect();
    let expected: Vec<&str> = ARTIFACTS_JOBS.iter().map(|(n, _)| *n).collect();
    if names != expected {
        out.push(format!(
            "artifacts.yml: jobs are {names:?}, not {expected:?}"
        ));
    }
    for (name, permissions) in ARTIFACTS_JOBS {
        let job = &artifacts["jobs"][name];
        if !get(job, "permissions").is_some_and(|p| same(p, &yaml(permissions))) {
            out.push(format!(
                "artifacts.yml: job {name} does not hold exactly {permissions}"
            ));
        }
    }
    let attest = &artifacts["jobs"]["attest"];
    if str_of(&attest["if"])
        != "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
    {
        out.push("artifacts.yml: attest is not limited to a push to main".into());
    }
    for (name, allowed) in [
        ("attest", &["/usr/bin/sha256sum ", "cp "][..]),
        ("publish", &["gh release create "][..]),
    ] {
        for step in steps(&artifacts["jobs"][name]) {
            if str_of(&step["uses"]).starts_with("actions/checkout@") {
                out.push(format!("artifacts.yml: {name} checks out the repository"));
            }
            if let Some(run) = get(step, "run").map(str_of)
                && !allowed.iter().any(|prefix| run.starts_with(prefix))
            {
                out.push(format!("artifacts.yml: {name} runs {run:?}"));
            }
        }
    }
    let needs = |job: &str, other: &str| {
        artifacts["jobs"][job]["needs"]
            .as_vec()
            .is_some_and(|n| n.iter().any(|v| str_of(v) == other))
    };
    for (job, other) in [
        ("publish", "verify"),
        ("verify", "attest"),
        ("attest", "sums"),
    ] {
        if !needs(job, other) {
            out.push(format!("artifacts.yml: {job} does not wait for {other}"));
        }
    }
    out
}

#[test]
fn every_workflow_grants_nothing_at_the_top_and_pins_every_action() {
    let mut names: Vec<String> = std::fs::read_dir(workflows_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["advisories.yml", "artifacts.yml", "ci.yml", "deploy.yml"]
    );
    for name in &names {
        assert_eq!(common_violations(name, &load(name)), Vec::<String>::new());
    }
}

#[test]
fn artifacts_holds_its_signing_and_publishing_boundaries() {
    assert_eq!(violations(&load("artifacts.yml")), Vec::<String>::new());
}

/// artifacts.yml with `edit` applied to its text.
fn broken(edit: impl Fn(&str) -> String) -> Value {
    let text = std::fs::read_to_string(workflows_dir().join("artifacts.yml")).unwrap();
    let changed = edit(&text);
    assert_ne!(changed, text, "the edit changed nothing");
    yaml(&changed)
}

#[test]
fn mappings_compare_in_any_key_order() {
    let cases = [
        ("{a: 1, b: 2}", "{b: 2, a: 1}", true),
        ("{a: {x: 1, y: 2}}", "{a: {y: 2, x: 1}}", true),
        ("{a: 1, b: 2}", "{a: 1}", false),
        ("{a: 1, b: 2}", "{a: 1, c: 2}", false),
        ("{a: 1, b: 2}", "{a: 1, b: 3}", false),
        ("[a, b]", "[b, a]", false),
        ("[a, b]", "[a]", false),
        ("[{a: 1, b: 2}]", "[{b: 2, a: 1}]", true),
        ("a", "a", true),
        ("a", "{a: 1}", false),
    ];
    for (a, b, expected) in cases {
        assert_eq!(same(&yaml(a), &yaml(b)), expected, "{a} vs {b}");
    }
}

/// A job's permissions written in another key order hold the same boundary.
#[test]
fn reordered_permissions_hold_the_boundary() {
    let reordered = broken(|t| {
        t.replacen(
            "      contents: read\n      id-token: write\n      attestations: write\n",
            "      attestations: write\n      contents: read\n      id-token: write\n",
            1,
        )
    });
    assert_eq!(violations(&reordered), Vec::<String>::new());
}

#[test]
fn each_broken_boundary_is_named() {
    let cases: Vec<(Value, &str)> = vec![
        (
            broken(|t| {
                t.replacen(
                    "  build:\n    name: build ${{ matrix.platform }}\n    needs: [plan]\n    runs-on: ${{ matrix.runner }}\n    timeout-minutes: 60\n    permissions:\n      contents: read\n",
                    "  build:\n    name: build ${{ matrix.platform }}\n    needs: [plan]\n    runs-on: ${{ matrix.runner }}\n    timeout-minutes: 60\n    permissions:\n      contents: read\n      id-token: write\n",
                    1,
                )
            }),
            "artifacts.yml: job build does not hold exactly contents: read",
        ),
        (
            broken(|t| {
                t.replacen(
                    "on:\n  push:\n    branches: [main]\n",
                    "on:\n  push:\n    branches: [main]\n  pull_request:\n",
                    1,
                )
            }),
            "artifacts.yml: it runs on more than a push to main",
        ),
        (
            broken(|t| t.replacen("permissions: {}\n", "permissions:\n  contents: read\n", 1)),
            "artifacts.yml: top-level permissions are not {}",
        ),
        (
            broken(|t| {
                t.replacen(
                    "      - name: Refuse files that differ from the sums\n",
                    "      - run: cargo xtask release sums --dir dist --version \"$V\"\n      - name: Refuse files that differ from the sums\n",
                    1,
                )
            }),
            "artifacts.yml: attest runs \"cargo xtask release sums --dir dist --version \\\"$V\\\"\"",
        ),
        (
            broken(|t| {
                t.replacen(
                    "    needs: [plan, verify]\n",
                    "    needs: [plan, attest]\n",
                    1,
                )
            }),
            "artifacts.yml: publish does not wait for verify",
        ),
        (
            broken(|t| {
                t.replacen("    if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}\n", "", 1)
            }),
            "artifacts.yml: attest is not limited to a push to main",
        ),
        (
            broken(|t| {
                t.replacen(
                    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
                    "actions/attest-build-provenance@v4",
                    1,
                )
            }),
            "artifacts.yml: job attest uses actions/attest-build-provenance@v4 without a commit pin",
        ),
    ];
    for (workflow, message) in cases {
        assert_eq!(violations(&workflow), [message.to_owned()]);
    }
}
