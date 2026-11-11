//! The permission and trust boundaries of the workflows, read from the files themselves:
//!
//! - every workflow grants nothing at the top (`permissions: {}`) and pins every action and
//!   every called workflow by commit;
//! - `artifacts.yml` runs only on a push to `main`; each job holds exactly the permissions
//!   listed in [`ARTIFACTS_JOBS`]; only `attest` can sign (`id-token: write`,
//!   `attestations: write`), it runs only for a push to `main`, checks out nothing and runs
//!   only `sha256sum` and `cp`, so no repository code runs while it can sign; only `publish` can
//!   write (`contents: write`), it checks out nothing and runs only `gh release create`; and
//!   `publish` runs only after `verify`, which runs only after `attest`;
//! - the release deploys itself only after `publish` and only while the repository variable
//!   `CP_DEPLOY_ENDPOINT` is set: `deploy-digest` and `deploy` run only for a push to `main`
//!   with that variable not empty ([`DEPLOY_IF`]); `deploy` holds only `id-token: write` and
//!   calls exactly [`DEPLOY_WORKFLOW`] with exactly [`DEPLOY_WITH`]; the one step of
//!   `deploy-digest` that holds the token runs only `gh release download`.
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
const ARTIFACTS_JOBS: [(&str, &str); 8] = [
    ("plan", "contents: read"),
    ("build", "contents: read"),
    ("sums", "contents: read"),
    (
        "attest",
        "{contents: read, id-token: write, attestations: write}",
    ),
    ("verify", "{contents: read, attestations: read}"),
    ("publish", "contents: write"),
    ("deploy-digest", "contents: read"),
    ("deploy", "id-token: write"),
];

/// The condition of `deploy-digest` and `deploy`: a push to main, and the deploy front set.
const DEPLOY_IF: &str = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && vars.CP_DEPLOY_ENDPOINT != '' }}";

/// The reusable workflow `deploy` calls, at the commit the updater's allow-list names for
/// `job_workflow_ref`.
const DEPLOY_WORKFLOW: &str = "komira-ai/docker-swarm-updater/.github/workflows/deploy.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6";

/// The inputs `deploy` sends, exactly: no signer input, so the signer is the default (this
/// repository, artifacts.yml, refs/heads/main).
const DEPLOY_WITH: &str = "
service: docker-swarm-updater
version: ${{ needs.plan.outputs.version }}
image-digest: ${{ needs.deploy-digest.outputs.digest }}
image-url: ${{ needs.deploy-digest.outputs.image-url }}
bundle-url: ${{ needs.deploy-digest.outputs.bundle-url }}
endpoint: ${{ vars.CP_DEPLOY_ENDPOINT }}
audience: ${{ vars.CP_DEPLOY_AUDIENCE }}
environment: controlplane
wait-minutes: 60
tailscale-oauth-client-id: ${{ vars.CP_DEPLOY_TAILSCALE_CLIENT_ID }}
tailscale-audience: ${{ vars.CP_DEPLOY_TAILSCALE_AUDIENCE }}
tailscale-tags: ${{ vars.CP_DEPLOY_TAILSCALE_TAGS }}
";

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

/// What every workflow must hold: nothing granted at the top, every action and every called
/// workflow pinned by commit.
fn common_violations(name: &str, workflow: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if get(workflow, "permissions") != Some(&Value::Hash(Hash::new())) {
        out.push(format!("{name}: top-level permissions are not {{}}"));
    }
    for (job_name, job) in workflow["jobs"].as_hash().into_iter().flatten() {
        let called = get(job, "uses").map(str_of);
        let actions = steps(job).iter().filter_map(|s| get(s, "uses").map(str_of));
        for uses in called.into_iter().chain(actions) {
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
        ("deploy-digest", "publish"),
        ("deploy-digest", "sums"),
        ("deploy", "deploy-digest"),
    ] {
        if !needs(job, other) {
            out.push(format!("artifacts.yml: {job} does not wait for {other}"));
        }
    }
    out.extend(deploy_violations(&artifacts["jobs"]));
    out
}

/// The boundaries of `deploy-digest` and `deploy`, the jobs of artifacts.yml `jobs`.
fn deploy_violations(jobs: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for name in ["deploy-digest", "deploy"] {
        if str_of(&jobs[name]["if"]) != DEPLOY_IF {
            out.push(format!(
                "artifacts.yml: {name} is not limited to a push to main with CP_DEPLOY_ENDPOINT set"
            ));
        }
    }
    let deploy = &jobs["deploy"];
    if str_of(&deploy["uses"]) != DEPLOY_WORKFLOW {
        out.push(format!(
            "artifacts.yml: deploy calls {:?}, not {DEPLOY_WORKFLOW}",
            str_of(&deploy["uses"])
        ));
    }
    if !get(deploy, "with").is_some_and(|w| same(w, &yaml(DEPLOY_WITH))) {
        out.push("artifacts.yml: deploy does not send exactly the deploy inputs".into());
    }
    for step in steps(&jobs["deploy-digest"]) {
        let run = str_of(&step["run"]);
        if get(&step["env"], "GH_TOKEN").is_some() && !run.starts_with("gh release download ") {
            out.push(format!(
                "artifacts.yml: deploy-digest runs {run:?} holding the token"
            ));
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

#[test]
fn each_broken_deploy_boundary_is_named() {
    let gate = "    if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' && vars.CP_DEPLOY_ENDPOINT != '' }}\n";
    let cases: Vec<(Value, &str)> = vec![
        // The deploy jobs run without the variable, in deploy-digest and in deploy.
        (
            broken(|t| {
                t.replacen(gate, "    if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}\n", 1)
            }),
            "artifacts.yml: deploy-digest is not limited to a push to main with CP_DEPLOY_ENDPOINT set",
        ),
        (
            broken(|t| {
                let at = t.rfind(gate).unwrap();
                format!("{}{}", &t[..at], &t[at + gate.len()..])
            }),
            "artifacts.yml: deploy is not limited to a push to main with CP_DEPLOY_ENDPOINT set",
        ),
        // deploy holds a scope beyond id-token: write.
        (
            broken(|t| {
                t.replacen(
                    "    permissions:\n      id-token: write\n    uses:",
                    "    permissions:\n      id-token: write\n      contents: write\n    uses:",
                    1,
                )
            }),
            "artifacts.yml: job deploy does not hold exactly id-token: write",
        ),
        // The called workflow at another commit, or another repository's.
        (
            broken(|t| {
                t.replacen(
                    "deploy.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6",
                    "deploy.yml@b1ad99f0b1ad99f0b1ad99f0b1ad99f0b1ad99f0",
                    1,
                )
            }),
            "artifacts.yml: deploy calls \"komira-ai/docker-swarm-updater/.github/workflows/deploy.yml@b1ad99f0b1ad99f0b1ad99f0b1ad99f0b1ad99f0\", not komira-ai/docker-swarm-updater/.github/workflows/deploy.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6",
        ),
        (
            broken(|t| {
                t.replacen(
                    "uses: komira-ai/docker-swarm-updater/.github",
                    "uses: someone-else/docker-swarm-updater/.github",
                    1,
                )
            }),
            "artifacts.yml: deploy calls \"someone-else/docker-swarm-updater/.github/workflows/deploy.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6\", not komira-ai/docker-swarm-updater/.github/workflows/deploy.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6",
        ),
        // Another service, a signer input that overrides the default, an input dropped.
        (
            broken(|t| {
                t.replacen(
                    "      service: docker-swarm-updater\n",
                    "      service: other-service\n",
                    1,
                )
            }),
            "artifacts.yml: deploy does not send exactly the deploy inputs",
        ),
        (
            broken(|t| {
                t.replacen(
                    "      environment: controlplane\n",
                    "      environment: controlplane\n      signer-ref: refs/heads/dev\n",
                    1,
                )
            }),
            "artifacts.yml: deploy does not send exactly the deploy inputs",
        ),
        (
            broken(|t| t.replacen("      wait-minutes: 60\n", "", 1)),
            "artifacts.yml: deploy does not send exactly the deploy inputs",
        ),
        // The order: the digest before the release is published, the deploy without it.
        (
            broken(|t| {
                t.replacen(
                    "    needs: [plan, sums, publish]\n",
                    "    needs: [plan, sums, verify]\n",
                    1,
                )
            }),
            "artifacts.yml: deploy-digest does not wait for publish",
        ),
        (
            broken(|t| {
                t.replacen(
                    "    needs: [plan, deploy-digest]\n",
                    "    needs: [plan, publish]\n",
                    1,
                )
            }),
            "artifacts.yml: deploy does not wait for deploy-digest",
        ),
        // Repository code run beside the token.
        (
            broken(|t| {
                t.replacen(
                    "        run: gh release download ",
                    "        run: cargo xtask release deploy-inputs && gh release download ",
                    1,
                )
            }),
            "artifacts.yml: deploy-digest runs \"cargo xtask release deploy-inputs && gh release download \\\"v$VERSION\\\" --repo \\\"$REPO\\\" --dir release --pattern SHA256SUMS --pattern \\\"docker-swarm-updater-$VERSION-linux-x86_64.image.tar\\\"\" holding the token",
        ),
    ];
    for (workflow, message) in cases {
        assert_eq!(violations(&workflow), [message.to_owned()]);
    }
}

/// A called workflow is held to a commit pin as an action is.
#[test]
fn a_called_workflow_without_a_commit_pin_is_named() {
    let workflow = yaml(
        "permissions: {}\njobs:\n  a:\n    uses: o/r/.github/workflows/w.yml@main\n  b:\n    uses: o/r/.github/workflows/w.yml@c1fcc47610e2886d4d9e561be3c0c76f0452d1f6\n  c:\n    uses: ./.github/workflows/w.yml\n",
    );
    assert_eq!(
        common_violations("w.yml", &workflow),
        [
            "w.yml: job a uses o/r/.github/workflows/w.yml@main without a commit pin",
            "w.yml: job c uses ./.github/workflows/w.yml without a commit pin",
        ]
    );
}
