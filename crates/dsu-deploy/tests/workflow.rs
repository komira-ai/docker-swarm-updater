//! `.github/workflows/deploy.yml` driven as a caller drives it. A small runner reads the
//! workflow file itself: it resolves the caller's `with:` against the declared inputs and their
//! defaults, evaluates each step's `${{ }}` expressions and `if:`, records what the checkout and
//! Tailscale steps would do, and runs the Deploy step's own command line (its quoted flags,
//! from its own `env:`) with the client this commit builds, against an updater fake on
//! 127.0.0.1 port 0. A step, expression or command the runner does not know fails the test, so
//! a change to the workflow cannot pass unexamined.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests: a failed unwrap or a panic is a failed test"
)]

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde_json::{Value as Json, json};
use support::{DIGEST, ID, Server, record};
use yaml_rust2::{Yaml as Value, YamlLoader};

const WORKFLOW_REPOSITORY: &str = "komira-ai/docker-swarm-updater";
const WORKFLOW_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const CALLER: &str = "example-org/app";
const IMAGE_URL: &str =
    "https://github.com/example-org/app/releases/download/v1.4.2/app-1.4.2-linux-x86_64.image.tar";
const BUNDLE_URL: &str = "https://github.com/example-org/app/releases/download/v1.4.2/app-1.4.2-linux-x86_64.image.tar.sigstore.json";

fn workflow() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/deploy.yml");
    yaml(&std::fs::read_to_string(path).unwrap())
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

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Integer(n) => n.to_string(),
        Value::Real(r) => r.clone(),
        Value::Boolean(b) => b.to_string(),
        other => panic!("not a scalar: {other:?}"),
    }
}

/// The contexts a job of the called workflow sees.
struct Contexts {
    inputs: BTreeMap<String, String>,
    github_repository: String,
    job_workflow_repository: String,
    job_workflow_sha: String,
}

impl Contexts {
    /// The caller's `with:` resolved as GitHub resolves it: every given input must be
    /// declared, every required one given, the others take their default.
    fn resolve(workflow: &Value, with: &[(&str, &str)]) -> Contexts {
        let declared = workflow["on"]["workflow_call"]["inputs"].as_hash().unwrap();
        for (name, _) in with {
            assert!(
                declared.contains_key(&Value::String((*name).to_owned())),
                "the caller gives an undeclared input {name}"
            );
        }
        let mut inputs = BTreeMap::new();
        for (name, spec) in declared {
            let name = text(name);
            let given = with.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
            let value = match (given, get(spec, "default")) {
                (Some(v), _) => v.to_owned(),
                (None, Some(default)) => text(default),
                (None, None) => {
                    assert_ne!(
                        get(spec, "required"),
                        Some(&Value::Boolean(true)),
                        "required input {name} not given"
                    );
                    String::new()
                }
            };
            inputs.insert(name, value);
        }
        Contexts {
            inputs,
            github_repository: CALLER.to_owned(),
            job_workflow_repository: WORKFLOW_REPOSITORY.to_owned(),
            job_workflow_sha: WORKFLOW_SHA.to_owned(),
        }
    }

    /// One context reference: `inputs.<name>`, `github.repository`, `job.workflow_*`.
    fn get(&self, reference: &str) -> String {
        if let Some(name) = reference.strip_prefix("inputs.") {
            return self
                .inputs
                .get(name)
                .unwrap_or_else(|| panic!("undeclared input {name}"))
                .clone();
        }
        match reference {
            "github.repository" => self.github_repository.clone(),
            "job.workflow_repository" => self.job_workflow_repository.clone(),
            "job.workflow_sha" => self.job_workflow_sha.clone(),
            other => panic!("the runner does not know the context {other}"),
        }
    }

    /// The value of `<ref> || <ref> ...`: the first non-empty one, as GitHub's `||` does.
    fn value(&self, expression: &str) -> String {
        expression
            .split(" || ")
            .map(|r| self.get(r.trim()))
            .find(|v| !v.is_empty())
            .unwrap_or_default()
    }

    /// A field: literal text, or exactly one `${{ <refs> }}`.
    fn field(&self, raw: &str) -> String {
        match raw.strip_prefix("${{ ").and_then(|r| r.strip_suffix(" }}")) {
            Some(expression) => self.value(expression),
            None => {
                assert!(!raw.contains("${{"), "the runner does not know {raw}");
                raw.to_owned()
            }
        }
    }

    /// An `if:` of terms `<ref> == ''` or `<ref> != ''`, joined by `&&` into groups and the
    /// groups by `||` (GitHub's `&&` binds tighter than `||`; no parentheses).
    fn condition(&self, raw: &str) -> bool {
        let inner = raw
            .strip_prefix("${{ ")
            .and_then(|r| r.strip_suffix(" }}"))
            .unwrap_or_else(|| panic!("the runner does not know the condition {raw}"));
        assert!(
            !inner.contains(['(', ')']),
            "the runner does not know the condition {raw}"
        );
        inner.split(" || ").any(|group| {
            group.split(" && ").all(|term| {
                if let Some(r) = term.strip_suffix(" == ''") {
                    self.get(r).is_empty()
                } else if let Some(r) = term.strip_suffix(" != ''") {
                    !self.get(r).is_empty()
                } else {
                    panic!("the runner does not know the term {term}")
                }
            })
        })
    }
}

/// What a run of the job did.
#[derive(Debug)]
struct Run {
    /// `with:` of each action step that ran, by action (the part of `uses:` before `@`).
    actions: BTreeMap<String, BTreeMap<String, String>>,
    /// The commands run, in order (the client as `dsu-deploy`).
    commands: Vec<String>,
    /// The job's result: `Ok` when every step passed, else the failing step's name.
    result: Result<(), String>,
    /// The client's standard output.
    client_output: String,
}

/// Runs the `deploy` job of `workflow` with `contexts`. The runner's own environment holds
/// GitHub's token endpoint, `token_url`, and its bearer.
fn run_job(workflow: &Value, contexts: &Contexts, token_url: &str) -> Run {
    let job = &workflow["jobs"]["deploy"];
    let mut run = Run {
        actions: BTreeMap::new(),
        commands: Vec::new(),
        result: Ok(()),
        client_output: String::new(),
    };
    let mut checkout: Option<String> = None;
    for step in job["steps"].as_vec().unwrap() {
        let name = text(&step["name"]);
        if let Some(condition) = get(step, "if")
            && !contexts.condition(&text(condition))
        {
            continue;
        }
        if let Some(uses) = get(step, "uses") {
            let uses = text(uses);
            let (action, pin) = uses.split_once('@').unwrap();
            assert_eq!(pin.len(), 40, "{action} is not pinned by commit");
            let with: BTreeMap<String, String> = step["with"]
                .as_hash()
                .unwrap()
                .iter()
                .map(|(k, v)| (text(k), contexts.field(&text(v))))
                .collect();
            if action == "actions/checkout" {
                checkout = Some(with["path"].clone());
            }
            run.actions.insert(action.to_owned(), with);
            continue;
        }
        let command = text(&step["run"]);
        if command == "exit 1" {
            run.result = Err(name);
            return run;
        }
        // Every command after the checkout runs in this workflow's own checkout.
        let directory = get(step, "working-directory").map(text);
        assert_eq!(directory, checkout, "{name} does not run in the checkout");
        match command.as_str() {
            // The toolchain of rust-toolchain.toml and the client built from the checkout:
            // here, the client cargo built for this test from this commit.
            "rustup toolchain install" | "cargo build --locked -p dsu-deploy" => {
                run.commands.push(command);
            }
            _ => {
                let output = deploy_step(step, &command, contexts, token_url);
                run.commands.push("dsu-deploy".to_owned());
                run.client_output = String::from_utf8(output.stdout).unwrap();
                if !output.status.success() {
                    run.result = Err(name);
                    return run;
                }
            }
        }
    }
    run
}

/// Runs the Deploy step: its command line, word by word, each word a literal or exactly one
/// quoted `"$NAME"` taken from the step's `env:` or the runner's environment.
fn deploy_step(
    step: &Value,
    command: &str,
    contexts: &Contexts,
    token_url: &str,
) -> std::process::Output {
    let env: BTreeMap<String, String> = step["env"]
        .as_hash()
        .unwrap()
        .iter()
        .map(|(k, v)| (text(k), contexts.field(&text(v))))
        .collect();
    let mut words = command.split_whitespace();
    assert_eq!(
        words.next(),
        Some("target/debug/dsu-deploy"),
        "the step does not run the client `cargo build -p dsu-deploy` makes"
    );
    let args: Vec<String> = words
        .map(
            |word| match word.strip_prefix("\"$").and_then(|w| w.strip_suffix('"')) {
                Some("ACTIONS_ID_TOKEN_REQUEST_URL") => token_url.to_owned(),
                Some(name) => env
                    .get(name)
                    .unwrap_or_else(|| panic!("${name} is not in the step's env"))
                    .clone(),
                None => {
                    assert!(!word.contains('$'), "{word} is not one quoted variable");
                    word.to_owned()
                }
            },
        )
        .collect();
    Command::new(env!("CARGO_BIN_EXE_dsu-deploy"))
        .args(&args)
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-bearer")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .output()
        .unwrap()
}

/// The updater fake: tokens at `/token`, and Deploy answering `state`.
fn updater(state: &'static str, error: Option<(&'static str, &'static str)>) -> Server {
    Server::start(move |method, target| match (method, target) {
        ("GET", t) if t.starts_with("/token?") => (200, b"{\"value\":\"oidc-token\"}".to_vec()),
        ("POST", "/v1/services/app/deploys") => (200, record(ID, state, "done", error)),
        _ => (
            404,
            b"{\"error\":\"not_found\",\"detail\":\"no route\"}".to_vec(),
        ),
    })
}

fn with<'a>(endpoint: &'a str, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut with = vec![
        ("service", "app"),
        ("version", "1.4.2"),
        ("image-digest", DIGEST),
        ("image-url", IMAGE_URL),
        ("bundle-url", BUNDLE_URL),
        ("endpoint", endpoint),
        ("audience", "deploy-audience"),
        ("environment", "production"),
    ];
    with.extend_from_slice(extra);
    with
}

#[test]
fn a_caller_with_the_required_inputs_deploys_with_the_defaults_and_passes() {
    let workflow = workflow();
    let server = updater("converged", None);
    let endpoint = server.url("");
    let contexts = Contexts::resolve(&workflow, &with(&endpoint, &[]));
    let run = run_job(&workflow, &contexts, &server.url("/token?api-version=2.0"));
    assert_eq!(run.result, Ok(()), "{}", run.client_output);

    // No tailnet join without a client id; the checkout is this workflow's own commit.
    assert!(!run.actions.contains_key("tailscale/github-action"));
    let checkout = &run.actions["actions/checkout"];
    assert_eq!(checkout["repository"], WORKFLOW_REPOSITORY);
    assert_eq!(checkout["ref"], WORKFLOW_SHA);
    assert_eq!(checkout["persist-credentials"], "false");
    assert_eq!(
        run.commands,
        [
            "rustup toolchain install",
            "cargo build --locked -p dsu-deploy",
            "dsu-deploy"
        ]
    );

    // The request the client sent: the caller's inputs, the signer defaults (the caller's
    // repository, artifacts.yml on main), never allow_older.
    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[0].target,
        "/token?api-version=2.0&audience=deploy-audience"
    );
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer runner-bearer")
    );
    assert_eq!(seen[1].target, "/v1/services/app/deploys");
    assert_eq!(seen[1].authorization.as_deref(), Some("Bearer oidc-token"));
    let body: Json = serde_json::from_slice(&seen[1].body).unwrap();
    assert_eq!(
        body,
        json!({
            "image_digest": DIGEST,
            "image_url": IMAGE_URL,
            "bundle_url": BUNDLE_URL,
            "signer": {"repository": CALLER, "workflow": ".github/workflows/artifacts.yml", "ref": "refs/heads/main"},
            "version": "1.4.2",
            "allow_older": false,
        })
    );
    assert_eq!(
        run.client_output,
        format!(
            "deploy app {DIGEST} (version 1.4.2) at {endpoint}\n\
             deploy {ID}: converged, phase done\n\
             deploy {ID} converged\n"
        )
    );
}

#[test]
fn a_deploy_that_does_not_converge_fails_the_callers_job() {
    let workflow = workflow();
    let server = updater(
        "rolled_back",
        Some(("swarm_rolled_back", "the new task failed its health check")),
    );
    let endpoint = server.url("");
    let contexts = Contexts::resolve(&workflow, &with(&endpoint, &[]));
    let run = run_job(&workflow, &contexts, &server.url("/token"));
    assert_eq!(run.result, Err("Deploy".to_owned()));
    assert!(
        run.client_output.ends_with(&format!(
            "::error::deploy {ID} ended rolled_back: swarm_rolled_back: the new task failed its health check\n"
        )),
        "{}",
        run.client_output
    );
}

#[test]
fn the_callers_signer_wait_and_tailnet_inputs_reach_their_steps() {
    let workflow = workflow();
    let server = updater("converged", None);
    let endpoint = server.url("");
    let extra = [
        ("signer-repository", "example-org/builds"),
        ("signer-workflow", ".github/workflows/sign.yml"),
        ("signer-ref", "refs/heads/release"),
        ("wait-minutes", "0"),
        ("tailscale-oauth-client-id", "client-id"),
        ("tailscale-audience", "ts-audience"),
        ("tailscale-tags", "tag:deploy"),
    ];
    let contexts = Contexts::resolve(&workflow, &with(&endpoint, &extra));
    let run = run_job(&workflow, &contexts, &server.url("/token"));
    assert_eq!(run.result, Ok(()), "{}", run.client_output);
    let tailscale = &run.actions["tailscale/github-action"];
    assert_eq!(tailscale["oauth-client-id"], "client-id");
    assert_eq!(tailscale["audience"], "ts-audience");
    assert_eq!(tailscale["tags"], "tag:deploy");
    // Tailscale itself is pinned by version and SHA-256 and never taken from a cache.
    assert_eq!(tailscale["version"], "1.104.2");
    assert_eq!(tailscale["sha256sum"].len(), 64);
    assert_eq!(tailscale["use-cache"], "false");
    let body: Json = serde_json::from_slice(&server.seen()[1].body).unwrap();
    assert_eq!(
        body["signer"],
        json!({"repository": "example-org/builds", "workflow": ".github/workflows/sign.yml", "ref": "refs/heads/release"})
    );
}

/// A client id with the audience or the tags empty: the job stops before the join in the step
/// named for the empty input, and sends nothing.
#[test]
fn a_tailnet_join_missing_its_audience_or_tags_stops_naming_the_input() {
    let workflow = workflow();
    let server = updater("converged", None);
    let endpoint = server.url("");
    let audience =
        "Refuse a tailnet join with tailscale-oauth-client-id set and tailscale-audience empty";
    let tags = "Refuse a tailnet join with tailscale-oauth-client-id set and tailscale-tags empty";
    let cases = [
        // The variable for the tags unset: what the caller in artifacts.yml would send.
        (
            vec![
                ("tailscale-oauth-client-id", "client-id"),
                ("tailscale-audience", "ts-audience"),
                ("tailscale-tags", ""),
            ],
            tags,
        ),
        // The input left out: its default is empty.
        (
            vec![
                ("tailscale-oauth-client-id", "client-id"),
                ("tailscale-audience", "ts-audience"),
            ],
            tags,
        ),
        (
            vec![
                ("tailscale-oauth-client-id", "client-id"),
                ("tailscale-tags", "tag:deploy"),
            ],
            audience,
        ),
        // Both empty: the audience is named first.
        (vec![("tailscale-oauth-client-id", "client-id")], audience),
    ];
    for (extra, step) in cases {
        let contexts = Contexts::resolve(&workflow, &with(&endpoint, &extra));
        let run = run_job(&workflow, &contexts, &server.url("/token"));
        assert_eq!(run.result, Err(step.to_owned()), "{extra:?}");
        assert!(
            run.actions.is_empty() && run.commands.is_empty(),
            "{extra:?}"
        );
    }
    assert!(server.seen().is_empty());
}

/// Without a client id there is no join, whatever the other two hold: the job deploys
/// without one, as it does with none of the three.
#[test]
fn audience_and_tags_without_a_client_id_join_nothing_and_deploy() {
    let workflow = workflow();
    let server = updater("converged", None);
    let endpoint = server.url("");
    let extra = [
        ("tailscale-audience", "ts-audience"),
        ("tailscale-tags", "tag:deploy"),
    ];
    let contexts = Contexts::resolve(&workflow, &with(&endpoint, &extra));
    let run = run_job(&workflow, &contexts, &server.url("/token"));
    assert_eq!(run.result, Ok(()), "{}", run.client_output);
    assert!(!run.actions.contains_key("tailscale/github-action"));
    assert_eq!(run.commands.last().map(String::as_str), Some("dsu-deploy"));
}

#[test]
fn a_runner_that_cannot_name_the_workflows_commit_stops_before_any_checkout() {
    let workflow = workflow();
    let server = updater("converged", None);
    let endpoint = server.url("");
    for (repository, sha) in [("", WORKFLOW_SHA), (WORKFLOW_REPOSITORY, "")] {
        let mut contexts = Contexts::resolve(&workflow, &with(&endpoint, &[]));
        contexts.job_workflow_repository = repository.to_owned();
        contexts.job_workflow_sha = sha.to_owned();
        let run = run_job(&workflow, &contexts, &server.url("/token"));
        assert_eq!(
            run.result,
            Err(
                "Refuse a runner that does not set job.workflow_repository and job.workflow_sha"
                    .to_owned()
            )
        );
        assert!(run.actions.is_empty() && run.commands.is_empty());
    }
    assert!(server.seen().is_empty());
}

#[test]
fn the_workflow_is_called_only_and_its_job_holds_only_id_token_in_the_callers_environment() {
    let workflow = workflow();
    let on = workflow["on"].as_hash().unwrap();
    assert_eq!(on.len(), 1);
    assert!(on.contains_key(&Value::String("workflow_call".to_owned())));
    assert_eq!(workflow["permissions"], Value::Hash(Default::default()));
    let jobs = workflow["jobs"].as_hash().unwrap();
    assert_eq!(jobs.len(), 1);
    let job = &workflow["jobs"]["deploy"];
    assert_eq!(job["permissions"], yaml("id-token: write"));
    assert_eq!(text(&job["environment"]), "${{ inputs.environment }}");
    // The inputs a caller must give.
    let required: Vec<String> = workflow["on"]["workflow_call"]["inputs"]
        .as_hash()
        .unwrap()
        .iter()
        .filter(|(_, spec)| get(spec, "required") == Some(&Value::Boolean(true)))
        .map(|(name, _)| text(name))
        .collect();
    assert_eq!(
        required,
        [
            "service",
            "version",
            "image-digest",
            "image-url",
            "bundle-url",
            "endpoint",
            "audience",
            "environment"
        ]
    );
}
