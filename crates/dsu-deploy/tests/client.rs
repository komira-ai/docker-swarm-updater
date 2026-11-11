//! One deploy, start to end, against an in-memory updater and a virtual clock: what is sent,
//! what is retried, when the run passes, fails or gives up, and what it prints.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

mod support;

use std::time::Duration;

use dsu_core::api::{DeployRequest, RequestSigner};
use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_deploy::client::{DeployError, Plan, TokenSource, run};
use support::{
    DIGEST, ENDPOINT, FakeClock, FakeHttp, ID, OTHER_ID, TOKEN_URL, answer, error_body, record,
    unreachable_answer,
};

const DEPLOY_URL: &str = "http://deploy.example:8450/v1/services/app/deploys";
const STATUS_URL: &str = "http://deploy.example:8450/v1/deploys/d-abcdefghijklmnopqrstuvwxyz";

fn plan(wait_minutes: u64) -> Plan {
    Plan {
        endpoint: ENDPOINT.to_owned(),
        service: ServiceName::parse("app").unwrap(),
        request: DeployRequest {
            image_digest: Digest::parse(DIGEST).unwrap(),
            image_url: "https://github.com/example-org/app/releases/download/v1.2.3/app-1.2.3-linux-x86_64.image.tar".to_owned(),
            bundle_url: "https://github.com/example-org/app/releases/download/v1.2.3/app-1.2.3-linux-x86_64.image.tar.sigstore.json".to_owned(),
            signer: Some(RequestSigner {
                repository: "example-org/app".to_owned(),
                workflow: ".github/workflows/artifacts.yml".to_owned(),
                git_ref: "refs/heads/main".to_owned(),
            }),
            version: "1.2.3".to_owned(),
            allow_older: false,
        },
        tokens: TokenSource {
            url: url::Url::parse(TOKEN_URL).unwrap(),
            bearer: "request-bearer".to_owned(),
            audience: "deploy audience".to_owned(),
        },
        wait: (wait_minutes > 0).then(|| Duration::from_secs(wait_minutes * 60)),
    }
}

/// Runs `plan` against `http`; returns the result, the printed lines and the clock.
fn go(plan: &Plan, http: &FakeHttp) -> (Result<DeployId, DeployError>, Vec<String>, FakeClock) {
    let clock = FakeClock::default();
    let mut out = Vec::new();
    let result = run(plan, http, &clock, &mut out);
    let lines = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    (result, lines, clock)
}

fn id() -> DeployId {
    DeployId::parse(ID).unwrap()
}

#[test]
fn a_deploy_that_converges_passes_and_every_request_has_its_own_token() {
    let http = FakeHttp::new(vec![
        answer(202, record(ID, "running", "queued", None)),
        answer(200, record(ID, "running", "fetching", None)),
        answer(200, record(ID, "running", "fetching", None)),
        answer(200, record(ID, "running", "waiting", None)),
        answer(200, record(ID, "converged", "done", None)),
    ]);
    let (result, lines, clock) = go(&plan(60), &http);
    assert_eq!(result, Ok(id()));
    assert_eq!(
        lines,
        [
            format!("deploy app {DIGEST} (version 1.2.3) at {ENDPOINT}"),
            format!("deploy {ID}: running, phase queued"),
            format!("deploy {ID}: running, phase fetching"),
            format!("deploy {ID}: running, phase waiting"),
            format!("deploy {ID}: converged, phase done"),
            format!("deploy {ID} converged"),
        ]
    );
    let get = |n: u32| {
        (
            "Get".to_owned(),
            STATUS_URL.to_owned(),
            format!("token-{n}"),
        )
    };
    assert_eq!(
        http.calls(),
        [
            (
                "Post".to_owned(),
                DEPLOY_URL.to_owned(),
                "token-1".to_owned()
            ),
            get(2),
            get(3),
            get(4),
            get(5),
        ]
    );
    // Each token request asks for the audience, keeps GitHub's own query and carries the
    // request bearer.
    let expected_token_url =
        "https://tokens.example/token?api-version=2.0&audience=deploy+audience".to_owned();
    assert_eq!(
        http.token_requests(),
        vec![(expected_token_url, "request-bearer".to_owned()); 5]
    );
    // The Deploy body is the updater's request, signer included, never allow_older.
    let body: serde_json::Value =
        serde_json::from_slice(http.sent.borrow()[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "image_digest": DIGEST,
            "image_url": plan(60).request.image_url,
            "bundle_url": plan(60).request.bundle_url,
            "signer": {"repository": "example-org/app", "workflow": ".github/workflows/artifacts.yml", "ref": "refs/heads/main"},
            "version": "1.2.3",
            "allow_older": false,
        })
    );
    // One wait before each Status request, none before Deploy.
    assert_eq!(clock.sleeps.get(), 4);
}

#[test]
fn a_deploy_answered_already_converged_passes_without_a_status_request() {
    let http = FakeHttp::new(vec![answer(200, record(ID, "converged", "done", None))]);
    let (result, lines, clock) = go(&plan(60), &http);
    assert_eq!(result, Ok(id()));
    assert_eq!(
        lines[1..],
        [
            format!("deploy {ID}: converged, phase done"),
            format!("deploy {ID} converged")
        ]
    );
    assert_eq!(http.calls().len(), 1);
    assert_eq!(clock.sleeps.get(), 0);
}

#[test]
fn every_other_final_state_fails_with_the_records_error() {
    let cases = [
        (
            "failed",
            Some(("bundle_signer", "signed by another workflow")),
            "deploy d-abcdefghijklmnopqrstuvwxyz ended failed: bundle_signer: signed by another workflow",
        ),
        (
            "rolled_back",
            Some(("swarm_rolled_back", "Swarm rolled back")),
            "deploy d-abcdefghijklmnopqrstuvwxyz ended rolled_back: swarm_rolled_back: Swarm rolled back",
        ),
        (
            "paused",
            Some(("swarm_paused", "update paused")),
            "deploy d-abcdefghijklmnopqrstuvwxyz ended paused: swarm_paused: update paused",
        ),
        // A state this client does not know is final, and fails.
        (
            "abandoned",
            None,
            "deploy d-abcdefghijklmnopqrstuvwxyz ended abandoned: none: the record names no error",
        ),
    ];
    for (state, error, message) in cases {
        let http = FakeHttp::new(vec![
            answer(202, record(ID, "running", "queued", None)),
            answer(200, record(ID, state, "done", error)),
        ]);
        let (result, lines, _) = go(&plan(60), &http);
        assert_eq!(result.unwrap_err().to_string(), message, "{state}");
        assert_eq!(
            lines.last().unwrap(),
            &format!("deploy {ID}: {state}, phase done")
        );
    }
}

#[test]
fn a_refused_deploy_fails_at_once_with_the_answers_error() {
    let http = FakeHttp::new(vec![answer(
        409,
        error_body("busy", "deploy d-x is running"),
    )]);
    let (result, _, clock) = go(&plan(60), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        "deploy refused: 409 busy: deploy d-x is running"
    );
    assert_eq!(clock.sleeps.get(), 0);

    // A body that is not an error body is shown as one line of at most 512 characters.
    let long = format!("no route\nhere {}", "x".repeat(600));
    let http = FakeHttp::new(vec![answer(404, long.into_bytes())]);
    let (result, _, _) = go(&plan(60), &http);
    let expected = format!("no route here {}", "x".repeat(512 - "no route here ".len()));
    assert_eq!(
        result.unwrap_err(),
        DeployError::Refused {
            status: 404,
            error: "unexpected_answer".to_owned(),
            detail: expected
        }
    );
}

#[test]
fn deploy_is_retried_on_503_and_transport_errors_with_a_new_token_each_time() {
    let http = FakeHttp::new(vec![
        answer(503, b"no healthy upstream".to_vec()),
        unreachable_answer(DEPLOY_URL),
        answer(200, record(ID, "converged", "done", None)),
    ]);
    let (result, lines, clock) = go(&plan(60), &http);
    assert_eq!(result, Ok(id()));
    assert_eq!(
        lines[1..3],
        [
            "deploy: 503: no healthy upstream; retrying in 10 s".to_owned(),
            format!("deploy: {DEPLOY_URL}: connection refused; retrying in 10 s"),
        ]
    );
    let bearers: Vec<String> = http.calls().into_iter().map(|c| c.2).collect();
    assert_eq!(bearers, ["token-1", "token-2", "token-3"]);
    assert_eq!(clock.sleeps.get(), 2);
}

#[test]
fn a_deploy_never_accepted_fails_once_the_wait_has_run_out() {
    // One minute: attempts at 0, 10, ..., 60 seconds; the one at 60 s is the last.
    let http = FakeHttp::new((0..7).map(|_| answer(503, b"down".to_vec())).collect());
    let (result, _, clock) = go(&plan(1), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        "the deploy was not accepted within 1 min; last attempt: 503: down"
    );
    assert_eq!(http.calls().len(), 7);
    assert_eq!(clock.sleeps.get(), 6);
}

#[test]
fn status_is_retried_on_503_and_transport_errors() {
    let http = FakeHttp::new(vec![
        answer(202, record(ID, "running", "handed_off", None)),
        answer(503, b"no healthy upstream".to_vec()),
        unreachable_answer(STATUS_URL),
        answer(200, record(ID, "converged", "done", None)),
    ]);
    let (result, lines, _) = go(&plan(60), &http);
    assert_eq!(result, Ok(id()));
    assert_eq!(
        lines[2..4],
        [
            format!("status of deploy {ID}: 503: no healthy upstream; retrying"),
            format!("status of deploy {ID}: {STATUS_URL}: connection refused; retrying"),
        ]
    );
}

#[test]
fn a_deploy_still_running_when_the_wait_runs_out_fails_and_says_it_continues() {
    // Status at 10, 20, ..., 60 seconds, then the wait is over.
    let mut script = vec![answer(202, record(ID, "running", "waiting", None))];
    script.extend((0..6).map(|_| answer(200, record(ID, "running", "waiting", None))));
    let http = FakeHttp::new(script);
    let (result, lines, clock) = go(&plan(1), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("deploy {ID} still running; it continues")
    );
    assert_eq!(http.calls().len(), 7);
    assert_eq!(clock.sleeps.get(), 6);
    // An unchanged state and phase is printed once.
    assert_eq!(lines.len(), 2);
}

#[test]
fn a_wait_of_zero_waits_however_long_the_deploy_takes() {
    // 600 polls is 100 minutes: past the default wait, and past any wait of one minute.
    let mut script = vec![answer(202, record(ID, "running", "waiting", None))];
    script.extend((0..600).map(|_| answer(200, record(ID, "running", "waiting", None))));
    script.push(answer(200, record(ID, "converged", "done", None)));
    let http = FakeHttp::new(script);
    let (result, _, clock) = go(&plan(0), &http);
    assert_eq!(result, Ok(id()));
    assert_eq!(clock.sleeps.get(), 601);
}

#[test]
fn a_refused_status_request_fails_with_the_answers_error() {
    let http = FakeHttp::new(vec![
        answer(202, record(ID, "running", "queued", None)),
        answer(404, error_body("unknown_deploy", "no such deploy")),
    ]);
    let (result, _, _) = go(&plan(60), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        format!("status of deploy {ID}: 404 unknown_deploy: no such deploy")
    );
}

#[test]
fn an_answer_that_is_not_the_deploys_record_fails() {
    let http = FakeHttp::new(vec![answer(202, b"{}".to_vec())]);
    let (result, _, _) = go(&plan(60), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        "the answer to deploy is not a deploy record: missing field `id` at line 1 column 2"
    );

    // An id that is not a deploy id is not a record either.
    let http = FakeHttp::new(vec![answer(
        202,
        record("d-../x", "running", "queued", None),
    )]);
    let (result, _, _) = go(&plan(60), &http);
    assert!(matches!(result.unwrap_err(), DeployError::BadRecord { what, .. } if what == "deploy"));

    let http = FakeHttp::new(vec![
        answer(202, record(ID, "running", "queued", None)),
        answer(200, record(OTHER_ID, "converged", "done", None)),
    ]);
    let (result, _, _) = go(&plan(60), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        format!(
            "the answer to status of deploy {ID} is not a deploy record: it is deploy {OTHER_ID}"
        )
    );

    let http = FakeHttp::new(vec![
        answer(202, record(ID, "running", "queued", None)),
        answer(200, b"not json".to_vec()),
    ]);
    let (result, _, _) = go(&plan(60), &http);
    assert!(
        matches!(result.unwrap_err(), DeployError::BadRecord { what, .. } if what == format!("status of deploy {ID}"))
    );
}

#[test]
fn a_token_github_does_not_mint_ends_the_run_before_anything_is_sent() {
    let cases = [
        (
            answer(500, b"internal\n".to_vec()),
            "the OIDC token request failed: status 500: internal",
        ),
        (
            answer(200, b"{\"count\":1}".to_vec()),
            "the OIDC token request failed: the answer has no token: missing field `value` at line 1 column 11",
        ),
        (
            unreachable_answer("https://tokens.example/token"),
            "the OIDC token request failed: https://tokens.example/token: connection refused",
        ),
    ];
    for (token_answer, message) in cases {
        let http = FakeHttp::new(vec![]);
        *http.token_answer.borrow_mut() = Some(token_answer);
        let (result, _, _) = go(&plan(60), &http);
        assert_eq!(result.unwrap_err().to_string(), message);
        assert!(http.calls().is_empty());
    }

    // A token that fails while following a deploy ends the run too.
    let http = FakeHttp::new(vec![answer(202, record(ID, "running", "queued", None))]);
    http.good_tokens.set(1);
    *http.token_answer.borrow_mut() = Some(answer(403, b"denied".to_vec()));
    let (result, _, _) = go(&plan(60), &http);
    assert_eq!(
        result.unwrap_err().to_string(),
        "the OIDC token request failed: status 403: denied"
    );
    assert_eq!(http.calls().len(), 1);
}
