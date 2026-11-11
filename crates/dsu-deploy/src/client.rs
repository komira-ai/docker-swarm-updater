//! One deploy, start to end (docs/design.md section 7, the reusable workflow): ask GitHub for
//! a new OIDC token for every request, `POST /v1/services/{service}/deploys`, then
//! `GET /v1/deploys/{id}` every [`POLL_INTERVAL`] until the record reaches a final state or
//! the wait runs out.
//!
//! - A 503 or a transport error (the updater replacing itself, the proxy without an upstream,
//!   a tailnet peer not yet visible) is retried every [`POLL_INTERVAL`], on Deploy and on
//!   Status, until the wait runs out. Deploy is idempotent per (service, digest), so a retried
//!   Deploy that did reach the updater answers 200 with the same record.
//! - Any other answer that is not 200 or 202 ends the run with the answer's `error` and
//!   `detail`.
//! - `converged` passes; every other final state fails with the record's error; the wait
//!   running out fails with "deploy `<id>` still running; it continues".
//!
//! Side effects are behind [`Http`] and [`Clock`], so the tests drive every path with fakes and
//! a virtual clock.

use std::io::Write;
use std::time::Duration;

use dsu_core::api::DeployRequest;
use dsu_core::ids::{DeployId, ServiceName};
use serde::Deserialize;

/// How long to wait between two Status requests, and before retrying a 503.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The record state that is not final.
const RUNNING: &str = "running";
/// The final state that passes.
const CONVERGED: &str = "converged";

/// The method of a [`Request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`, no body.
    Get,
    /// `POST` with a JSON body.
    Post,
}

/// One HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The absolute URL.
    pub url: String,
    /// Sent as `Authorization: Bearer <bearer>`.
    pub bearer: String,
    /// The JSON body of a `POST`.
    pub body: Option<Vec<u8>>,
}

/// One HTTP answer, whatever its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// No answer was read: the connection failed, timed out, or the body was unreadable or too
/// large.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{url}: {message}")]
pub struct TransportError {
    /// The URL asked.
    pub url: String,
    /// What failed.
    pub message: String,
}

/// Sends one request and reads its answer.
pub trait Http {
    /// Sends `request`; any status is an answer, only a failure to get one is an error.
    fn send(&self, request: &Request) -> Result<Response, TransportError>;
}

/// The time the run has taken, and waiting.
pub trait Clock {
    /// The time since the run started.
    fn elapsed(&self) -> Duration;
    /// Waits `duration`.
    fn sleep(&self, duration: Duration);
}

/// Where GitHub mints OIDC tokens for this job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSource {
    /// `ACTIONS_ID_TOKEN_REQUEST_URL`; `audience` is added to its query.
    pub url: url::Url,
    /// `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, the bearer of the token request.
    pub bearer: String,
    /// The audience every token is minted for.
    pub audience: String,
}

/// What one run asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The deploy front, `http[s]://host[:port]` with no path.
    pub endpoint: String,
    /// The configured service to deploy.
    pub service: ServiceName,
    /// The body of the Deploy request.
    pub request: DeployRequest,
    /// Where tokens come from.
    pub tokens: TokenSource,
    /// How long to wait for a final state; `None` waits however long it takes.
    pub wait: Option<Duration>,
}

/// Why a run did not end `converged`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeployError {
    /// GitHub did not mint a token.
    #[error("the OIDC token request failed: {0}")]
    Token(String),
    /// The Deploy request was answered with a refusal.
    #[error("deploy refused: {status} {error}: {detail}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The answer's `error` token, or `unexpected_answer` when the body is not an error body.
        error: String,
        /// The answer's `detail`, or the body's text.
        detail: String,
    },
    /// Every Deploy attempt failed with a 503 or a transport error until the wait ran out.
    #[error("the deploy was not accepted within {waited}; last attempt: {last}")]
    NotAccepted {
        /// The wait, for a person (`60 min`).
        waited: String,
        /// The last attempt's failure.
        last: String,
    },
    /// A 200 or 202 answer is not a deploy record.
    #[error("the answer to {what} is not a deploy record: {detail}")]
    BadRecord {
        /// `deploy` or `status of deploy <id>`.
        what: String,
        /// Why it was not read.
        detail: String,
    },
    /// A Status request was answered with a refusal.
    #[error("status of deploy {id}: {status} {error}: {detail}")]
    StatusRefused {
        /// The deploy.
        id: DeployId,
        /// The HTTP status.
        status: u16,
        /// The answer's `error` token, or `unexpected_answer`.
        error: String,
        /// The answer's `detail`, or the body's text.
        detail: String,
    },
    /// The wait ran out while the deploy ran.
    #[error("deploy {id} still running; it continues")]
    StillRunning {
        /// The deploy.
        id: DeployId,
    },
    /// The deploy reached a final state other than `converged`.
    #[error("deploy {id} ended {state}: {token}: {detail}")]
    Ended {
        /// The deploy.
        id: DeployId,
        /// The final state.
        state: String,
        /// The record's error token, or `none` when the record names none.
        token: String,
        /// The record's error detail.
        detail: String,
    },
}

/// The fields of a record the client reads. States and phases are kept as text, so a newer
/// updater's state is reported rather than refused; any state but `running` is final.
#[derive(Debug, Deserialize)]
struct RecordView {
    id: DeployId,
    state: String,
    phase: String,
    #[serde(default)]
    error: Option<RecordErrorView>,
}

#[derive(Debug, Deserialize)]
struct RecordErrorView {
    token: String,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct ErrorBodyView {
    error: String,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct TokenAnswer {
    value: String,
}

/// The answer of one attempt that may be retried.
enum Attempt {
    /// A 200 or 202 with its body.
    Answered(Vec<u8>),
    /// A 503 or a transport error: worth another attempt.
    Retry(String),
    /// Any other status: the `error` and `detail` it carried.
    Refused(u16, String, String),
}

/// Runs one deploy to its end. Progress goes to `out`, one line per change. Returns the deploy
/// id when the record ends `converged`.
pub fn run(
    plan: &Plan,
    http: &dyn Http,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<DeployId, DeployError> {
    let record = deploy(plan, http, clock, out)?;
    follow(plan, record, http, clock, out)
}

/// Sends Deploy until it is answered with a record or a refusal, or the wait runs out.
fn deploy(
    plan: &Plan,
    http: &dyn Http,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<RecordView, DeployError> {
    let url = format!(
        "{}/v1/services/{}/deploys",
        plan.endpoint,
        plan.service.as_str()
    );
    // DeployRequest holds only strings, a digest and a bool; serialising it cannot fail.
    let body = serde_json::to_vec(&plan.request).unwrap_or_default();
    let _ = writeln!(
        out,
        "deploy {} {} (version {}) at {}",
        plan.service, plan.request.image_digest, plan.request.version, plan.endpoint
    );
    loop {
        let request = Request {
            method: Method::Post,
            url: url.clone(),
            bearer: mint(&plan.tokens, http)?,
            body: Some(body.clone()),
        };
        match attempt(http, &request) {
            Attempt::Answered(body) => return parse_record(&body, "deploy"),
            Attempt::Refused(status, error, detail) => {
                return Err(DeployError::Refused {
                    status,
                    error,
                    detail,
                });
            }
            Attempt::Retry(reason) => {
                if waited_out(plan, clock) {
                    return Err(DeployError::NotAccepted {
                        waited: wait_text(plan),
                        last: reason,
                    });
                }
                let _ = writeln!(out, "deploy: {reason}; retrying in {}", interval_text());
                clock.sleep(POLL_INTERVAL);
            }
        }
    }
}

/// Polls Status until the record is final or the wait runs out.
fn follow(
    plan: &Plan,
    mut record: RecordView,
    http: &dyn Http,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> Result<DeployId, DeployError> {
    let id = record.id.clone();
    let url = format!("{}/v1/deploys/{}", plan.endpoint, id.as_str());
    let what = format!("status of deploy {id}");
    let mut shown = (record.state.clone(), record.phase.clone());
    let _ = writeln!(out, "deploy {id}: {}, phase {}", shown.0, shown.1);
    while record.state == RUNNING {
        if waited_out(plan, clock) {
            return Err(DeployError::StillRunning { id });
        }
        clock.sleep(POLL_INTERVAL);
        let request = Request {
            method: Method::Get,
            url: url.clone(),
            bearer: mint(&plan.tokens, http)?,
            body: None,
        };
        match attempt(http, &request) {
            Attempt::Answered(body) => record = parse_record(&body, &what)?,
            Attempt::Retry(reason) => {
                let _ = writeln!(out, "{what}: {reason}; retrying");
                continue;
            }
            Attempt::Refused(status, error, detail) => {
                return Err(DeployError::StatusRefused {
                    id,
                    status,
                    error,
                    detail,
                });
            }
        }
        if record.id != id {
            return Err(DeployError::BadRecord {
                what,
                detail: format!("it is deploy {}", record.id),
            });
        }
        let now = (record.state.clone(), record.phase.clone());
        if now != shown {
            let _ = writeln!(out, "deploy {id}: {}, phase {}", now.0, now.1);
            shown = now;
        }
    }
    if record.state == CONVERGED {
        let _ = writeln!(out, "deploy {id} converged");
        return Ok(id);
    }
    let (token, detail) = match record.error {
        Some(e) => (e.token, e.detail),
        None => ("none".to_owned(), "the record names no error".to_owned()),
    };
    Err(DeployError::Ended {
        id,
        state: record.state,
        token,
        detail,
    })
}

/// A new OIDC token for `source.audience`.
fn mint(source: &TokenSource, http: &dyn Http) -> Result<String, DeployError> {
    let mut url = source.url.clone();
    url.query_pairs_mut()
        .append_pair("audience", &source.audience);
    let request = Request {
        method: Method::Get,
        url: url.into(),
        bearer: source.bearer.clone(),
        body: None,
    };
    let response = http
        .send(&request)
        .map_err(|e| DeployError::Token(e.to_string()))?;
    if response.status != 200 {
        return Err(DeployError::Token(format!(
            "status {}: {}",
            response.status,
            text(&response.body)
        )));
    }
    let answer: TokenAnswer = serde_json::from_slice(&response.body)
        .map_err(|e| DeployError::Token(format!("the answer has no token: {e}")))?;
    Ok(answer.value)
}

fn attempt(http: &dyn Http, request: &Request) -> Attempt {
    match http.send(request) {
        Err(e) => Attempt::Retry(e.to_string()),
        Ok(r) if r.status == 200 || r.status == 202 => Attempt::Answered(r.body),
        Ok(r) if r.status == 503 => Attempt::Retry(format!("503: {}", text(&r.body))),
        Ok(r) => {
            let (error, detail) = match serde_json::from_slice::<ErrorBodyView>(&r.body) {
                Ok(e) => (e.error, e.detail),
                Err(_) => ("unexpected_answer".to_owned(), text(&r.body)),
            };
            Attempt::Refused(r.status, error, detail)
        }
    }
}

fn parse_record(body: &[u8], what: &str) -> Result<RecordView, DeployError> {
    serde_json::from_slice(body).map_err(|e| DeployError::BadRecord {
        what: what.to_owned(),
        detail: e.to_string(),
    })
}

fn waited_out(plan: &Plan, clock: &dyn Clock) -> bool {
    plan.wait.is_some_and(|wait| clock.elapsed() >= wait)
}

fn wait_text(plan: &Plan) -> String {
    // Only called when a wait is set.
    let minutes = plan.wait.map_or(0, |w| w.as_secs() / 60);
    format!("{minutes} min")
}

fn interval_text() -> String {
    format!("{} s", POLL_INTERVAL.as_secs())
}

/// A body as one line of text, at most 512 characters.
fn text(body: &[u8]) -> String {
    let line: String = String::from_utf8_lossy(body)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(512)
        .collect();
    line.trim().to_owned()
}
