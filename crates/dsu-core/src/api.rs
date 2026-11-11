//! The JSON types of the API (docs/design.md section 2): the deploy request, the error body
//! and every refusal token with its HTTP status, the list entries.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::config::Signer;
use crate::ids::{DeployId, Digest, ServiceName};
use crate::peer::{PeerRefusal, Principal};
use crate::route::RouteRefusal;

/// The longest `version` text of a deploy request, in bytes.
pub const MAX_VERSION_BYTES: usize = 128;

/// The largest request body the API reads, in bytes (16 KiB).
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// An error answer: the HTTP status, the `error` token and a one-line `detail`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// 400: the body or header cannot be used.
    #[error("bad_request: {0}")]
    BadRequest(String),
    /// 401: the proxy's uid sent no claims header.
    #[error("no_claims: {0}")]
    NoClaims(String),
    /// 401: the peer may not send this request.
    #[error("bad_peer: {0}")]
    BadPeer(String),
    /// 401: the token's `exp` has passed.
    #[error("expired: {0}")]
    Expired(String),
    /// 401: the token's `jti` was used before.
    #[error("replayed: {0}")]
    Replayed(String),
    /// 403: no caller entry of the service equals the claims, or the operator-only route.
    #[error("not_allowed: {0}")]
    NotAllowed(String),
    /// 403: the request's `signer` differs from the configured one.
    #[error("signer_mismatch: {0}")]
    SignerMismatch(String),
    /// 403: a URL breaks the URL rules.
    #[error("url_not_allowed: {0}")]
    UrlNotAllowed(String),
    /// 404: the path matches no endpoint.
    #[error("not_found: {0}")]
    NotFound(String),
    /// 404: `{service}` is not configured.
    #[error("unknown_service: {0}")]
    UnknownService(String),
    /// 404: no such deploy, or the caller may not see it.
    #[error("unknown_deploy: {0}")]
    UnknownDeploy(String),
    /// 405: the path answers another method.
    #[error("method_not_allowed: {0}")]
    MethodNotAllowed(String),
    /// 409: another digest of the service is deploying (its id is in the detail).
    #[error("busy: {0}")]
    Busy(String),
    /// 409: the digest is in the service's failed list.
    #[error("previously_failed: {0}")]
    PreviouslyFailed(String),
    /// 409: a self-update and another deploy would overlap.
    #[error("self_update_busy: {0}")]
    SelfUpdateBusy(String),
    /// 413: the body is over 16 KiB.
    #[error("payload_too_large: {0}")]
    PayloadTooLarge(String),
    /// 500: the updater failed (a state file could not be written, ...).
    #[error("internal: {0}")]
    Internal(String),
    /// 503: the updater is not healthy.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl ApiError {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            ApiError::BadRequest(_) => 400,
            ApiError::NoClaims(_)
            | ApiError::BadPeer(_)
            | ApiError::Expired(_)
            | ApiError::Replayed(_) => 401,
            ApiError::NotAllowed(_) | ApiError::SignerMismatch(_) | ApiError::UrlNotAllowed(_) => {
                403
            }
            ApiError::NotFound(_) | ApiError::UnknownService(_) | ApiError::UnknownDeploy(_) => 404,
            ApiError::MethodNotAllowed(_) => 405,
            ApiError::Busy(_) | ApiError::PreviouslyFailed(_) | ApiError::SelfUpdateBusy(_) => 409,
            ApiError::PayloadTooLarge(_) => 413,
            ApiError::Internal(_) => 500,
            ApiError::Unavailable(_) => 503,
        }
    }

    /// The `error` token.
    pub fn token(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::NoClaims(_) => "no_claims",
            ApiError::BadPeer(_) => "bad_peer",
            ApiError::Expired(_) => "expired",
            ApiError::Replayed(_) => "replayed",
            ApiError::NotAllowed(_) => "not_allowed",
            ApiError::SignerMismatch(_) => "signer_mismatch",
            ApiError::UrlNotAllowed(_) => "url_not_allowed",
            ApiError::NotFound(_) => "not_found",
            ApiError::UnknownService(_) => "unknown_service",
            ApiError::UnknownDeploy(_) => "unknown_deploy",
            ApiError::MethodNotAllowed(_) => "method_not_allowed",
            ApiError::Busy(_) => "busy",
            ApiError::PreviouslyFailed(_) => "previously_failed",
            ApiError::SelfUpdateBusy(_) => "self_update_busy",
            ApiError::PayloadTooLarge(_) => "payload_too_large",
            ApiError::Internal(_) => "internal",
            ApiError::Unavailable(_) => "unavailable",
        }
    }

    /// The one-line `detail`.
    pub fn detail(&self) -> &str {
        match self {
            ApiError::BadRequest(d)
            | ApiError::NoClaims(d)
            | ApiError::BadPeer(d)
            | ApiError::Expired(d)
            | ApiError::Replayed(d)
            | ApiError::NotAllowed(d)
            | ApiError::SignerMismatch(d)
            | ApiError::UrlNotAllowed(d)
            | ApiError::NotFound(d)
            | ApiError::UnknownService(d)
            | ApiError::UnknownDeploy(d)
            | ApiError::MethodNotAllowed(d)
            | ApiError::Busy(d)
            | ApiError::PreviouslyFailed(d)
            | ApiError::SelfUpdateBusy(d)
            | ApiError::PayloadTooLarge(d)
            | ApiError::Internal(d)
            | ApiError::Unavailable(d) => d,
        }
    }

    /// The body of the answer.
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            error: self.token().to_owned(),
            detail: self.detail().to_owned(),
        }
    }

    /// The JSON text of the body: `{"error": "<token>", "detail": "<one line>"}`.
    pub fn to_json(&self) -> String {
        serde_json::json!({ "error": self.token(), "detail": self.detail() }).to_string()
    }
}

impl From<PeerRefusal> for ApiError {
    fn from(refusal: PeerRefusal) -> Self {
        match refusal {
            PeerRefusal::BadPeer => ApiError::BadPeer("this peer may not send this request".into()),
            PeerRefusal::NoClaims => {
                ApiError::NoClaims("the request carries no claims header".into())
            }
        }
    }
}

impl From<RouteRefusal> for ApiError {
    fn from(refusal: RouteRefusal) -> Self {
        match refusal {
            RouteRefusal::NotFound => ApiError::NotFound("no such path".into()),
            RouteRefusal::MethodNotAllowed { allow } => {
                ApiError::MethodNotAllowed(format!("this path answers {allow} only"))
            }
        }
    }
}

/// The JSON body of every error answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The token, e.g. `busy`.
    pub error: String,
    /// One line for a person.
    pub detail: String,
}

/// The body of a 200 `GET /v1/health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthBody {
    /// Always true in a 200.
    pub ok: bool,
}

/// The `signer` object of a deploy request: the three fields the caller states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSigner {
    /// `owner/repo` of the signing workflow's repository.
    pub repository: String,
    /// The signing workflow's path.
    pub workflow: String,
    /// The git ref the workflow ran on.
    #[serde(rename = "ref")]
    pub git_ref: String,
}

/// The body of `POST /v1/services/{service}/deploys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRequest {
    /// The manifest digest the caller expects.
    pub image_digest: Digest,
    /// The release URL of the image tar.
    pub image_url: String,
    /// The release URL of the tar's Sigstore bundle.
    pub bundle_url: String,
    /// The signer the caller expects, checked against the configured one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<RequestSigner>,
    /// Free text for the record and the log, at most 128 bytes.
    pub version: String,
    /// Accept a release older than the running one; the local operator only.
    #[serde(default)]
    pub allow_older: bool,
}

impl DeployRequest {
    /// Parses a request body. Unknown fields, a `version` over 128 bytes or with control
    /// characters, and bad JSON are `bad_request`.
    pub fn from_json(body: &[u8]) -> Result<DeployRequest, ApiError> {
        let request: DeployRequest = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(one_line(&format!("request body: {e}"))))?;
        if request.version.len() > MAX_VERSION_BYTES {
            return Err(ApiError::BadRequest(format!(
                "version is longer than {MAX_VERSION_BYTES} bytes"
            )));
        }
        if request.version.chars().any(char::is_control) {
            return Err(ApiError::BadRequest(
                "version contains a control character".into(),
            ));
        }
        Ok(request)
    }

    /// `allow_older` is accepted only from the local operator; from anyone else it is 400.
    pub fn check_allow_older(&self, principal: Principal) -> Result<(), ApiError> {
        if self.allow_older && principal != Principal::Operator {
            return Err(ApiError::BadRequest(
                "allow_older is accepted only from the local operator".into(),
            ));
        }
        Ok(())
    }

    /// The stated `signer`, if any, must equal the configured one on the three fields it
    /// carries; a difference is `signer_mismatch` naming the field.
    pub fn check_signer(&self, configured: &Signer) -> Result<(), ApiError> {
        let Some(stated) = &self.signer else {
            return Ok(());
        };
        let fields = [
            ("repository", &stated.repository, &configured.repository),
            ("workflow", &stated.workflow, &configured.workflow),
            ("ref", &stated.git_ref, &configured.git_ref),
        ];
        match fields
            .into_iter()
            .find(|(_, stated, configured)| stated != configured)
        {
            Some((name, _, _)) => Err(ApiError::SignerMismatch(format!(
                "signer.{name} is not the configured one"
            ))),
            None => Ok(()),
        }
    }
}

/// The text of `message` on one line: line breaks and other control characters become spaces.
fn one_line(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// One service in the `GET /v1/services` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListEntry {
    /// The `{service}` name of the API.
    pub service: ServiceName,
    /// The Swarm service it updates.
    pub swarm_service: String,
    /// The image digests Swarm's running tasks use.
    pub running_digests: Vec<Digest>,
    /// Swarm's `UpdateStatus.State`, if the service has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_state: Option<String>,
    /// The id of the service's latest deploy record, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_deploy: Option<DeployId>,
    /// The failed list.
    pub failed_digests: Vec<Digest>,
    /// The signed time of the last converged release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<Timestamp>,
}

/// The validity of a key of the trusted root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWindow {
    /// First instant the key is valid.
    pub from: Timestamp,
    /// Last instant the key is valid; absent while no end is announced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
}

/// The body of a 200 `GET /v1/services`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResponse {
    /// The services the caller may act on.
    pub services: Vec<ListEntry>,
    /// The validity of the trusted root's newest key, so a rotation is visible before it
    /// happens; absent when the trusted root lists no key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root_newest_key: Option<KeyWindow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn body(extra: &str) -> String {
        format!(
            r#"{{"image_digest":"{D}","image_url":"https://github.com/example-org/app/releases/download/v1/a.tar","bundle_url":"https://github.com/example-org/app/releases/download/v1/a.tar.sigstore.json","version":"1.4.2"{extra}}}"#
        )
    }

    fn signer() -> Signer {
        Signer {
            repository: "example-org/app".into(),
            repository_id: "1".into(),
            workflow: ".github/workflows/artifacts.yml".into(),
            git_ref: "refs/heads/main".into(),
            triggers: vec!["push".into()],
        }
    }

    #[test]
    fn minimal_request_defaults() {
        let r = DeployRequest::from_json(body("").as_bytes()).unwrap();
        assert_eq!(r.image_digest.as_str(), D);
        assert_eq!(r.version, "1.4.2");
        assert!(r.signer.is_none());
        assert!(!r.allow_older);
    }

    #[test]
    fn full_request_round_trips() {
        let extra = r#","signer":{"repository":"example-org/app","workflow":".github/workflows/artifacts.yml","ref":"refs/heads/main"},"allow_older":true"#;
        let r = DeployRequest::from_json(body(extra).as_bytes()).unwrap();
        assert!(r.allow_older);
        assert_eq!(r.signer.as_ref().unwrap().git_ref, "refs/heads/main");
        let again =
            DeployRequest::from_json(serde_json::to_string(&r).unwrap().as_bytes()).unwrap();
        assert_eq!(again, r);
        let minimal = DeployRequest::from_json(body("").as_bytes()).unwrap();
        assert!(!serde_json::to_string(&minimal).unwrap().contains("signer"));
    }

    #[test]
    fn bad_requests_are_400() {
        let missing = r#"{"image_digest":"x"}"#.to_owned();
        let no_version = body("").replace(r#","version":"1.4.2""#, "");
        let long = body("").replace("1.4.2", &"v".repeat(129));
        let newline = body("").replace("1.4.2", "a\\nb");
        let cases = [
            ("", "request body"),
            ("{", "request body"),
            (missing.as_str(), "request body"),
            (no_version.as_str(), "version"),
            (long.as_str(), "128"),
            (newline.as_str(), "control"),
            (&body(r#","extra":1"#), "unknown field"),
            (&body(r#","ex\ntra":1"#), "unknown field `ex tra`"),
            (
                &body(r#","signer":{"repository":"a","workflow":"b","ref":"c","x":1}"#),
                "unknown field",
            ),
            (&body(r#","allow_older":"yes""#), "request body"),
            (&body(r#","image_digest":"nope""#), "request body"),
        ];
        for (text, needle) in cases {
            let err = DeployRequest::from_json(text.as_bytes()).unwrap_err();
            assert_eq!(err.status(), 400, "{text}");
            assert_eq!(err.token(), "bad_request");
            assert!(err.detail().contains(needle), "{text}: {}", err.detail());
            assert!(!err.detail().contains('\n'));
        }
        let at_limit = body("").replace("1.4.2", &"v".repeat(128));
        assert!(DeployRequest::from_json(at_limit.as_bytes()).is_ok());
    }

    #[test]
    fn allow_older_only_from_the_operator() {
        let plain = DeployRequest::from_json(body("").as_bytes()).unwrap();
        let older = DeployRequest::from_json(body(r#","allow_older":true"#).as_bytes()).unwrap();
        for p in [Principal::Proxy, Principal::Operator, Principal::Anyone] {
            assert_eq!(plain.check_allow_older(p), Ok(()));
        }
        assert_eq!(older.check_allow_older(Principal::Operator), Ok(()));
        assert_eq!(
            older
                .check_allow_older(Principal::Proxy)
                .unwrap_err()
                .status(),
            400
        );
        assert_eq!(
            older
                .check_allow_older(Principal::Anyone)
                .unwrap_err()
                .token(),
            "bad_request"
        );
    }

    #[test]
    fn signer_is_compared_field_by_field() {
        let configured = signer();
        let none = DeployRequest::from_json(body("").as_bytes()).unwrap();
        assert_eq!(none.check_signer(&configured), Ok(()));
        let same = DeployRequest::from_json(
            body(r#","signer":{"repository":"example-org/app","workflow":".github/workflows/artifacts.yml","ref":"refs/heads/main"}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(same.check_signer(&configured), Ok(()));
        for field in ["repository", "workflow", "ref"] {
            let mut r = same.clone();
            let s = r.signer.as_mut().unwrap();
            match field {
                "repository" => s.repository.push('x'),
                "workflow" => s.workflow.push('x'),
                _ => s.git_ref.push('x'),
            }
            let err = r.check_signer(&configured).unwrap_err();
            assert_eq!(err.status(), 403);
            assert_eq!(err.token(), "signer_mismatch");
            assert!(err.detail().contains(field));
        }
    }

    #[test]
    fn every_error_has_its_status_and_token() {
        let d = || "d".to_owned();
        let all = [
            (ApiError::BadRequest(d()), 400, "bad_request"),
            (ApiError::NoClaims(d()), 401, "no_claims"),
            (ApiError::BadPeer(d()), 401, "bad_peer"),
            (ApiError::Expired(d()), 401, "expired"),
            (ApiError::Replayed(d()), 401, "replayed"),
            (ApiError::NotAllowed(d()), 403, "not_allowed"),
            (ApiError::SignerMismatch(d()), 403, "signer_mismatch"),
            (ApiError::UrlNotAllowed(d()), 403, "url_not_allowed"),
            (ApiError::NotFound(d()), 404, "not_found"),
            (ApiError::UnknownService(d()), 404, "unknown_service"),
            (ApiError::UnknownDeploy(d()), 404, "unknown_deploy"),
            (ApiError::MethodNotAllowed(d()), 405, "method_not_allowed"),
            (ApiError::Busy(d()), 409, "busy"),
            (ApiError::PreviouslyFailed(d()), 409, "previously_failed"),
            (ApiError::SelfUpdateBusy(d()), 409, "self_update_busy"),
            (ApiError::PayloadTooLarge(d()), 413, "payload_too_large"),
            (ApiError::Internal(d()), 500, "internal"),
            (ApiError::Unavailable(d()), 503, "unavailable"),
        ];
        for (err, status, token) in all {
            assert_eq!(err.status(), status);
            assert_eq!(err.token(), token);
            assert_eq!(err.detail(), "d");
            assert_eq!(err.to_string(), format!("{token}: d"));
            assert_eq!(
                err.body(),
                ErrorBody {
                    error: token.into(),
                    detail: "d".into()
                }
            );
            let parsed: ErrorBody = serde_json::from_str(&err.to_json()).unwrap();
            assert_eq!(parsed, err.body());
        }
    }

    #[test]
    fn peer_and_route_refusals_become_api_errors() {
        let e = ApiError::from(PeerRefusal::BadPeer);
        assert_eq!((e.status(), e.token()), (401, "bad_peer"));
        let e = ApiError::from(PeerRefusal::NoClaims);
        assert_eq!((e.status(), e.token()), (401, "no_claims"));
        let e = ApiError::from(RouteRefusal::NotFound);
        assert_eq!((e.status(), e.token()), (404, "not_found"));
        let e = ApiError::from(RouteRefusal::MethodNotAllowed { allow: "POST" });
        assert_eq!((e.status(), e.token()), (405, "method_not_allowed"));
        assert!(e.detail().contains("POST"));
    }

    #[test]
    fn list_entry_shape() {
        let entry = ListEntry {
            service: ServiceName::parse("app").unwrap(),
            swarm_service: "app_server".into(),
            running_digests: vec![Digest::parse(D).unwrap()],
            update_state: None,
            last_deploy: None,
            failed_digests: vec![],
            floor: None,
        };
        let json = serde_json::to_value(ListResponse {
            services: vec![entry.clone()],
            trusted_root_newest_key: None,
        })
        .unwrap();
        assert_eq!(json["services"][0]["service"], "app");
        assert!(json.get("trusted_root_newest_key").is_none());
        assert!(json["services"][0].get("floor").is_none());
        let full = ListEntry {
            update_state: Some("completed".into()),
            last_deploy: Some(DeployId::parse("d-abcdefghijklmnopqrstuvwxyz").unwrap()),
            floor: Some("2026-10-01T00:00:00Z".parse().unwrap()),
            ..entry
        };
        let text = serde_json::to_string(&full).unwrap();
        assert!(text.contains("2026-10-01T00:00:00Z"));
        assert_eq!(serde_json::from_str::<ListEntry>(&text).unwrap(), full);
        assert_eq!(
            serde_json::to_string(&HealthBody { ok: true }).unwrap(),
            r#"{"ok":true}"#
        );
    }

    #[test]
    fn list_response_carries_the_newest_key_window() {
        let from: Timestamp = "2026-09-01T00:00:00Z".parse().unwrap();
        let until: Timestamp = "2027-09-01T00:00:00Z".parse().unwrap();
        for window in [
            KeyWindow { from, until: None },
            KeyWindow {
                from,
                until: Some(until),
            },
        ] {
            let response = ListResponse {
                services: vec![],
                trusted_root_newest_key: Some(window),
            };
            let text = serde_json::to_string(&response).unwrap();
            assert_eq!(text.contains("until"), window.until.is_some());
            assert_eq!(
                serde_json::from_str::<ListResponse>(&text).unwrap(),
                response
            );
        }
    }

    #[test]
    fn limits_are_the_documented_ones() {
        assert_eq!(MAX_BODY_BYTES, 16_384);
        assert_eq!(MAX_VERSION_BYTES, 128);
    }
}
