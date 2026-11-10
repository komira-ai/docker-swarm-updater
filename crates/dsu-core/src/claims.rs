//! The claims header `x-dsu-claims`: the base64url JSON payload of the caller's verified
//! OIDC token, set by the fronting proxy (docs/design.md section 1).

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use jiff::Timestamp;
use serde::Deserialize;

use crate::config::Caller;

/// A claims header that cannot be used; the answer is 400 `bad_request`.
#[derive(Debug, thiserror::Error)]
pub enum ClaimsError {
    /// The header is not base64url.
    #[error("claims header is not base64url: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The payload is not a JSON object with the fields read (`jti` and `exp` are required).
    #[error("claims payload is not the expected JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// `jti` is the empty string.
    #[error("claims payload has an empty jti")]
    EmptyJti,
    /// `exp` is outside the range of representable times.
    #[error("claims payload has an exp that is not a valid time: {exp}")]
    ExpOutOfRange {
        /// The number found.
        exp: f64,
    },
}

/// Base64url, no padding on output; padding tolerated on input.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The fields of the token payload the updater reads. A claim the token lacks is the empty
/// string, which no configured caller equals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// `repository`.
    pub repository: String,
    /// `repository_id`.
    pub repository_id: String,
    /// `job_workflow_ref`.
    pub job_workflow_ref: String,
    /// `ref`.
    pub git_ref: String,
    /// `environment`.
    pub environment: String,
    /// `runner_environment`.
    pub runner_environment: String,
    /// `run_id`.
    pub run_id: String,
    /// `jti`: the token id, accepted once.
    pub jti: String,
    /// `exp`: when the token expires.
    pub exp: Timestamp,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    repository: String,
    #[serde(default)]
    repository_id: String,
    #[serde(default)]
    job_workflow_ref: String,
    #[serde(default, rename = "ref")]
    git_ref: String,
    #[serde(default)]
    environment: String,
    #[serde(default)]
    runner_environment: String,
    #[serde(default)]
    run_id: String,
    jti: String,
    exp: f64,
}

impl Claims {
    /// Decodes the value of the `x-dsu-claims` header.
    pub fn from_header(value: &str) -> Result<Claims, ClaimsError> {
        let bytes = BASE64URL.decode(value)?;
        let p: Payload = serde_json::from_slice(&bytes)?;
        if p.jti.is_empty() {
            return Err(ClaimsError::EmptyJti);
        }
        let exp = Timestamp::from_second(p.exp.floor() as i64)
            .map_err(|_| ClaimsError::ExpOutOfRange { exp: p.exp })?;
        Ok(Claims {
            repository: p.repository,
            repository_id: p.repository_id,
            job_workflow_ref: p.job_workflow_ref,
            git_ref: p.git_ref,
            environment: p.environment,
            runner_environment: p.runner_environment,
            run_id: p.run_id,
            jti: p.jti,
            exp,
        })
    }

    /// Whether the token has expired at `now` (`exp` is not in the future).
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.exp <= now
    }

    /// Whether `caller` equals these claims on all six claims it lists.
    pub fn matches(&self, caller: &Caller) -> bool {
        self.repository == caller.repository
            && self.repository_id == caller.repository_id
            && self.job_workflow_ref == caller.job_workflow_ref
            && self.git_ref == caller.git_ref
            && self.environment == caller.environment
            && self.runner_environment == caller.runner_environment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn header(json: &str) -> String {
        BASE64URL.encode(json)
    }

    const FULL: &str = r#"{"repository":"example-org/app","repository_id":"1","job_workflow_ref":"example-org/dsu/.github/workflows/deploy.yml@abc","ref":"refs/heads/main","environment":"production","runner_environment":"github-hosted","run_id":"77","jti":"j-1","exp":1790000000,"iss":"x","aud":"y"}"#;

    fn caller() -> Caller {
        Caller {
            repository: "example-org/app".into(),
            repository_id: "1".into(),
            job_workflow_ref: "example-org/dsu/.github/workflows/deploy.yml@abc".into(),
            git_ref: "refs/heads/main".into(),
            environment: "production".into(),
            runner_environment: "github-hosted".into(),
        }
    }

    #[test]
    fn decodes_every_field_and_ignores_unknown_ones() {
        let c = Claims::from_header(&header(FULL)).unwrap();
        assert_eq!(c.repository, "example-org/app");
        assert_eq!(c.repository_id, "1");
        assert_eq!(c.git_ref, "refs/heads/main");
        assert_eq!(c.environment, "production");
        assert_eq!(c.runner_environment, "github-hosted");
        assert_eq!(c.run_id, "77");
        assert_eq!(c.jti, "j-1");
        assert_eq!(c.exp, Timestamp::from_second(1_790_000_000).unwrap());
    }

    #[test]
    fn padding_is_tolerated() {
        let padded = format!("{}==", header(r#"{"jti":"a","exp":5}"#));
        assert!(Claims::from_header(&padded).is_ok());
        let c = Claims::from_header(&header(r#"{"jti":"a","exp":5}"#)).unwrap();
        assert_eq!(c.repository, "");
    }

    #[test]
    fn fractional_exp_is_floored() {
        let c = Claims::from_header(&header(r#"{"jti":"a","exp":5.9}"#)).unwrap();
        assert_eq!(c.exp, Timestamp::from_second(5).unwrap());
    }

    #[test]
    fn malformed_headers_are_refused() {
        assert!(matches!(
            Claims::from_header("not base64!"),
            Err(ClaimsError::Base64(_))
        ));
        assert!(matches!(
            Claims::from_header("+/+/"),
            Err(ClaimsError::Base64(_))
        ));
        assert!(matches!(
            Claims::from_header(&header("{")),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header("[]")),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header(r#"{"exp":1}"#)),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header(r#"{"jti":"a"}"#)),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header(r#"{"jti":"a","exp":"soon"}"#)),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header(r#"{"jti":1,"exp":1}"#)),
            Err(ClaimsError::Json(_))
        ));
        assert!(matches!(
            Claims::from_header(&header(r#"{"jti":"","exp":1}"#)),
            Err(ClaimsError::EmptyJti)
        ));
        let err = Claims::from_header(&header(r#"{"jti":"a","exp":1e30}"#)).unwrap_err();
        assert!(matches!(err, ClaimsError::ExpOutOfRange { .. }));
        assert!(err.to_string().contains("exp"));
    }

    #[test]
    fn expiry_is_exclusive() {
        let c = Claims::from_header(&header(FULL)).unwrap();
        assert!(!c.is_expired(Timestamp::from_second(1_789_999_999).unwrap()));
        assert!(c.is_expired(c.exp));
        assert!(c.is_expired(Timestamp::from_second(1_790_000_001).unwrap()));
    }

    #[test]
    fn a_caller_matches_only_when_all_six_claims_are_equal() {
        let c = Claims::from_header(&header(FULL)).unwrap();
        assert!(c.matches(&caller()));
        let edits: [fn(&mut Caller); 6] = [
            |c| c.repository.push('x'),
            |c| c.repository_id.push('x'),
            |c| c.job_workflow_ref.push('x'),
            |c| c.git_ref.push('x'),
            |c| c.environment.push('x'),
            |c| c.runner_environment.push('x'),
        ];
        for edit in edits {
            let mut other = caller();
            edit(&mut other);
            assert!(!c.matches(&other));
        }
    }
}
