//! Offline Sigstore bundle verification with the signer-identity and subject checks of docker-swarm-updater.
//!
//! [`verify`] runs the checks of docs/design.md section 3.3 steps 1 to 3 on a release's
//! Sigstore bundle, in this order:
//!
//! 1. the bundle parses ([`VerifyError::Invalid`]);
//! 2. its DSSE envelope signs an in-toto statement of predicate type SLSA provenance v1 that
//!    has a subject with the tar's SHA-256 and a name matching `artifact_name`
//!    ([`VerifyError::Subject`]);
//! 3. the certificate chain, the signature and a verified time (a transparency-log entry or an
//!    RFC 3161 timestamp) check out against one of the trusted roots ([`VerifyError::Chain`]);
//! 4. the certificate says the configured signer made it ([`VerifyError::Signer`]).
//!
//! No step touches the network: the trusted roots are bytes ([`TrustedRoots::parse`]) and the
//! bundle carries every proof.

use std::fmt::{self, Display};

use dsu_core::config::Signer;
use dsu_core::ids::Digest;
use serde::Deserialize;
use sigstore_verify::trust_root::TrustedRoot;
use sigstore_verify::types::{ArtifactDigest, Bundle, Sha256Hash, SignatureContent};
use sigstore_verify::{VerificationPolicy, VerificationResult, Verifier};

/// The DSSE payload type of an in-toto statement.
const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The `_type` of an in-toto statement, version 1.
const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
/// The predicate type of SLSA provenance, version 1.
const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
/// The issuer of GitHub Actions identity tokens, the only OIDC issuer accepted.
const TOKEN_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The runner environment that is accepted: GitHub's own runners.
const GITHUB_HOSTED: &str = "github-hosted";

/// Why a bundle was refused. Each variant is one record token of the API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// `bundle_invalid`: the bytes are not a parseable Sigstore bundle.
    #[error("not a Sigstore bundle: {detail}")]
    Invalid {
        /// One line saying what is wrong.
        detail: String,
    },
    /// `bundle_subject`: the bundle does not attest the tar's SHA-256 under `artifact_name`.
    #[error("the bundle does not attest this artifact: {detail}")]
    Subject {
        /// One line saying what is wrong.
        detail: String,
    },
    /// `bundle_signer`: an identity check of section 3.3 step 2 failed.
    #[error("the bundle was not signed by the configured signer: {detail}")]
    Signer {
        /// One line saying which check failed.
        detail: String,
    },
    /// `bundle_chain`: the certificate chain, the log entry or the timestamp does not verify
    /// against the trusted root.
    #[error("the bundle does not verify against the trusted root: {detail}")]
    Chain {
        /// One line saying what failed.
        detail: String,
    },
}

impl VerifyError {
    /// The record token: `bundle_invalid`, `bundle_subject`, `bundle_signer` or `bundle_chain`.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "bundle_invalid",
            Self::Subject { .. } => "bundle_subject",
            Self::Signer { .. } => "bundle_signer",
            Self::Chain { .. } => "bundle_chain",
        }
    }

    /// The one-line detail.
    pub fn detail(&self) -> &str {
        match self {
            Self::Invalid { detail }
            | Self::Subject { detail }
            | Self::Signer { detail }
            | Self::Chain { detail } => detail,
        }
    }
}

/// A trusted-root file that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    /// The file holds no trusted root.
    #[error("the trusted root file holds no trusted root")]
    Empty,
    /// A document is not a JSON Sigstore trusted root.
    #[error("trusted root {index} is not a Sigstore trusted root: {detail}")]
    Parse {
        /// 1-based position of the document in the file.
        index: usize,
        /// What the parser said.
        detail: String,
    },
    /// A trusted root parses but its keys or certificates are unusable.
    #[error("trusted root {index} is unusable: {detail}")]
    Unusable {
        /// 1-based position of the document in the file.
        index: usize,
        /// What the verifier said.
        detail: String,
    },
}

/// The validity window of a key or certificate authority of a trusted root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValidity {
    /// First instant the key is valid.
    pub from: jiff::Timestamp,
    /// Last instant the key is valid; `None` while no end is announced.
    pub until: Option<jiff::Timestamp>,
}

/// One parsed trusted root with its verifier.
struct Root {
    verifier: Verifier,
    /// Whether the root lists certificate-transparency logs; without any, certificates carry
    /// no SCT (GitHub's own instance) and the SCT check is skipped.
    has_ct_logs: bool,
}

/// The trusted roots of a trusted-root file, parsed once.
pub struct TrustedRoots {
    first: Root,
    rest: Vec<Root>,
    newest_key: Option<KeyValidity>,
}

impl fmt::Debug for TrustedRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedRoots")
            .field("roots", &(1 + self.rest.len()))
            .field("newest_key", &self.newest_key)
            .finish()
    }
}

impl TrustedRoots {
    /// Parses a trusted-root file: one JSON trusted root, or several in a row (one per line
    /// as `gh attestation trusted-root` writes them). A bundle verifies when it verifies
    /// against any of them.
    pub fn parse(bytes: &[u8]) -> Result<Self, RootError> {
        let documents = serde_json::Deserializer::from_slice(bytes).into_iter::<TrustedRoot>();
        let mut roots = Vec::new();
        let mut newest_key: Option<KeyValidity> = None;
        for (position, document) in documents.enumerate() {
            let index = position + 1;
            let root = document.map_err(|e| RootError::Parse {
                index,
                detail: one_line(e),
            })?;
            let verifier = Verifier::new(&root).map_err(|e| RootError::Unusable {
                index,
                detail: one_line(e),
            })?;
            newest_key = newer(newest_key, newest_key_of(&root));
            roots.push(Root {
                verifier,
                has_ct_logs: !root.ctlogs.is_empty(),
            });
        }
        let mut roots = roots.into_iter();
        let first = roots.next().ok_or(RootError::Empty)?;
        Ok(Self {
            first,
            rest: roots.collect(),
            newest_key,
        })
    }

    /// The validity of the newest key of the file: the one of every log, certificate
    /// authority and timestamp authority that starts last. `None` when the roots list no key.
    /// List shows it so an operator sees a rotation coming.
    pub fn newest_key(&self) -> Option<KeyValidity> {
        self.newest_key
    }
}

/// The key of `root` whose validity starts last.
fn newest_key_of(root: &TrustedRoot) -> Option<KeyValidity> {
    let windows = root
        .tlogs
        .iter()
        .map(|log| log.public_key.valid_for)
        .chain(root.ctlogs.iter().map(|log| log.public_key.valid_for))
        .chain(root.certificate_authorities.iter().map(|ca| ca.valid_for))
        .chain(root.timestamp_authorities.iter().map(|tsa| tsa.valid_for));
    windows
        .map(|window| match window {
            Some(range) => KeyValidity {
                from: range.start,
                until: range.end,
            },
            None => KeyValidity {
                from: jiff::Timestamp::MIN,
                until: None,
            },
        })
        .max_by_key(|key| key.from)
}

/// The key of `a` and `b` whose validity starts last; `a` when equal.
fn newer(a: Option<KeyValidity>, b: Option<KeyValidity>) -> Option<KeyValidity> {
    match (a, b) {
        (Some(a), Some(b)) if b.from > a.from => Some(b),
        (Some(a), _) => Some(a),
        (None, b) => b,
    }
}

/// What [`verify`] checks a bundle against.
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// The bundle file's bytes.
    pub bundle: &'a [u8],
    /// The trusted roots.
    pub roots: &'a TrustedRoots,
    /// The SHA-256 of the downloaded tar.
    pub tar_digest: &'a Digest,
    /// The configured signer identity of the service.
    pub signer: &'a Signer,
    /// The service's `artifact_name` pattern (one `*`).
    pub artifact_name: &'a str,
}

/// A bundle that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The earliest verified time of the signature (log integration or timestamp).
    pub signed_time: jiff::Timestamp,
    /// The name of the in-toto subject that matched.
    pub subject_name: String,
}

/// Verifies a release's bundle: see the crate documentation for the order of the checks.
/// When no trusted root accepts the bundle, the error is the one of the root that got
/// furthest (a signer error beats a chain error).
pub fn verify(input: &VerifyInput<'_>) -> Result<Verified, VerifyError> {
    let bundle: Bundle = serde_json::from_slice(input.bundle).map_err(invalid)?;
    let subject_name = check_subject(&bundle, input.artifact_name, input.tar_digest)?;
    let digest = Sha256Hash::from_hex(input.tar_digest.hex()).map_err(subject)?;
    let has_log_entry = !bundle.verification_material.tlog_entries.is_empty();
    let attempt =
        |root: &Root| verify_with_root(root, &bundle, digest, has_log_entry, input.signer);

    let first = attempt(&input.roots.first);
    let outcome = input
        .roots
        .rest
        .iter()
        .fold(first, |outcome, root| match outcome {
            Ok(_) => outcome,
            Err(earlier) => attempt(root).map_err(|later| furthest(earlier, later)),
        });
    outcome.map(|signed_time| Verified {
        signed_time,
        subject_name,
    })
}

/// The error that got furthest: a later signer error replaces an earlier chain error, every
/// other pair keeps the earlier one.
fn furthest(earlier: VerifyError, later: VerifyError) -> VerifyError {
    if matches!(later, VerifyError::Signer { .. }) && !matches!(earlier, VerifyError::Signer { .. })
    {
        later
    } else {
        earlier
    }
}

/// The statement a DSSE envelope signs: the fields this program reads.
#[derive(Deserialize)]
struct Statement {
    #[serde(rename = "_type")]
    kind: String,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    subject: Vec<StatementSubject>,
}

/// One subject of a statement.
#[derive(Deserialize)]
struct StatementSubject {
    #[serde(default)]
    name: String,
    #[serde(default)]
    digest: std::collections::BTreeMap<String, String>,
}

/// Section 3.3 step 3: the name of the subject with the tar's SHA-256 and a name matching
/// `pattern`, in a SLSA provenance v1 in-toto statement.
fn check_subject(bundle: &Bundle, pattern: &str, tar: &Digest) -> Result<String, VerifyError> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(subject(
            "the bundle holds a message signature, not an in-toto attestation",
        ));
    };
    ensure(
        envelope.payload_type == IN_TOTO_PAYLOAD_TYPE,
        subject,
        format!(
            "the envelope's payload type is {:?}, not an in-toto statement",
            envelope.payload_type
        ),
    )?;
    let statement: Statement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|e| subject(format!("the payload is not an in-toto statement: {e}")))?;
    ensure(
        statement.kind == IN_TOTO_STATEMENT_V1,
        subject,
        format!(
            "the statement type is {:?}, not {IN_TOTO_STATEMENT_V1:?}",
            statement.kind
        ),
    )?;
    ensure(
        statement.predicate_type == SLSA_PROVENANCE_V1,
        subject,
        format!(
            "the predicate type is {:?}, not {SLSA_PROVENANCE_V1:?}",
            statement.predicate_type
        ),
    )?;
    statement
        .subject
        .into_iter()
        .find(|s| {
            name_matches(pattern, &s.name)
                && s.digest
                    .get("sha256")
                    .is_some_and(|d| d.as_str() == tar.hex())
        })
        .map(|s| s.name)
        .ok_or_else(|| {
            subject(format!(
                "no subject named like {pattern:?} has the SHA-256 {}",
                tar.hex()
            ))
        })
}

/// Whether `name` matches `pattern`, a string with one `*` standing for any run of characters
/// (the config guarantees exactly one; without one the pattern must equal `name`).
fn name_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
        None => name == pattern,
    }
}

/// Section 3.3 step 1 against one root: the verified time of the signature.
fn verify_with_root(
    root: &Root,
    bundle: &Bundle,
    digest: Sha256Hash,
    has_log_entry: bool,
    signer: &Signer,
) -> Result<jiff::Timestamp, VerifyError> {
    let mut policy = VerificationPolicy::any_identity();
    if !has_log_entry {
        policy = policy.skip_tlog_unsafe();
    }
    if !root.has_ct_logs {
        policy = policy.skip_sct();
    }
    let result = root
        .verifier
        .verify(ArtifactDigest::sha256(digest), bundle, &policy)
        .map_err(chain)?;
    let signed_time = result
        .verified_timestamps()
        .iter()
        .min()
        .copied()
        .ok_or(chain("no verified time"))?;
    check_identity(&result, signer)?;
    Ok(signed_time)
}

/// Section 3.3 step 2: the certificate's identity against the configured signer.
fn check_identity(result: &VerificationResult, signer: &Signer) -> Result<(), VerifyError> {
    let claims = result
        .certificate()
        .map(|certificate| &certificate.ci_claims);
    let repository = format!("https://github.com/{}", signer.repository);
    let workflow = format!("{repository}/{}@{}", signer.workflow, signer.git_ref);

    let san = result.identity().map(|san| san.as_str());
    ensure(
        san == Some(workflow.as_str()),
        signer_error,
        format!("the certificate identity is {san:?}, not {workflow:?}"),
    )?;
    let issuer = result.issuer();
    ensure(
        issuer == Some(TOKEN_ISSUER),
        signer_error,
        format!("the token issuer is {issuer:?}, not {TOKEN_ISSUER:?}"),
    )?;
    let repository_id = claims.and_then(|c| c.source_repository_identifier.as_deref());
    ensure(
        repository_id == Some(signer.repository_id.as_str()),
        signer_error,
        format!(
            "the repository id is {repository_id:?}, not {:?}",
            signer.repository_id
        ),
    )?;
    let runner = claims.and_then(|c| c.runner_environment.as_deref());
    ensure(
        runner == Some(GITHUB_HOSTED),
        signer_error,
        format!("the runner environment is {runner:?}, not {GITHUB_HOSTED:?}"),
    )?;
    let trigger = claims.and_then(|c| c.build_trigger.as_deref());
    ensure(
        trigger.is_some_and(|t| signer.triggers.iter().any(|allowed| allowed == t)),
        signer_error,
        format!(
            "the build trigger is {trigger:?}, not one of {:?}",
            signer.triggers
        ),
    )?;
    let run = claims.and_then(|c| c.run_invocation_uri.as_deref());
    let runs = format!("{repository}/actions/runs/");
    ensure(
        run.is_some_and(|uri| uri.starts_with(&runs)),
        signer_error,
        format!("the run invocation URI is {run:?}, not under {runs:?}"),
    )
}

/// `Ok` when `ok`, else the error `make` builds from `detail`.
fn ensure(ok: bool, make: fn(String) -> VerifyError, detail: String) -> Result<(), VerifyError> {
    if ok { Ok(()) } else { Err(make(detail)) }
}

/// `detail` on one line: every run of white space (line breaks included) becomes a space.
fn one_line(detail: impl Display) -> String {
    detail
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn invalid(detail: impl Display) -> VerifyError {
    VerifyError::Invalid {
        detail: one_line(detail),
    }
}

fn subject(detail: impl Display) -> VerifyError {
    VerifyError::Subject {
        detail: one_line(detail),
    }
}

fn signer_error(detail: String) -> VerifyError {
    VerifyError::Signer {
        detail: one_line(detail),
    }
}

fn chain(detail: impl Display) -> VerifyError {
    VerifyError::Chain {
        detail: one_line(detail),
    }
}
