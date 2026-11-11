//! `dsu-deploy`: the client the reusable workflow `.github/workflows/deploy.yml` builds from
//! its own commit and runs (docs/design.md section 7). It asks docker-swarm-updater, through
//! the fronting proxy at `--endpoint`, to deploy one release of one service and follows the
//! deploy to its end; see [`client`] for the steps.
//!
//! Every setting is a flag. The one value read from the environment is
//! `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, the secret GitHub gives a job that may mint OIDC tokens; it
//! is never printed.
//!
//! Exit codes: 0 when the deploy ends `converged`; 1 when it was refused, ended in another
//! state, or the wait ran out; 2 when the command line or the environment is wrong.

pub mod client;
pub mod http;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;
use clap::builder::NonEmptyStringValueParser;
use dsu_core::api::{DeployRequest, RequestSigner};
use dsu_core::ids::{Digest, ServiceName};

use crate::client::{Clock, Plan, TokenSource};
use crate::http::UreqHttp;

/// The environment variable holding the bearer of GitHub's token request.
pub const TOKEN_REQUEST_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

/// The command line.
#[derive(Debug, Parser)]
#[command(
    name = "dsu-deploy",
    about = "Asks docker-swarm-updater to deploy one release of one service and waits for the outcome"
)]
pub struct Cli {
    /// The deploy front: `http://host[:port]` or `https://host[:port]`, no path.
    #[arg(long, value_parser = parse_endpoint)]
    pub endpoint: String,
    /// The configured service to deploy.
    #[arg(long, value_parser = ServiceName::parse)]
    pub service: ServiceName,
    /// The manifest digest of the image, `sha256:<64 hex>`.
    #[arg(long, value_parser = Digest::parse)]
    pub image_digest: Digest,
    /// The release URL of the image tar.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub image_url: String,
    /// The release URL of the tar's Sigstore bundle.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub bundle_url: String,
    /// The signer's repository, `owner/repo`.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub signer_repository: String,
    /// The signing workflow's path, e.g. `.github/workflows/artifacts.yml`.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub signer_workflow: String,
    /// The ref the signing workflow ran on, e.g. `refs/heads/main`.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub signer_ref: String,
    /// The release version, for the record and the log (at most 128 bytes).
    #[arg(long)]
    pub version: String,
    /// The audience every OIDC token is minted for.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    pub audience: String,
    /// GitHub's token endpoint, `ACTIONS_ID_TOKEN_REQUEST_URL`.
    #[arg(long)]
    pub id_token_url: url::Url,
    /// Minutes to wait for a final state; 0 waits however long the deploy takes.
    #[arg(long, default_value_t = 60)]
    pub wait_minutes: u32,
}

/// Why `--endpoint` was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The text is not a URL.
    #[error("{text:?}: {reason}")]
    NotAUrl {
        /// The flag's value.
        text: String,
        /// The URL parser's error.
        reason: String,
    },
    /// The scheme is neither `http` nor `https`.
    #[error("{text:?}: the scheme must be http or https")]
    Scheme {
        /// The flag's value.
        text: String,
    },
    /// The URL has a user, a path, a query or a fragment.
    #[error("{text:?}: give the scheme, host and port only (no user, path, query or fragment)")]
    NotBare {
        /// The flag's value.
        text: String,
    },
}

/// Why the flags do not make a deploy request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The updater's own request parser refuses the request (only `--version` can make it
    /// refuse: over 128 bytes, or a control character).
    #[error("--version: {0}")]
    Version(String),
}

/// Parses `--endpoint`: `http` or `https`, a host, an optional port, and nothing else.
/// Returns it without a trailing slash.
pub fn parse_endpoint(text: &str) -> Result<String, EndpointError> {
    let url = url::Url::parse(text).map_err(|e| EndpointError::NotAUrl {
        text: text.to_owned(),
        reason: e.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(EndpointError::Scheme {
            text: text.to_owned(),
        });
    }
    let bare = url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    if !bare {
        return Err(EndpointError::NotBare {
            text: text.to_owned(),
        });
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

impl Cli {
    /// The plan of the run, with `bearer` as the token request's bearer. A `version` the
    /// updater would refuse (over 128 bytes, a control character) is refused here.
    pub fn plan(self, bearer: String) -> Result<Plan, PlanError> {
        let request = DeployRequest {
            image_digest: self.image_digest,
            image_url: self.image_url,
            bundle_url: self.bundle_url,
            signer: Some(RequestSigner {
                repository: self.signer_repository,
                workflow: self.signer_workflow,
                git_ref: self.signer_ref,
            }),
            version: self.version,
            allow_older: false,
        };
        // The updater's own parser, so a request it would refuse as 400 is refused before
        // anything is sent.
        let text = serde_json::to_vec(&request).unwrap_or_default();
        let request = DeployRequest::from_json(&text)
            .map_err(|e| PlanError::Version(e.detail().to_owned()))?;
        Ok(Plan {
            endpoint: self.endpoint,
            service: self.service,
            request,
            tokens: TokenSource {
                url: self.id_token_url,
                bearer,
                audience: self.audience,
            },
            wait: match self.wait_minutes {
                0 => None,
                m => Some(Duration::from_secs(u64::from(m) * 60)),
            },
        })
    }
}

/// The real clock.
#[derive(Debug)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// A clock whose [`Clock::elapsed`] counts from now.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Runs the command line `args` (with the program name) and returns the exit code; see the
/// crate documentation.
pub fn main(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let bearer = std::env::var(TOKEN_REQUEST_ENV).ok();
    run(
        args,
        bearer,
        &UreqHttp::new(),
        &SystemClock::start(),
        &mut out,
    )
}

/// [`main`] with its inputs given: `bearer` is the value of [`TOKEN_REQUEST_ENV`]. A failure is
/// written to `out` as a GitHub Actions error annotation.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    bearer: Option<String>,
    http: &dyn client::Http,
    clock: &dyn Clock,
    out: &mut dyn Write,
) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = write!(out, "{e}");
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };
    let Some(bearer) = bearer.filter(|b| !b.is_empty()) else {
        let _ = writeln!(
            out,
            "::error::{TOKEN_REQUEST_ENV} is not set: the job needs `permissions: id-token: write`"
        );
        return ExitCode::from(2);
    };
    let plan = match cli.plan(bearer) {
        Ok(plan) => plan,
        Err(e) => {
            let _ = writeln!(out, "::error::{e}");
            return ExitCode::from(2);
        }
    };
    match client::run(&plan, http, clock, out) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(out, "::error::{e}");
            ExitCode::FAILURE
        }
    }
}
