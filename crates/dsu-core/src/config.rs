//! The config file (docs/design.md section 2.3): one TOML file read at start. Unknown keys
//! are refused. [`Config::parse`] runs every check of section 2.3 that needs no file system;
//! the `trusted_root` ownership and mode check is the server's (it reads file metadata).

use serde::{Deserialize, Serialize};

use crate::ids::ServiceName;

/// The whole config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `host:port` of the registry the updater pushes to and names in image references.
    pub registry: String,
    /// Path of the Sigstore trusted-root file (one JSON document, or one per line as
    /// `gh attestation trusted-root` writes).
    pub trusted_root: std::path::PathBuf,
    /// Bare host names a release download may be redirected to.
    pub redirect_hosts: Vec<String>,
    /// Converged digests kept per service besides the running one and Swarm's previous spec.
    pub keep_previous: u32,
    /// A deploy is refused (`fetch_failed`) if the state directory's disk would go below this.
    pub min_free_bytes: u64,
    /// The services this updater may deploy (TOML `[[service]]`).
    #[serde(rename = "service")]
    pub services: Vec<ServiceConfig>,
}

/// One `[[service]]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// The `{service}` of the API.
    pub name: ServiceName,
    /// The Swarm service it updates.
    pub swarm_service: String,
    /// The registry repository name.
    pub repository: String,
    /// `os/architecture` the tar's image config must name, e.g. `linux/amd64`.
    pub platform: String,
    /// The GitHub owner and repository whose release assets may be fetched.
    pub artifact_url: ArtifactUrl,
    /// A pattern with exactly one `*`: the in-toto subject name and the URL's file name
    /// must match it.
    pub artifact_name: String,
    /// Optional cap on the image tar's size; absent means no cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_image_bytes: Option<u64>,
    /// The identity that must have signed the release.
    pub signer: Signer,
    /// Seconds to wait for Swarm; 0 waits however long the service's drain takes.
    #[serde(default)]
    pub converge_timeout_secs: u64,
    /// The callers allowed to act on this service (TOML `[[service.caller]]`), at least one.
    #[serde(rename = "caller")]
    pub callers: Vec<Caller>,
}

/// The release location of a service's artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUrl {
    /// The GitHub owner (user or organisation).
    pub owner: String,
    /// The GitHub repository name.
    pub repo: String,
}

/// The configured signer identity of a service (section 3.3 step 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    /// `owner/repo` of the signing workflow's repository.
    pub repository: String,
    /// The numeric repository id (a renamed or re-created repository is refused).
    pub repository_id: String,
    /// The signing workflow's path, under `.github/workflows/`.
    pub workflow: String,
    /// The git ref the workflow ran on, e.g. `refs/heads/main`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The build triggers accepted, e.g. `["push"]`.
    pub triggers: Vec<String>,
}

/// One `[[service.caller]]` entry: every claim must equal the token's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    /// The `repository` claim.
    pub repository: String,
    /// The `repository_id` claim.
    pub repository_id: String,
    /// The `job_workflow_ref` claim.
    pub job_workflow_ref: String,
    /// The `ref` claim.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The `environment` claim.
    pub environment: String,
    /// The `runner_environment` claim.
    pub runner_environment: String,
}
