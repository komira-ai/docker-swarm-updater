//! The config file (docs/design.md section 2.3): one TOML file read at start. Unknown keys
//! are refused. [`Config::parse`] runs every check of section 2.3 that needs no file system;
//! the `trusted_root` ownership and mode check is the server's (it reads file metadata).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::claims::Claims;
use crate::ids::ServiceName;
use crate::oci::Platform;

/// A config that cannot be used. Each refusal names the offending key, e.g.
/// `service[1].caller[0].environment`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// The text is not TOML of the shape of [`Config`] (unknown keys included).
    #[error("config is not valid: {0}")]
    Syntax(#[from] toml::de::Error),
    /// A value breaks a rule of docs/design.md section 2.3.
    #[error("config key `{key}` is refused: {rule}")]
    Invalid {
        /// The key, with table indexes (`service[0].signer.ref`).
        key: String,
        /// The rule it breaks.
        rule: &'static str,
    },
}

fn invalid(key: impl Into<String>, rule: &'static str) -> ConfigError {
    ConfigError::Invalid {
        key: key.into(),
        rule,
    }
}

fn non_empty(key: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        Err(invalid(key, "must not be empty"))
    } else {
        Ok(())
    }
}

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
    #[serde(rename = "service", default)]
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
    #[serde(rename = "caller", default)]
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
    #[serde(default)]
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

impl Config {
    /// Parses `text` as the config file and runs every check of section 2.3 that needs no
    /// file system.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// The configured service called `name`, if any.
    pub fn service(&self, name: &ServiceName) -> Option<&ServiceConfig> {
        self.services.iter().find(|s| &s.name == name)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        non_empty("registry", &self.registry)?;
        if self.trusted_root.as_os_str().is_empty() {
            return Err(invalid("trusted_root", "must not be empty"));
        }
        for (i, host) in self.redirect_hosts.iter().enumerate() {
            if !is_bare_host(host) {
                return Err(invalid(
                    format!("redirect_hosts[{i}]"),
                    "must be a bare lower-case host name (no scheme, port, path or user info)",
                ));
            }
        }
        if self.services.is_empty() {
            return Err(invalid("service", "at least one service is required"));
        }
        let mut names = BTreeSet::new();
        let mut swarm_services = BTreeSet::new();
        for (i, service) in self.services.iter().enumerate() {
            service.validate(i)?;
            if !names.insert(service.name.as_str()) {
                return Err(invalid(
                    format!("service[{i}].name"),
                    "is used by an earlier service",
                ));
            }
            if !swarm_services.insert(service.swarm_service.as_str()) {
                return Err(invalid(
                    format!("service[{i}].swarm_service"),
                    "is already updated by an earlier service",
                ));
            }
        }
        Ok(())
    }
}

impl ServiceConfig {
    /// Whether `file_name` matches this service's `artifact_name` pattern.
    pub fn matches_artifact(&self, file_name: &str) -> bool {
        artifact_name_matches(&self.artifact_name, file_name)
    }

    /// Whether one of this service's callers equals `claims` on all six claims.
    pub fn has_caller(&self, claims: &Claims) -> bool {
        self.callers.iter().any(|c| claims.matches(c))
    }

    fn validate(&self, i: usize) -> Result<(), ConfigError> {
        let key = |field: &str| format!("service[{i}].{field}");
        non_empty(&key("swarm_service"), &self.swarm_service)?;
        non_empty(&key("repository"), &self.repository)?;
        if Platform::parse(&self.platform).is_err() {
            return Err(invalid(
                key("platform"),
                "must be os/architecture or os/architecture/variant",
            ));
        }
        non_empty(&key("artifact_url.owner"), &self.artifact_url.owner)?;
        non_empty(&key("artifact_url.repo"), &self.artifact_url.repo)?;
        if self.artifact_name.matches('*').count() != 1 {
            return Err(invalid(
                key("artifact_name"),
                "must contain exactly one `*`",
            ));
        }
        if self.artifact_name.contains('/') {
            return Err(invalid(key("artifact_name"), "must not contain `/`"));
        }
        self.signer.validate(&key("signer"))?;
        if self.callers.is_empty() {
            return Err(invalid(key("caller"), "at least one caller is required"));
        }
        for (j, caller) in self.callers.iter().enumerate() {
            caller.validate(&format!("service[{i}].caller[{j}]"))?;
        }
        Ok(())
    }
}

impl Signer {
    fn validate(&self, prefix: &str) -> Result<(), ConfigError> {
        non_empty(&format!("{prefix}.repository"), &self.repository)?;
        non_empty(&format!("{prefix}.repository_id"), &self.repository_id)?;
        non_empty(&format!("{prefix}.ref"), &self.git_ref)?;
        if !is_workflow_path(&self.workflow) {
            return Err(invalid(
                format!("{prefix}.workflow"),
                "must be a plain path under .github/workflows/ ending in .yml or .yaml",
            ));
        }
        if self.triggers.is_empty() {
            return Err(invalid(
                format!("{prefix}.triggers"),
                "at least one trigger is required",
            ));
        }
        for (k, trigger) in self.triggers.iter().enumerate() {
            non_empty(&format!("{prefix}.triggers[{k}]"), trigger)?;
        }
        Ok(())
    }
}

impl Caller {
    fn validate(&self, prefix: &str) -> Result<(), ConfigError> {
        let claims = [
            ("repository", &self.repository),
            ("repository_id", &self.repository_id),
            ("job_workflow_ref", &self.job_workflow_ref),
            ("ref", &self.git_ref),
            ("environment", &self.environment),
            ("runner_environment", &self.runner_environment),
        ];
        for (name, value) in claims {
            non_empty(&format!("{prefix}.{name}"), value)?;
        }
        Ok(())
    }
}

/// A path of plain characters under `.github/workflows/` ending in `.yml` or `.yaml`, with no
/// empty, `.` or `..` segment.
fn is_workflow_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(".github/workflows/") else {
        return false;
    };
    let plain = rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    let extension = rest.ends_with(".yml") || rest.ends_with(".yaml");
    let segments = rest.split('/').all(|s| !s.is_empty() && s != ".");
    plain && extension && segments && !rest.contains("..")
}

/// A DNS-style lower-case host name: dot-separated labels of 1 to 63 of `[a-z0-9-]`, none
/// starting or ending with `-`.
fn is_bare_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Whether `name` matches `pattern`, a string with exactly one `*`. The star stands for one or
/// more characters, none of them `/`. A pattern without exactly one `*` matches nothing.
pub fn artifact_name_matches(pattern: &str, name: &str) -> bool {
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return false;
    };
    if suffix.contains('*') {
        return false;
    }
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(star) = rest.strip_suffix(suffix) else {
        return false;
    };
    !star.is_empty() && !star.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
registry = "127.0.0.1:5000"
trusted_root = "/etc/docker-swarm-updater/trusted_root.json"
redirect_hosts = ["objects.githubusercontent.com", "release-assets.githubusercontent.com"]
keep_previous = 3
min_free_bytes = 10737418240

[[service]]
name = "app"
swarm_service = "app_server"
repository = "app"
platform = "linux/amd64"
artifact_url = { owner = "example-org", repo = "app" }
artifact_name = "app-*-linux-x86_64.image.tar"
max_image_bytes = 4294967296
signer = { repository = "example-org/app", repository_id = "123456789", workflow = ".github/workflows/artifacts.yml", ref = "refs/heads/main", triggers = ["push"] }
converge_timeout_secs = 0
  [[service.caller]]
  repository = "example-org/app"
  repository_id = "123456789"
  job_workflow_ref = "example-org/docker-swarm-updater/.github/workflows/deploy.yml@0123456789012345678901234567890123456789"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
"#;

    const SECOND: &str = r#"
[[service]]
name = "web"
swarm_service = "web_server"
repository = "web"
platform = "linux/arm64/v8"
artifact_url = { owner = "example-org", repo = "web" }
artifact_name = "web-*.tar"
signer = { repository = "example-org/web", repository_id = "2", workflow = ".github/workflows/artifacts.yaml", ref = "refs/heads/main", triggers = ["push", "workflow_dispatch"] }
  [[service.caller]]
  repository = "example-org/web"
  repository_id = "2"
  job_workflow_ref = "w@1"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
  [[service.caller]]
  repository = "example-org/web"
  repository_id = "2"
  job_workflow_ref = "w@2"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
"#;

    /// Replaces the first `from` of `GOOD` (or of `GOOD` followed by `SECOND`) with `to`.
    fn edited(from: &str, to: &str) -> String {
        let text = format!("{GOOD}{SECOND}");
        assert!(text.contains(from), "{from}");
        text.replacen(from, to, 1)
    }

    fn refused_key(text: &str) -> String {
        let message = Config::parse(text).unwrap_err().to_string();
        assert!(message.starts_with("config key `"), "{message}");
        message.split('`').nth(1).unwrap().to_owned()
    }

    #[test]
    fn the_design_example_parses() {
        let config = Config::parse(GOOD).unwrap();
        assert_eq!(config.registry, "127.0.0.1:5000");
        assert_eq!(config.keep_previous, 3);
        assert_eq!(config.services.len(), 1);
        let s = &config.services[0];
        assert_eq!(s.name.as_str(), "app");
        assert_eq!(s.max_image_bytes, Some(4_294_967_296));
        assert_eq!(s.converge_timeout_secs, 0);
        assert_eq!(s.signer.git_ref, "refs/heads/main");
        assert_eq!(s.callers[0].environment, "production");
    }

    #[test]
    fn optional_keys_default_and_two_services_parse() {
        let config = Config::parse(&format!("{GOOD}{SECOND}")).unwrap();
        assert_eq!(config.services.len(), 2);
        let web = &config.services[1];
        assert_eq!(web.max_image_bytes, None);
        assert_eq!(web.converge_timeout_secs, 0);
        assert_eq!(web.callers.len(), 2);
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(serde_json::from_str::<Config>(&json).unwrap(), config);
    }

    #[test]
    fn service_lookup() {
        let config = Config::parse(&format!("{GOOD}{SECOND}")).unwrap();
        let web = ServiceName::parse("web").unwrap();
        assert_eq!(config.service(&web).unwrap().swarm_service, "web_server");
        assert!(
            config
                .service(&ServiceName::parse("nope").unwrap())
                .is_none()
        );
    }

    #[test]
    fn bad_toml_unknown_keys_and_missing_keys_are_syntax_errors() {
        let cases = [
            "registry = ".to_owned(),
            "".to_owned(),
            edited("keep_previous = 3", "keep_previous = 3\nsurprise = 1"),
            edited(
                "platform = \"linux/amd64\"",
                "platform = \"linux/amd64\"\nsurprise = 1",
            ),
            edited("[[service]]\nname = \"app\"", "[[service]]\nname = \"App\""),
            edited(
                "  [[service.caller]]\n  repository = \"example-org/app\"",
                "  [[service.caller]]\n  extra = 1\n  repository = \"example-org/app\"",
            ),
        ];
        for text in cases {
            let err = Config::parse(&text).unwrap_err();
            assert!(matches!(err, ConfigError::Syntax(_)), "{err:?}");
            assert!(err.to_string().starts_with("config is not valid"));
        }
        let err = Config::parse(&edited(
            "keep_previous = 3",
            "keep_previous = 3\nsurprise = 1",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("surprise"));
    }

    #[test]
    fn no_service_is_refused_naming_the_key() {
        let head: String = GOOD.split("[[service]]").next().unwrap().to_owned();
        assert_eq!(refused_key(&head), "service");
        assert_eq!(refused_key(&format!("{head}service = []")), "service");
    }

    #[test]
    fn top_level_values_are_checked() {
        assert_eq!(
            refused_key(&edited("registry = \"127.0.0.1:5000\"", "registry = \"\"")),
            "registry"
        );
        assert_eq!(
            refused_key(&edited(
                "trusted_root = \"/etc/docker-swarm-updater/trusted_root.json\"",
                "trusted_root = \"\""
            )),
            "trusted_root"
        );
    }

    #[test]
    fn redirect_hosts_must_be_bare_host_names() {
        let bad = [
            "https://objects.githubusercontent.com",
            "objects.githubusercontent.com:443",
            "objects.githubusercontent.com/x",
            "user@objects.example",
            "Objects.Example",
            "",
            ".example.com",
            "example..com",
            "example.com.",
            "-a.example.com",
            "a-.example.com",
            "exa mple.com",
            &"a".repeat(64),
            &format!("{0}.{0}.{0}.{0}.{0}", "a".repeat(60)),
        ];
        for host in bad {
            let text = edited(
                "[\"objects.githubusercontent.com\", ",
                &format!("[{host:?}, "),
            );
            assert_eq!(refused_key(&text), "redirect_hosts[0]", "{host:?}");
        }
        let text = edited("\"release-assets.githubusercontent.com\"", "\"https://x\"");
        assert_eq!(refused_key(&text), "redirect_hosts[1]");
        let ok = edited(
            "redirect_hosts = [\"objects.githubusercontent.com\", \"release-assets.githubusercontent.com\"]",
            "redirect_hosts = [\"localhost\", \"a-b.c1.example\", \"203.0.113.10\"]",
        );
        assert!(Config::parse(&ok).is_ok());
        let none = edited(
            "redirect_hosts = [\"objects.githubusercontent.com\", \"release-assets.githubusercontent.com\"]",
            "redirect_hosts = []",
        );
        assert!(Config::parse(&none).is_ok());
    }

    #[test]
    fn duplicate_services_are_refused_at_the_second_one() {
        let dup_name = edited("name = \"web\"", "name = \"app\"");
        assert_eq!(refused_key(&dup_name), "service[1].name");
        let dup_swarm = edited(
            "swarm_service = \"web_server\"",
            "swarm_service = \"app_server\"",
        );
        assert_eq!(refused_key(&dup_swarm), "service[1].swarm_service");
    }

    #[test]
    fn empty_service_strings_are_refused_naming_the_key() {
        let cases = [
            (
                "swarm_service = \"app_server\"",
                "swarm_service = \"\"",
                "service[0].swarm_service",
            ),
            (
                "repository = \"app\"\nplatform",
                "repository = \"\"\nplatform",
                "service[0].repository",
            ),
            (
                "owner = \"example-org\", repo = \"app\"",
                "owner = \"\", repo = \"app\"",
                "service[0].artifact_url.owner",
            ),
            (
                "owner = \"example-org\", repo = \"app\"",
                "owner = \"example-org\", repo = \"\"",
                "service[0].artifact_url.repo",
            ),
            (
                "swarm_service = \"web_server\"",
                "swarm_service = \"\"",
                "service[1].swarm_service",
            ),
        ];
        for (from, to, key) in cases {
            assert_eq!(refused_key(&edited(from, to)), key);
        }
    }

    #[test]
    fn platform_must_be_os_arch_or_os_arch_variant() {
        for bad in ["linux", "linux/", "linux/amd64/v8/x", "Linux/amd64", ""] {
            let text = edited("platform = \"linux/amd64\"", &format!("platform = {bad:?}"));
            assert_eq!(refused_key(&text), "service[0].platform", "{bad:?}");
        }
    }

    #[test]
    fn artifact_name_needs_exactly_one_star_and_no_slash() {
        for bad in ["app.tar", "app-*-*.tar", "**", "a/*.tar", "*/a"] {
            let text = edited(
                "artifact_name = \"app-*-linux-x86_64.image.tar\"",
                &format!("artifact_name = {bad:?}"),
            );
            assert_eq!(refused_key(&text), "service[0].artifact_name", "{bad:?}");
        }
        for good in ["*", "*.tar", "app-*"] {
            let text = edited(
                "artifact_name = \"app-*-linux-x86_64.image.tar\"",
                &format!("artifact_name = {good:?}"),
            );
            assert!(Config::parse(&text).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn artifact_name_matcher() {
        let p = "app-*-linux-x86_64.image.tar";
        assert!(artifact_name_matches(p, "app-1.4.2-linux-x86_64.image.tar"));
        assert!(artifact_name_matches(p, "app-v1-linux-x86_64.image.tar"));
        assert!(artifact_name_matches(p, "app-a-linux-x86_64.image.tar"));
        // The star stands for at least one character.
        assert!(!artifact_name_matches(p, "app--linux-x86_64.image.tar"));
        // And no slash.
        assert!(!artifact_name_matches(p, "app-1/2-linux-x86_64.image.tar"));
        // Prefix, suffix and overlap.
        assert!(!artifact_name_matches(
            p,
            "lib-1.4.2-linux-x86_64.image.tar"
        ));
        assert!(!artifact_name_matches(
            p,
            "app-1.4.2-linux-x86_64.image.tar.sigstore.json"
        ));
        assert!(!artifact_name_matches(p, "app-linux-x86_64.image.tar"));
        assert!(!artifact_name_matches("a*a", "a"));
        assert!(artifact_name_matches("*", "x"));
        assert!(!artifact_name_matches("*", ""));
        assert!(artifact_name_matches("a*", "ab"));
        assert!(!artifact_name_matches("a*", "a"));
        // A pattern without exactly one star matches nothing.
        assert!(!artifact_name_matches("app.tar", "app.tar"));
        assert!(!artifact_name_matches("a*b*c", "aXbYc"));
    }

    #[test]
    fn service_matches_artifact_names_and_bundle_names() {
        let config = Config::parse(GOOD).unwrap();
        let s = &config.services[0];
        assert!(s.matches_artifact("app-1-linux-x86_64.image.tar"));
        assert!(!s.matches_artifact("app-1-linux-aarch64.image.tar"));
    }

    #[test]
    fn signer_values_are_checked() {
        let cases = [
            (
                "repository = \"example-org/app\", repository_id",
                "repository = \"\", repository_id",
                "service[0].signer.repository",
            ),
            (
                "repository_id = \"123456789\", workflow",
                "repository_id = \"\", workflow",
                "service[0].signer.repository_id",
            ),
            (
                "ref = \"refs/heads/main\", triggers",
                "ref = \"\", triggers",
                "service[0].signer.ref",
            ),
            (
                "triggers = [\"push\"]",
                "triggers = []",
                "service[0].signer.triggers",
            ),
            (
                "triggers = [\"push\"]",
                "triggers = [\"\"]",
                "service[0].signer.triggers[0]",
            ),
            (
                "triggers = [\"push\", \"workflow_dispatch\"]",
                "triggers = [\"push\", \"\"]",
                "service[1].signer.triggers[1]",
            ),
        ];
        for (from, to, key) in cases {
            assert_eq!(refused_key(&edited(from, to)), key);
        }
        let no_triggers = edited(", triggers = [\"push\"]", "");
        assert_eq!(refused_key(&no_triggers), "service[0].signer.triggers");
    }

    #[test]
    fn signer_workflow_must_be_a_plain_path_under_the_workflows_directory() {
        let bad = [
            "",
            "artifacts.yml",
            ".github/workflows/",
            ".github/workflows/artifacts",
            ".github/workflows/artifacts.yml.txt",
            ".github/workflow/artifacts.yml",
            "/.github/workflows/artifacts.yml",
            "x/.github/workflows/artifacts.yml",
            ".github/workflows/../artifacts.yml",
            ".github/workflows/a/../b.yml",
            ".github/workflows/..yml",
            ".github/workflows/a..b.yml",
            ".github/workflows//a.yml",
            ".github/workflows/./a.yml",
            ".github/workflows/a.yml/",
            ".github/workflows/a%2e.yml",
            ".github/workflows/a b.yml",
            ".github/workflows/a\\b.yml",
        ];
        for workflow in bad {
            let text = edited(
                "workflow = \".github/workflows/artifacts.yml\"",
                &format!("workflow = {workflow:?}"),
            );
            assert_eq!(
                refused_key(&text),
                "service[0].signer.workflow",
                "{workflow:?}"
            );
        }
        for good in [
            ".github/workflows/a.yml",
            ".github/workflows/Build_1-x.yaml",
            ".github/workflows/sub/a.yml",
        ] {
            let text = edited(
                "workflow = \".github/workflows/artifacts.yml\"",
                &format!("workflow = {good:?}"),
            );
            assert!(Config::parse(&text).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_service_needs_a_caller() {
        let start = GOOD.find("  [[service.caller]]").unwrap();
        let no_caller = &GOOD[..start];
        assert_eq!(refused_key(no_caller), "service[0].caller");
        let second_without = format!(
            "{GOOD}{}",
            SECOND.split("  [[service.caller]]").next().unwrap()
        );
        assert_eq!(refused_key(&second_without), "service[1].caller");
    }

    #[test]
    fn every_caller_claim_must_be_non_empty() {
        let claims = [
            "repository",
            "repository_id",
            "job_workflow_ref",
            "ref",
            "environment",
            "runner_environment",
        ];
        for claim in claims {
            let mut text = format!("{GOOD}{SECOND}");
            let marker = format!("  {claim} = ");
            let at = text.find(&marker).unwrap() + marker.len();
            let end = at + text[at..].find('\n').unwrap();
            text.replace_range(at..end, "\"\"");
            assert_eq!(refused_key(&text), format!("service[0].caller[0].{claim}"));
        }
    }

    #[test]
    fn a_later_caller_is_named_by_its_index() {
        let text = edited(
            "job_workflow_ref = \"w@2\"\n  ref = \"refs/heads/main\"\n  environment = \"production\"",
            "job_workflow_ref = \"w@2\"\n  ref = \"refs/heads/main\"\n  environment = \"\"",
        );
        assert_eq!(refused_key(&text), "service[1].caller[1].environment");
    }

    #[test]
    fn has_caller_needs_all_six_claims_of_one_entry() {
        use base64::Engine as _;
        let config = Config::parse(&format!("{GOOD}{SECOND}")).unwrap();
        let claims = |workflow: &str| {
            let json = format!(
                r#"{{"repository":"example-org/web","repository_id":"2","job_workflow_ref":"{workflow}","ref":"refs/heads/main","environment":"production","runner_environment":"github-hosted","jti":"j","exp":1}}"#
            );
            Claims::from_header(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
                .unwrap()
        };
        let web = &config.services[1];
        assert!(web.has_caller(&claims("w@1")));
        assert!(web.has_caller(&claims("w@2")));
        assert!(!web.has_caller(&claims("w@3")));
        assert!(!config.services[0].has_caller(&claims("w@1")));
    }
}
