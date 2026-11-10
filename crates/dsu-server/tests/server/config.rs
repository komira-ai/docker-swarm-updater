//! The `config` row of docs/design.md section 6: each refusal of section 2.3 and
//! `--proxy-uid 0` refuse the start, naming the key or the flag.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use dsu_server::cli::{ServeArgs, serve};
use dsu_server::startup::{StartError, load_config, trusted_root_problem};
use dsu_testkit::mint::Authority;

use crate::harness::{REGISTRY, config_text, write_trusted_root};

struct Files {
    dir: tempfile::TempDir,
}

impl Files {
    fn new() -> Files {
        let dir = tempfile::tempdir().unwrap();
        write_trusted_root(
            &dir.path().join("root.json"),
            &Authority::public_good().trusted_root_json(),
        );
        Files { dir }
    }

    fn root(&self) -> std::path::PathBuf {
        self.dir.path().join("root.json")
    }

    /// Loads the harness config with `edit` applied to its text; the message of the refusal.
    fn refused(&self, edit: impl FnOnce(String) -> String) -> String {
        let path = self.dir.path().join("config.toml");
        std::fs::write(&path, edit(config_text(&self.root(), REGISTRY))).unwrap();
        load_config(&path).unwrap_err().to_string()
    }
}

fn replace_first(text: String, from: &str, to: &str) -> String {
    assert!(text.contains(from), "{from}");
    text.replacen(from, to, 1)
}

#[test]
fn the_good_config_loads() {
    let files = Files::new();
    let path = files.dir.path().join("config.toml");
    std::fs::write(&path, config_text(&files.root(), REGISTRY)).unwrap();
    let loaded = load_config(&path).unwrap();
    assert_eq!(loaded.config.services.len(), 3);
    assert!(loaded.roots.newest_key().is_some());
}

#[test]
fn each_refusal_of_section_2_3_names_the_key() {
    let files = Files::new();
    let cases: [(&str, &str, &str, &str); 7] = [
        (
            "two services on one swarm_service",
            "swarm_service = \"web_server\"",
            "swarm_service = \"app_server\"",
            "service[1].swarm_service",
        ),
        (
            "a caller with an empty claim",
            "environment = \"production\"",
            "environment = \"\"",
            "service[0].caller[0].environment",
        ),
        (
            "a workflow outside .github/workflows",
            "workflow = \".github/workflows/artifacts.yml\"",
            "workflow = \"ci/artifacts.yml\"",
            "service[0].signer.workflow",
        ),
        (
            "an artifact_name with no star",
            "artifact_name = \"app-*-linux-x86_64.image.tar\"",
            "artifact_name = \"app.tar\"",
            "service[0].artifact_name",
        ),
        (
            "an artifact_name with two stars",
            "artifact_name = \"app-*-linux-x86_64.image.tar\"",
            "artifact_name = \"app-*-*.tar\"",
            "service[0].artifact_name",
        ),
        (
            "a redirect host that is not bare",
            "redirect_hosts = [\"objects.githubusercontent.com\"]",
            "redirect_hosts = [\"https://objects.githubusercontent.com\"]",
            "redirect_hosts[0]",
        ),
        (
            "an unknown key",
            "keep_previous = 3",
            "keep_previous = 3\nsurprise = 1",
            "surprise",
        ),
    ];
    for (what, from, to, key) in cases {
        let message = files.refused(|text| replace_first(text, from, to));
        assert!(message.contains(key), "{what}: {message}");
    }
}

#[test]
fn the_trusted_root_must_be_a_file_the_updater_may_trust() {
    let files = Files::new();
    let key = "trusted_root";
    // Writable by group or by other.
    for mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(files.root(), std::fs::Permissions::from_mode(mode)).unwrap();
        let message = files.refused(|t| t);
        assert!(
            message.contains(key) && message.contains("writable by group or other"),
            "{mode:o}: {message}"
        );
    }
    // Not a regular file.
    std::fs::remove_file(files.root()).unwrap();
    std::fs::create_dir(files.root()).unwrap();
    let message = files.refused(|t| t);
    assert!(
        message.contains(key) && message.contains("not a regular file"),
        "{message}"
    );
    // Missing.
    std::fs::remove_dir(files.root()).unwrap();
    let message = files.refused(|t| t);
    assert!(
        message.contains(key) && message.contains("No such file"),
        "{message}"
    );
    // A file the verifier cannot use: not JSON, and empty.
    for content in ["not json", ""] {
        write_trusted_root(&files.root(), content);
        let message = files.refused(|t| t);
        assert!(message.contains(key), "{content:?}: {message}");
    }
    // A mode of 0600 and 0644 is fine.
    for mode in [0o600, 0o644, 0o444] {
        write_trusted_root(&files.root(), &Authority::public_good().trusted_root_json());
        std::fs::set_permissions(files.root(), std::fs::Permissions::from_mode(mode)).unwrap();
        let path = files.dir.path().join("config.toml");
        std::fs::write(&path, config_text(&files.root(), REGISTRY)).unwrap();
        assert!(load_config(&path).is_ok(), "{mode:o}");
    }
}

#[test]
fn the_owner_of_the_trusted_root_is_root_or_the_updaters_user() {
    assert_eq!(trusted_root_problem(true, 0, 0o644, 1000), None);
    assert_eq!(trusted_root_problem(true, 1000, 0o644, 1000), None);
    assert!(
        trusted_root_problem(true, 1001, 0o644, 1000)
            .unwrap()
            .contains("owned by neither")
    );
    assert!(
        trusted_root_problem(false, 0, 0o644, 1000)
            .unwrap()
            .contains("regular file")
    );
    assert!(
        trusted_root_problem(true, 0, 0o620, 1000)
            .unwrap()
            .contains("writable")
    );
    assert!(
        trusted_root_problem(true, 0, 0o602, 1000)
            .unwrap()
            .contains("writable")
    );
}

#[test]
fn an_unreadable_config_file_names_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let error = load_config(&dir.path().join("missing.toml")).unwrap_err();
    assert!(matches!(error, StartError::ConfigRead { .. }));
    assert!(error.to_string().contains("--config"));
}

fn serve_args(files: &Files) -> ServeArgs {
    let path = files.dir.path().join("config.toml");
    std::fs::write(&path, config_text(&files.root(), REGISTRY)).unwrap();
    ServeArgs {
        config: path,
        socket: files.dir.path().join("run").join("dsu.sock"),
        socket_group: crate::harness::current_gid(),
        proxy_uid: 1234,
        state_dir: files.dir.path().join("state"),
        docker: files.dir.path().join("docker.sock"),
        allow_local_operator: false,
        ca_file: None,
    }
}

async fn refused_start(args: ServeArgs) -> String {
    serve(args, || panic!("must not be ready"))
        .await
        .unwrap_err()
        .to_string()
}

#[tokio::test]
async fn proxy_uid_zero_is_refused_naming_the_flag() {
    let files = Files::new();
    let mut args = serve_args(&files);
    args.proxy_uid = 0;
    let message = refused_start(args).await;
    assert!(message.contains("--proxy-uid"), "{message}");
    assert!(
        !files.dir.path().join("state").exists(),
        "nothing was started"
    );
}

#[tokio::test]
async fn a_bad_config_or_ca_file_or_docker_refuses_the_start() {
    let files = Files::new();
    // The config is checked before anything is opened.
    let args = serve_args(&files);
    std::fs::write(&args.config, "registry = ").unwrap();
    let message = refused_start(args).await;
    assert!(message.contains("config"), "{message}");
    // --ca-file: missing, and without a certificate.
    let mut args = serve_args(&files);
    args.ca_file = Some(files.dir.path().join("no-such.pem"));
    let message = refused_start(args.clone()).await;
    assert!(message.contains("--ca-file"), "{message}");
    std::fs::write(files.dir.path().join("empty.pem"), "").unwrap();
    args.ca_file = Some(files.dir.path().join("empty.pem"));
    let message = refused_start(args).await;
    assert!(message.contains("--ca-file"), "{message}");
    // --docker: nothing listens there.
    let message = refused_start(serve_args(&files)).await;
    assert!(message.contains("--docker"), "{message}");
    // --state-dir: a path below a file.
    let mut args = serve_args(&files);
    args.state_dir = files.root().join("state");
    let message = refused_start(args).await;
    assert!(message.contains("--state-dir"), "{message}");
}

#[test]
fn a_missing_trusted_root_refuses_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config_text(Path::new("no/such/root.json"), REGISTRY)).unwrap();
    assert!(matches!(
        load_config(&path).unwrap_err(),
        StartError::TrustedRootFile { .. }
    ));
}
