//! `cargo xtask release image`, run as the release workflow runs it: the tar it writes is the
//! same for the same inputs, holds the binary as a `FROM scratch` image, and is an image the
//! updater's own verifier accepts for a service configured for it, with a bundle that signs it.
#![allow(
    clippy::unwrap_used,
    reason = "tests: a failed unwrap is a failed test"
)]

use std::io::Read as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use dsu_core::config::Config;
use dsu_core::ids::Digest;
use dsu_core::record::ErrorToken;
use dsu_server::pipeline::{VerifyJob, hash_file, verify_tar};
use dsu_testkit::mint::{Authority, Spec};
use dsu_verify::TrustedRoots;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
/// 2026-11-10T00:00:00Z.
const CREATED: &str = "1794268800";
const BINARY: &[u8] = b"\x7fELF a static binary";

fn xtask(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .unwrap()
}

/// Writes the image of `BINARY` for `platform` and `created` to `out`; returns the digest it
/// printed.
fn image(dir: &Path, out: &str, platform: &str, created: &str) -> Digest {
    let binary = dir.join("binary");
    std::fs::write(&binary, BINARY).unwrap();
    let out = dir.join(out);
    let output = xtask(&[
        "release",
        "image",
        "--binary",
        &binary.to_string_lossy(),
        "--version",
        "0.1.42",
        "--commit",
        COMMIT,
        "--created",
        created,
        "--platform",
        platform,
        "--out",
        &out.to_string_lossy(),
    ]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let digest = stdout.strip_prefix("image=").unwrap().trim_end();
    Digest::parse(digest).unwrap()
}

/// The regular files of a tar, by name.
fn files(tar: &[u8]) -> Vec<(String, u32, u64, Vec<u8>)> {
    tar::Archive::new(tar)
        .entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let name = e.path().unwrap().to_string_lossy().into_owned();
            let (mode, uid) = (e.header().mode().unwrap(), e.header().uid().unwrap());
            let mut bytes = Vec::new();
            e.read_to_end(&mut bytes).unwrap();
            (name, mode, uid, bytes)
        })
        .collect()
}

fn blob<'a>(entries: &'a [(String, u32, u64, Vec<u8>)], digest: &str) -> &'a [u8] {
    let name = format!("blobs/sha256/{}", digest.trim_start_matches("sha256:"));
    &entries.iter().find(|e| e.0 == name).unwrap().3
}

fn service(platform: &str) -> dsu_core::config::ServiceConfig {
    let text = format!(
        r#"registry = "127.0.0.1:5000"
trusted_root = "/unused"
redirect_hosts = ["objects.githubusercontent.com"]
keep_previous = 3
min_free_bytes = 0
[[service]]
name = "docker-swarm-updater"
swarm_service = "docker-swarm-updater_server"
repository = "docker-swarm-updater"
platform = "{platform}"
artifact_url = {{ owner = "example-org", repo = "docker-swarm-updater" }}
artifact_name = "docker-swarm-updater-*-linux-x86_64.image.tar"
signer = {{ repository = "example-org/docker-swarm-updater", repository_id = "1", workflow = ".github/workflows/artifacts.yml", ref = "refs/heads/main", triggers = ["push"] }}
  [[service.caller]]
  repository = "example-org/docker-swarm-updater"
  repository_id = "1"
  job_workflow_ref = "example-org/docker-swarm-updater/.github/workflows/deploy.yml@{COMMIT}"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
"#
    );
    Config::parse(&text).unwrap().services.remove(0)
}

/// Verifies `tar` as the asset `name` of a service configured for `platform`, with a bundle the
/// test Sigstore instance signed over the tar.
fn verify(
    tar: &Path,
    name: &str,
    digest: &Digest,
    platform: &str,
) -> Result<dsu_server::pipeline::VerifiedTar, dsu_server::pipeline::PipelineError> {
    let authority = Authority::public_good();
    let service = service(platform);
    let tar_digest = hash_file(tar).unwrap();
    let bundle = authority
        .bundle(&Spec::github(&service.signer, name, &tar_digest))
        .to_string()
        .into_bytes();
    verify_tar(&VerifyJob {
        tar: tar.to_owned(),
        tar_digest,
        bundle,
        image_digest: digest.clone(),
        service,
        roots: Arc::new(TrustedRoots::parse(authority.trusted_root_json().as_bytes()).unwrap()),
    })
}

#[test]
fn the_same_inputs_make_the_same_bytes_and_another_time_other_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let a = image(dir.path(), "a.tar", "linux/amd64", CREATED);
    let b = image(dir.path(), "b.tar", "linux/amd64", CREATED);
    assert_eq!(a, b);
    assert_eq!(
        std::fs::read(dir.path().join("a.tar")).unwrap(),
        std::fs::read(dir.path().join("b.tar")).unwrap()
    );
    let c = image(dir.path(), "c.tar", "linux/amd64", "1794268801");
    assert_ne!(a, c);
    // Nothing but the output is left behind.
    assert!(!dir.path().join("a.tar.part").exists());
}

#[test]
fn the_image_is_the_binary_alone_from_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let digest = image(dir.path(), "i.tar", "linux/arm64", CREATED);
    let tar = std::fs::read(dir.path().join("i.tar")).unwrap();
    let entries = files(&tar);
    let names: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(names.len(), 8);
    assert_eq!(&names[..2], ["blobs/", "blobs/sha256/"]);
    assert_eq!(&names[5..], ["index.json", "manifest.json", "oci-layout"]);
    for (name, _, uid, _) in &entries {
        assert_eq!(*uid, 0, "{name}");
    }
    let mtimes: Vec<u64> = tar::Archive::new(tar.as_slice())
        .entries()
        .unwrap()
        .map(|e| e.unwrap().header().mtime().unwrap())
        .collect();
    assert_eq!(mtimes, vec![CREATED.parse::<u64>().unwrap(); 8]);

    let json = |bytes: &[u8]| -> Value { serde_json::from_slice(bytes).unwrap() };
    let index = json(&entries[5].3);
    assert_eq!(index["manifests"].as_array().unwrap().len(), 1);
    assert_eq!(index["manifests"][0]["digest"], digest.as_str());
    assert_eq!(index["manifests"][0]["platform"]["architecture"], "arm64");
    assert_eq!(
        index["manifests"][0]["annotations"]["io.containerd.image.name"],
        "docker.io/library/docker-swarm-updater:0.1.42"
    );
    assert_eq!(
        json(&entries[7].3),
        serde_json::json!({"imageLayoutVersion": "1.0.0"})
    );

    let manifest_bytes = blob(&entries, digest.as_str());
    assert_eq!(
        format!("sha256:{}", hex(&Sha256::digest(manifest_bytes))),
        digest.as_str()
    );
    let manifest = json(manifest_bytes);
    assert_eq!(
        manifest["mediaType"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    let config_digest = manifest["config"]["digest"].as_str().unwrap();
    let layers = manifest["layers"].as_array().unwrap();
    assert_eq!(layers.len(), 1);
    let layer_digest = layers[0]["digest"].as_str().unwrap();
    assert_eq!(
        layers[0]["mediaType"],
        "application/vnd.oci.image.layer.v1.tar+gzip"
    );

    // The one layer holds the binary alone, read-only and executable, owned by root.
    let layer_gz = blob(&entries, layer_digest);
    let mut layer = Vec::new();
    flate2::read::GzDecoder::new(layer_gz)
        .read_to_end(&mut layer)
        .unwrap();
    let layer_files = files(&layer);
    assert_eq!(
        layer_files,
        [("docker-swarm-updater".to_owned(), 0o555, 0, BINARY.to_vec())]
    );

    let config = json(blob(&entries, config_digest));
    assert_eq!(config["os"], "linux");
    assert_eq!(config["architecture"], "arm64");
    assert_eq!(config["created"], "2026-11-10T00:00:00Z");
    assert_eq!(
        config["config"]["Entrypoint"],
        serde_json::json!(["/docker-swarm-updater"])
    );
    assert_eq!(config["config"]["User"], "65532:65532");
    assert_eq!(
        config["config"]["Labels"],
        serde_json::json!({
            "org.opencontainers.image.source": "https://github.com/komira-ai/docker-swarm-updater",
            "org.opencontainers.image.revision": COMMIT,
            "org.opencontainers.image.version": "0.1.42",
            "org.opencontainers.image.licenses": "Apache-2.0",
        })
    );
    assert_eq!(
        config["rootfs"]["diff_ids"],
        serde_json::json!([format!("sha256:{}", hex(&Sha256::digest(&layer)))])
    );

    // Docker's manifest.json names the same config and layer, and the version tag.
    assert_eq!(
        json(&entries[6].3),
        serde_json::json!([{
            "Config": format!("blobs/sha256/{}", config_digest.trim_start_matches("sha256:")),
            "RepoTags": ["docker-swarm-updater:0.1.42"],
            "Layers": [format!("blobs/sha256/{}", layer_digest.trim_start_matches("sha256:"))],
        }])
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_updater_verifies_the_image_for_the_platform_it_was_built_for() {
    let dir = tempfile::tempdir().unwrap();
    let name = "docker-swarm-updater-0.1.42-linux-x86_64.image.tar";
    let digest = image(dir.path(), name, "linux/amd64", CREATED);
    let tar = dir.path().join(name);
    let verified = verify(&tar, name, &digest, "linux/amd64").unwrap();
    assert_eq!(verified.image.manifest_digest, digest);
    // The config and the layer are pushed as blobs; the manifest is pushed by its digest.
    assert_eq!(verified.image.blobs.len(), 2);

    // The arm64 image is refused for a service configured for amd64, after its digest
    // matched: it is that image's platform that is wrong.
    let arm = image(dir.path(), "arm.tar", "linux/arm64", CREATED);
    let arm_tar = dir.path().join("arm.tar");
    let error = verify(&arm_tar, name, &arm, "linux/amd64").unwrap_err();
    assert_eq!(error.token(), ErrorToken::PlatformMismatch);
}

#[test]
fn a_bad_command_line_or_input_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("binary");
    std::fs::write(&binary, BINARY).unwrap();
    let binary = binary.to_string_lossy().into_owned();
    let out = dir.path().join("o.tar").to_string_lossy().into_owned();
    let missing_binary = dir.path().join("missing").to_string_lossy().into_owned();
    let missing_out = dir
        .path()
        .join("missing/o.tar")
        .to_string_lossy()
        .into_owned();
    let reading_missing = format!("reading {missing_binary}");
    let writing_missing = format!("writing {missing_out}");
    let missing_binary = dir.path().join("missing").to_string_lossy().into_owned();
    let missing_out = dir
        .path()
        .join("missing/o.tar")
        .to_string_lossy()
        .into_owned();
    let base = [
        ("--binary", binary.as_str()),
        ("--version", "1"),
        ("--commit", COMMIT),
        ("--created", CREATED),
        ("--platform", "linux/amd64"),
        ("--out", out.as_str()),
    ];
    let cases = [
        (
            "--commit",
            "0123",
            "--commit \"0123\" is not 40 lower-case hex digits",
        ),
        (
            "--commit",
            &COMMIT.to_uppercase(),
            "is not 40 lower-case hex digits",
        ),
        (
            "--created",
            "noon",
            "--created \"noon\" is not a number of seconds",
        ),
        ("--created", "-1", "--created -1 is before 1970"),
        (
            "--created",
            "999999999999999",
            "--created 999999999999999: ",
        ),
        (
            "--platform",
            "linux/riscv64",
            "--platform \"linux/riscv64\" is not linux/amd64 or linux/arm64",
        ),
        (
            "--platform",
            "darwin/arm64",
            "is not linux/amd64 or linux/arm64",
        ),
        ("--binary", &missing_binary, &reading_missing),
        ("--out", &missing_out, &writing_missing),
    ];
    for (flag, value, message) in cases {
        let mut args = vec!["release", "image"];
        for (f, v) in base {
            args.push(f);
            args.push(if f == flag { value } else { v });
        }
        let output = xtask(&args);
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(2), "{flag} {value}: {stderr}");
        assert!(stderr.contains(message), "{flag} {value}: {stderr}");
    }
    assert!(!dir.path().join("o.tar").exists());
    let output = xtask(&["release", "image", "--binary", &binary]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "xtask: --out is required\n"
    );
}

/// What `release deploy-inputs` reads from the release's linux-x86_64 image is the digest
/// `release image` wrote it with, and the updater verifies that image under that digest.
#[test]
fn the_deploy_inputs_name_the_digest_the_updater_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let name = "docker-swarm-updater-0.1.42-linux-x86_64.image.tar";
    let written = image(dir.path(), name, "linux/amd64", CREATED);
    let output = xtask(&[
        "release",
        "deploy-inputs",
        "--dir",
        &dir.path().to_string_lossy(),
        "--repo",
        "komira-ai/docker-swarm-updater",
        "--version",
        "0.1.42",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let url = format!(
        "https://github.com/komira-ai/docker-swarm-updater/releases/download/v0.1.42/{name}"
    );
    assert_eq!(
        stdout,
        format!("digest={written}\nimage-url={url}\nbundle-url={url}.sigstore.json\n")
    );
    let sent = stdout
        .lines()
        .next()
        .unwrap()
        .strip_prefix("digest=")
        .unwrap();
    let sent = Digest::parse(sent).unwrap();
    let verified = verify(&dir.path().join(name), name, &sent, "linux/amd64").unwrap();
    assert_eq!(verified.image.manifest_digest, written);

    // No image of that version in the directory: exit 2, naming the file.
    let output = xtask(&[
        "release",
        "deploy-inputs",
        "--dir",
        &dir.path().to_string_lossy(),
        "--repo",
        "komira-ai/docker-swarm-updater",
        "--version",
        "0.1.43",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let missing = dir
        .path()
        .join("docker-swarm-updater-0.1.43-linux-x86_64.image.tar");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .starts_with(&format!("xtask: reading {}: ", missing.display()))
    );
}
