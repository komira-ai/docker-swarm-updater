//! `cargo xtask release image --binary <file> --version <v> --commit <40 hex> --created <unix
//! seconds> --platform linux/amd64|linux/arm64 --out <file>`: the container image of the
//! release, `FROM scratch` with the static binary and nothing else (docs/design.md section 5),
//! as a tar that is an OCI image layout:
//!
//! - one layer, gzip, holding [`ENTRYPOINT`] (the binary, mode 0555, owner 0:0);
//! - an image config naming that entrypoint, the user 65532:65532, the platform, and the
//!   `org.opencontainers.image.*` labels (source, revision, version, licenses);
//! - an OCI manifest, `index.json` listing it once (the digest a deploy names), `oci-layout`,
//!   and Docker's `manifest.json`, so `docker load` reads the same file and tags it
//!   `docker-swarm-updater:<version>`.
//!
//! Every byte depends only on the inputs: entries in a fixed order, every time the commit's
//! (`--created`), owners 0, a gzip header with no name and no time. Two runs on the same
//! inputs write the same file, which the workflow checks byte for byte. The output is written
//! to `<out>.part` and renamed; the manifest digest is printed as `image=sha256:<hex>`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{NAME, PLATFORMS, flags, required};
use crate::Report;

/// Where the binary is in the image, and the image's entrypoint.
pub const ENTRYPOINT: &str = "/docker-swarm-updater";

/// The user the image runs as unless the service names one.
pub const USER: &str = "65532:65532";

const SOURCE: &str = "https://github.com/komira-ai/docker-swarm-updater";
const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const INDEX_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// What one image is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs {
    /// The static binary's bytes.
    pub binary: Vec<u8>,
    /// The release version.
    pub version: String,
    /// The commit the release is built from, 40 hex digits.
    pub commit: String,
    /// The commit's time, in seconds since the epoch: every time in the image.
    pub created: i64,
    /// The OCI architecture, `amd64` or `arm64`.
    pub architecture: String,
}

/// An image tar and its manifest digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The tar's bytes.
    pub tar: Vec<u8>,
    /// `sha256:<hex>` of the manifest.
    pub manifest_digest: String,
}

pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    let flags = flags(
        args,
        &[
            "--binary",
            "--version",
            "--commit",
            "--created",
            "--platform",
            "--out",
        ],
    )?;
    let binary = PathBuf::from(required(&flags, "--binary")?);
    let out = PathBuf::from(required(&flags, "--out")?);
    let commit = required(&flags, "--commit")?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "--commit {commit:?} is not 40 lower-case hex digits"
        ));
    }
    let created = required(&flags, "--created")?;
    let created: i64 = created
        .parse()
        .map_err(|_| format!("--created {created:?} is not a number of seconds"))?;
    let platform = required(&flags, "--platform")?;
    let architecture = PLATFORMS
        .iter()
        .map(|(_, arch)| *arch)
        .find(|arch| platform == format!("linux/{arch}"))
        .ok_or_else(|| format!("--platform {platform:?} is not linux/amd64 or linux/arm64"))?;
    let inputs = Inputs {
        binary: std::fs::read(&binary).map_err(|e| format!("reading {}: {e}", binary.display()))?,
        version: required(&flags, "--version")?.to_owned(),
        commit: commit.to_owned(),
        created,
        architecture: architecture.to_owned(),
    };
    let image = build(&inputs)?;
    write(&out, &image.tar)?;
    Ok(Report {
        text: format!("image={}\n", image.manifest_digest),
        passed: true,
    })
}

/// The image of `inputs`.
pub fn build(inputs: &Inputs) -> Result<Image, String> {
    let created = jiff::Timestamp::from_second(inputs.created)
        .map_err(|e| format!("--created {}: {e}", inputs.created))?;
    let mtime = u64::try_from(inputs.created)
        .map_err(|_| format!("--created {} is before 1970", inputs.created))?;

    let mut layer = Tar::new(mtime);
    layer.file(ENTRYPOINT.trim_start_matches('/'), 0o555, &inputs.binary)?;
    let layer_tar = layer.finish()?;
    let diff_id = sha256(&layer_tar);
    let layer_gz = gzip(&layer_tar)?;

    let created = created.to_string();
    let config = json!({
        "architecture": inputs.architecture,
        "os": "linux",
        "created": created,
        "config": {
            "Entrypoint": [ENTRYPOINT],
            "User": USER,
            "Labels": {
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": inputs.commit,
                "org.opencontainers.image.version": inputs.version,
                "org.opencontainers.image.licenses": "Apache-2.0",
            },
        },
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": created, "created_by": "cargo xtask release image"}],
    })
    .to_string()
    .into_bytes();
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": {"mediaType": CONFIG_TYPE, "digest": sha256(&config), "size": config.len()},
        "layers": [{"mediaType": LAYER_TYPE, "digest": sha256(&layer_gz), "size": layer_gz.len()}],
    })
    .to_string()
    .into_bytes();
    let manifest_digest = sha256(&manifest);
    let tag = format!("{NAME}:{}", inputs.version);
    let index = json!({
        "schemaVersion": 2,
        "mediaType": INDEX_TYPE,
        "manifests": [{
            "mediaType": MANIFEST_TYPE,
            "digest": manifest_digest,
            "size": manifest.len(),
            "platform": {"architecture": inputs.architecture, "os": "linux"},
            "annotations": {
                "io.containerd.image.name": format!("docker.io/library/{tag}"),
                "org.opencontainers.image.ref.name": inputs.version,
            },
        }],
    })
    .to_string()
    .into_bytes();
    let docker_manifest = json!([{
        "Config": blob_path(&sha256(&config)),
        "RepoTags": [tag],
        "Layers": [blob_path(&sha256(&layer_gz))],
    }])
    .to_string()
    .into_bytes();

    let mut tar = Tar::new(mtime);
    tar.dir("blobs/")?;
    tar.dir("blobs/sha256/")?;
    let mut blobs = [layer_gz, config, manifest];
    blobs.sort_by_key(|b| sha256(b));
    for blob in &blobs {
        tar.file(&blob_path(&sha256(blob)), 0o444, blob)?;
    }
    tar.file("index.json", 0o444, &index)?;
    tar.file("manifest.json", 0o444, &docker_manifest)?;
    tar.file("oci-layout", 0o444, br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    Ok(Image {
        tar: tar.finish()?,
        manifest_digest,
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn blob_path(digest: &str) -> String {
    format!("blobs/sha256/{}", digest.trim_start_matches("sha256:"))
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(bytes)
        .and_then(|()| encoder.finish())
        .map_err(|e| format!("compressing the layer: {e}"))
}

/// A tar written in memory with fixed owners and times.
struct Tar {
    builder: tar::Builder<Vec<u8>>,
    mtime: u64,
}

impl Tar {
    fn new(mtime: u64) -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
            mtime,
        }
    }

    fn header(&self, kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(self.mtime);
        header.set_size(size);
        header
    }

    fn dir(&mut self, path: &str) -> Result<(), String> {
        let mut header = self.header(tar::EntryType::Directory, 0o755, 0);
        self.builder
            .append_data(&mut header, path, std::io::empty())
            .map_err(|e| format!("writing {path}: {e}"))
    }

    fn file(&mut self, path: &str, mode: u32, bytes: &[u8]) -> Result<(), String> {
        let mut header = self.header(tar::EntryType::Regular, mode, bytes.len() as u64);
        self.builder
            .append_data(&mut header, path, bytes)
            .map_err(|e| format!("writing {path}: {e}"))
    }

    fn finish(self) -> Result<Vec<u8>, String> {
        self.builder
            .into_inner()
            .map_err(|e| format!("finishing a tar: {e}"))
    }
}

/// Writes `bytes` to `<out>.part` and renames it over `out`; a failure removes the `.part`.
fn write(out: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut part = out.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = std::fs::write(&part, bytes)
        .and_then(|()| std::fs::rename(&part, out))
        .map_err(|e| format!("writing {}: {e}", out.display()));
    if result.is_err() {
        // Best effort: the .part may not exist when the write itself failed.
        let _ = std::fs::remove_file(&part);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tar_entry_the_tar_format_refuses_is_an_error_naming_it() {
        let mut tar = Tar::new(0);
        assert!(
            tar.dir("a/../b/")
                .unwrap_err()
                .starts_with("writing a/../b/: ")
        );
        assert!(
            tar.file("../x", 0o444, b"x")
                .unwrap_err()
                .starts_with("writing ../x: ")
        );
    }
}
