//! An OCI image-layout tar builder for tests: `oci-layout`, `index.json` and
//! `blobs/sha256/*` for a one-platform image, with switches for the broken tars of the
//! `tar` row of docs/design.md section 6.

use std::io;
use std::path::Path;

use dsu_core::ids::Digest;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Modification time of every tar entry (2026-11-01), so the bytes are reproducible.
const MTIME: u64 = 1_793_491_200;

/// The manifest flavour of the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// `application/vnd.oci.image.manifest.v1+json`.
    Oci,
    /// `application/vnd.docker.distribution.manifest.v2+json`, what real releases carry inside
    /// an OCI layout.
    DockerV2,
}

impl ManifestKind {
    fn manifest_type(self) -> &'static str {
        match self {
            Self::Oci => "application/vnd.oci.image.manifest.v1+json",
            Self::DockerV2 => "application/vnd.docker.distribution.manifest.v2+json",
        }
    }

    fn config_type(self) -> &'static str {
        match self {
            Self::Oci => "application/vnd.oci.image.config.v1+json",
            Self::DockerV2 => "application/vnd.docker.container.image.v1+json",
        }
    }

    fn layer_type(self) -> &'static str {
        match self {
            Self::Oci => "application/vnd.oci.image.layer.v1.tar+gzip",
            Self::DockerV2 => "application/vnd.docker.image.rootfs.diff.tar.gzip",
        }
    }
}

/// A defect to build into the tar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flaw {
    /// `index.json` names a manifest digest other than the manifest's own.
    IndexDigestDiffers,
    /// `index.json` lists the manifest twice.
    TwoManifests,
    /// The first layer's blob is not in the tar.
    MissingBlob,
    /// The first layer's blob holds other bytes than its name says.
    MisHashedBlob,
}

/// Where a blob's bytes sit in the tar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarBlob {
    /// The blob's name: its file name under `blobs/sha256/`.
    pub digest: Digest,
    /// Offset of the first content byte in the tar.
    pub offset: u64,
    /// Content length in bytes.
    pub len: u64,
}

/// A built image layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltImage {
    /// The tar file's bytes.
    pub tar: Vec<u8>,
    /// The digest of the manifest (the real one, whatever `index.json` says).
    pub manifest_digest: Digest,
    /// The manifest's exact bytes.
    pub manifest: Vec<u8>,
    /// The manifest's media type.
    pub media_type: &'static str,
    /// The blobs in the tar (config and layers; a missing blob is not listed).
    pub blobs: Vec<TarBlob>,
}

impl BuiltImage {
    /// Writes the tar to `path`.
    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, &self.tar)
    }
}

/// A builder of one-platform image layouts. The content is deterministic: the same
/// settings give the same bytes.
#[derive(Debug, Clone)]
pub struct OciImage {
    label: String,
    os: String,
    architecture: String,
    kind: ManifestKind,
    layers: usize,
    flaw: Option<Flaw>,
}

impl OciImage {
    /// A `linux/amd64` image with an OCI manifest and one layer; `label` is part of the
    /// layer bytes, so images with different labels have different digests.
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            kind: ManifestKind::Oci,
            layers: 1,
            flaw: None,
        }
    }

    /// The `os` and `architecture` of the image config.
    pub fn platform(mut self, os: &str, architecture: &str) -> Self {
        self.os = os.to_owned();
        self.architecture = architecture.to_owned();
        self
    }

    /// The manifest flavour.
    pub fn kind(mut self, kind: ManifestKind) -> Self {
        self.kind = kind;
        self
    }

    /// The number of layers.
    pub fn layers(mut self, layers: usize) -> Self {
        self.layers = layers;
        self
    }

    /// Builds a defect into the tar.
    pub fn flaw(mut self, flaw: Flaw) -> Self {
        self.flaw = Some(flaw);
        self
    }

    /// Builds the tar.
    pub fn build(&self) -> BuiltImage {
        let layers: Vec<Vec<u8>> = (0..self.layers)
            .map(|i| {
                format!(
                    "layer {i} of {} {}/{}",
                    self.label, self.os, self.architecture
                )
                .into_bytes()
            })
            .collect();
        let layer_digests: Vec<Digest> = layers.iter().map(|l| digest_of(l)).collect();
        let config = serde_json::to_vec(&json!({
            "architecture": self.architecture,
            "os": self.os,
            "rootfs": {"type": "layers", "diff_ids": layer_digests},
        }))
        .unwrap();
        let config_digest = digest_of(&config);
        let descriptor = |media_type: &str, digest: &Digest, size: usize| json!({"mediaType": media_type, "digest": digest, "size": size});
        let layer_descriptors: Vec<Value> = layers
            .iter()
            .zip(&layer_digests)
            .map(|(l, d)| descriptor(self.kind.layer_type(), d, l.len()))
            .collect();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": self.kind.manifest_type(),
            "config": descriptor(self.kind.config_type(), &config_digest, config.len()),
            "layers": layer_descriptors,
        }))
        .unwrap();
        let manifest_digest = digest_of(&manifest);

        let indexed_digest = match self.flaw {
            Some(Flaw::IndexDigestDiffers) => digest_of(b"another manifest"),
            _ => manifest_digest.clone(),
        };
        let entry = descriptor(self.kind.manifest_type(), &indexed_digest, manifest.len());
        let entries = if self.flaw == Some(Flaw::TwoManifests) {
            vec![entry.clone(), entry]
        } else {
            vec![entry]
        };
        let index = serde_json::to_vec(&json!({"schemaVersion": 2, "manifests": entries})).unwrap();

        let mut blobs: Vec<(Digest, Vec<u8>)> = vec![
            (config_digest, config),
            (manifest_digest.clone(), manifest.clone()),
        ];
        for (i, (digest, bytes)) in layer_digests.into_iter().zip(layers).enumerate() {
            match (i, self.flaw) {
                (0, Some(Flaw::MissingBlob)) => {}
                (0, Some(Flaw::MisHashedBlob)) => {
                    blobs.push((digest, b"not the bytes the name says".to_vec()))
                }
                _ => blobs.push((digest, bytes)),
            }
        }

        let mut builder = tar::Builder::new(Vec::new());
        append(
            &mut builder,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        append(&mut builder, "index.json", &index);
        for (digest, bytes) in &blobs {
            append(
                &mut builder,
                &format!("blobs/sha256/{}", digest.hex()),
                bytes,
            );
        }
        let tar = builder.into_inner().unwrap();
        let ranges = blobs
            .iter()
            .map(|(digest, bytes)| TarBlob {
                digest: digest.clone(),
                offset: 0,
                len: bytes.len() as u64,
            })
            .collect::<Vec<_>>();
        let blobs = locate(&tar, ranges);
        BuiltImage {
            tar,
            manifest_digest,
            manifest,
            media_type: self.kind.manifest_type(),
            blobs,
        }
    }
}

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::from_sha256(Sha256::digest(bytes).into())
}

fn append(builder: &mut tar::Builder<Vec<u8>>, path: &str, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(MTIME);
    builder.append_data(&mut header, path, bytes).unwrap();
}

/// Fills in each blob's offset by reading the finished tar.
fn locate(tar: &[u8], mut blobs: Vec<TarBlob>) -> Vec<TarBlob> {
    let mut archive = tar::Archive::new(tar);
    for entry in archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        if let Some(hex) = path.strip_prefix("blobs/sha256/") {
            let blob = blobs.iter_mut().find(|b| b.digest.hex() == hex).unwrap();
            blob.offset = entry.raw_file_position();
        }
    }
    blobs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
        use std::io::Read as _;
        let mut archive = tar::Archive::new(tar);
        archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut bytes = Vec::new();
                e.read_to_end(&mut bytes).unwrap();
                (e.path().unwrap().to_string_lossy().into_owned(), bytes)
            })
            .collect()
    }

    fn file(tar: &[u8], name: &str) -> Option<Vec<u8>> {
        entries(tar)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b)
    }

    fn index_manifests(image: &BuiltImage) -> Vec<Value> {
        let index: Value =
            serde_json::from_slice(&file(&image.tar, "index.json").unwrap()).unwrap();
        index["manifests"].as_array().unwrap().clone()
    }

    #[test]
    fn default_image_is_a_valid_oci_layout() {
        let image = OciImage::new("a").build();
        assert_eq!(
            file(&image.tar, "oci-layout").unwrap(),
            br#"{"imageLayoutVersion":"1.0.0"}"#
        );
        assert_eq!(
            image.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        let manifests = index_manifests(&image);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0]["digest"], image.manifest_digest.as_str());
        assert_eq!(manifests[0]["mediaType"], image.media_type);
        assert_eq!(manifests[0]["size"], image.manifest.len());
        assert_eq!(digest_of(&image.manifest), image.manifest_digest);

        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        assert_eq!(manifest["mediaType"], image.media_type);
        assert_eq!(manifest["layers"].as_array().unwrap().len(), 1);
        let config_digest = manifest["config"]["digest"].as_str().unwrap();
        let config: Value = serde_json::from_slice(
            &file(
                &image.tar,
                &format!("blobs/sha256/{}", &config_digest["sha256:".len()..]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (config["os"].as_str(), config["architecture"].as_str()),
            (Some("linux"), Some("amd64"))
        );
        assert_eq!(image.blobs.len(), 3);
    }

    #[test]
    fn every_blob_is_named_by_its_hash_and_located() {
        let image = OciImage::new("b").layers(2).build();
        assert_eq!(image.blobs.len(), 4);
        for blob in &image.blobs {
            let bytes = file(&image.tar, &format!("blobs/sha256/{}", blob.digest.hex())).unwrap();
            assert_eq!(digest_of(&bytes), blob.digest);
            let start = blob.offset as usize;
            assert_eq!(
                &image.tar[start..start + blob.len as usize],
                bytes.as_slice()
            );
        }
    }

    #[test]
    fn docker_v2_manifest_kind() {
        let image = OciImage::new("c").kind(ManifestKind::DockerV2).build();
        assert_eq!(
            image.media_type,
            "application/vnd.docker.distribution.manifest.v2+json"
        );
        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        assert_eq!(
            manifest["config"]["mediaType"],
            "application/vnd.docker.container.image.v1+json"
        );
        assert_eq!(
            manifest["layers"][0]["mediaType"],
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        );
    }

    #[test]
    fn building_twice_gives_the_same_bytes_and_labels_differ() {
        assert_eq!(OciImage::new("d").build(), OciImage::new("d").build());
        assert_ne!(
            OciImage::new("d").build().manifest_digest,
            OciImage::new("e").build().manifest_digest
        );
    }

    #[test]
    fn another_platform_is_in_the_config() {
        let image = OciImage::new("f").platform("linux", "arm64").build();
        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        let digest = manifest["config"]["digest"].as_str().unwrap();
        let config: Value = serde_json::from_slice(
            &file(
                &image.tar,
                &format!("blobs/sha256/{}", &digest["sha256:".len()..]),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(config["architecture"], "arm64");
    }

    #[test]
    fn index_digest_differs() {
        let image = OciImage::new("g").flaw(Flaw::IndexDigestDiffers).build();
        let manifests = index_manifests(&image);
        assert_eq!(manifests.len(), 1);
        assert_ne!(manifests[0]["digest"], image.manifest_digest.as_str());
        assert_eq!(digest_of(&image.manifest), image.manifest_digest);
    }

    #[test]
    fn two_manifests() {
        let image = OciImage::new("h").flaw(Flaw::TwoManifests).build();
        assert_eq!(index_manifests(&image).len(), 2);
    }

    #[test]
    fn missing_blob() {
        let image = OciImage::new("i").flaw(Flaw::MissingBlob).build();
        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        let layer = manifest["layers"][0]["digest"].as_str().unwrap();
        assert!(
            file(
                &image.tar,
                &format!("blobs/sha256/{}", &layer["sha256:".len()..])
            )
            .is_none()
        );
        assert_eq!(image.blobs.len(), 2);
    }

    #[test]
    fn mis_hashed_blob() {
        let image = OciImage::new("j").flaw(Flaw::MisHashedBlob).build();
        let manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
        let layer = manifest["layers"][0]["digest"].as_str().unwrap();
        let bytes = file(
            &image.tar,
            &format!("blobs/sha256/{}", &layer["sha256:".len()..]),
        )
        .unwrap();
        assert_ne!(digest_of(&bytes).as_str(), layer);
        assert_eq!(image.blobs.len(), 3);
    }

    #[test]
    fn write_to_stores_the_tar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.tar");
        let image = OciImage::new("k").build();
        image.write_to(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), image.tar);
    }
}
