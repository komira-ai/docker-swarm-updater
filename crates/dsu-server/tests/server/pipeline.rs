//! Verifying and pushing an image tar: the `bundle`, `tar` and `registry` rows of
//! docs/design.md section 6 as seen through the pipeline functions the runner and `import`
//! share.

use std::path::PathBuf;
use std::sync::Arc;

use dsu_core::config::{Config, ServiceConfig};
use dsu_core::ids::Digest;
use dsu_core::record::ErrorToken;
use dsu_registry::Registry;
use dsu_server::pipeline::{
    PipelineError, VerifiedTar, VerifyJob, hash_file, push_tar, verify_tar,
};
use dsu_testkit::mint::{Authority, Identity, Spec, signed_at};
use dsu_testkit::oci::{BuiltImage, Flaw, ManifestKind, OciImage};
use dsu_testkit::registry::{FakeRegistry, Mode};
use dsu_verify::TrustedRoots;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::harness::{REGISTRY, config_text};

const FILE: &str = "app-1.0-linux-x86_64.image.tar";

pub fn service() -> ServiceConfig {
    let text = config_text(std::path::Path::new("/unused"), REGISTRY);
    Config::parse(&text).unwrap().services.remove(0)
}

pub fn digest_of(bytes: &[u8]) -> Digest {
    Digest::from_sha256(Sha256::digest(bytes).into())
}

/// The entries of a tar, in order.
pub fn entries(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
    use std::io::Read as _;
    tar::Archive::new(tar)
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

pub fn build(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// `image`'s tar with its manifest replaced by `manifest` (and the blob, the index entry and
/// the digest following it). Returns the tar and the new manifest digest.
pub fn with_manifest(image: &BuiltImage, manifest: &[u8]) -> (Vec<u8>, Digest) {
    let new = digest_of(manifest);
    let mut all = entries(&image.tar);
    for (name, bytes) in &mut all {
        if *name == format!("blobs/sha256/{}", image.manifest_digest.hex()) {
            *name = format!("blobs/sha256/{}", new.hex());
            *bytes = manifest.to_vec();
        } else if name == "index.json" {
            *bytes = json!({
                "schemaVersion": 2,
                "manifests": [{"mediaType": image.media_type, "digest": new, "size": manifest.len()}],
            })
            .to_string()
            .into_bytes();
        }
    }
    (build(&all), new)
}

pub struct Release {
    pub _dir: tempfile::TempDir,
    pub tar: PathBuf,
    pub bundle: Vec<u8>,
    pub tar_digest: Digest,
    pub image_digest: Digest,
}

impl Release {
    /// Writes `tar` and a bundle `authority` made for `spec_name` over the tar's digest.
    pub fn new(authority: &Authority, tar: &[u8], image_digest: &Digest) -> Release {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        std::fs::write(&path, tar).unwrap();
        let tar_digest = digest_of(tar);
        let spec = Spec::github(&service().signer, FILE, &tar_digest);
        let bundle = authority.bundle(&spec).to_string().into_bytes();
        Release {
            _dir: dir,
            tar: path,
            bundle,
            tar_digest,
            image_digest: image_digest.clone(),
        }
    }

    pub fn of(authority: &Authority, image: &BuiltImage) -> Release {
        Release::new(authority, &image.tar, &image.manifest_digest)
    }

    pub fn job(&self, authority: &Authority) -> VerifyJob {
        VerifyJob {
            tar: self.tar.clone(),
            tar_digest: self.tar_digest.clone(),
            bundle: self.bundle.clone(),
            image_digest: self.image_digest.clone(),
            service: service(),
            roots: Arc::new(TrustedRoots::parse(authority.trusted_root_json().as_bytes()).unwrap()),
        }
    }
}

fn refusal(result: Result<VerifiedTar, PipelineError>) -> PipelineError {
    result.unwrap_err()
}

#[test]
fn a_good_release_verifies_with_the_blobs_where_the_tar_has_them() {
    let authority = Authority::public_good();
    for kind in [ManifestKind::Oci, ManifestKind::DockerV2] {
        let image = OciImage::new("a").kind(kind).layers(2).build();
        let release = Release::of(&authority, &image);
        let verified = verify_tar(&release.job(&authority)).unwrap();
        assert_eq!(verified.signed_time, signed_at());
        assert_eq!(verified.image.manifest_digest, image.manifest_digest);
        assert_eq!(verified.image.manifest, image.manifest);
        assert_eq!(verified.image.manifest_media_type, image.media_type);
        // The config and the two layers, not the manifest; at the offsets the tar has them.
        assert_eq!(verified.image.blobs.len(), 3);
        for blob in &verified.image.blobs {
            let built = image
                .blobs
                .iter()
                .find(|b| b.digest == blob.digest)
                .unwrap();
            assert_eq!(
                (blob.offset, blob.len, &blob.path),
                (built.offset, built.len, &release.tar)
            );
        }
        assert_eq!(hash_file(&release.tar).unwrap(), release.tar_digest);
    }
}

#[test]
fn a_blob_named_twice_is_pushed_once() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    let layer = manifest["layers"][0].clone();
    manifest["layers"] = json!([layer, layer]);
    let (tar, digest) = with_manifest(&image, manifest.to_string().as_bytes());
    let release = Release::new(&authority, &tar, &digest);
    assert_eq!(
        verify_tar(&release.job(&authority))
            .unwrap()
            .image
            .blobs
            .len(),
        2
    );
}

#[test]
fn tar_rows() {
    let authority = Authority::public_good();
    let cases = [
        (Flaw::IndexDigestDiffers, ErrorToken::DigestMismatch, false),
        (Flaw::TwoManifests, ErrorToken::TarInvalid, false),
        (Flaw::MissingBlob, ErrorToken::TarInvalid, true),
        (Flaw::MisHashedBlob, ErrorToken::TarInvalid, true),
    ];
    for (flaw, token, bound) in cases {
        let image = OciImage::new("a").flaw(flaw).build();
        let release = Release::of(&authority, &image);
        let error = refusal(verify_tar(&release.job(&authority)));
        assert_eq!(
            (error.token(), error.digest_bound()),
            (token, bound),
            "{flaw:?}: {error}"
        );
    }
    let image = OciImage::new("a").platform("linux", "arm64").build();
    let error = refusal(verify_tar(&Release::of(&authority, &image).job(&authority)));
    assert_eq!(
        (error.token(), error.digest_bound()),
        (ErrorToken::PlatformMismatch, true)
    );
    assert!(error.detail().contains("linux/arm64"));
}

#[test]
fn the_index_is_checked_before_the_bundle() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").flaw(Flaw::IndexDigestDiffers).build();
    let mut release = Release::of(&authority, &image);
    release.bundle = b"not json".to_vec();
    let error = refusal(verify_tar(&release.job(&authority)));
    assert_eq!(error.token(), ErrorToken::DigestMismatch);
}

#[test]
fn bundle_rows() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    let release = Release::of(&authority, &image);
    let check = |release: &Release, authority: &Authority| {
        let error = refusal(verify_tar(&release.job(authority)));
        assert!(error.digest_bound(), "{error}");
        (error.token(), error.detail())
    };
    // Not JSON.
    let mut bad = Release::of(&authority, &image);
    bad.bundle = b"nope".to_vec();
    assert_eq!(check(&bad, &authority).0, ErrorToken::BundleInvalid);
    // Another artifact of the same release, and a tar changed after signing.
    let mut other = Release::of(&authority, &image);
    let spec = Spec::github(
        &service().signer,
        "other-1.0-linux-x86_64.image.tar",
        &other.tar_digest,
    );
    other.bundle = authority.bundle(&spec).to_string().into_bytes();
    assert_eq!(check(&other, &authority).0, ErrorToken::BundleSubject);
    let mut changed = Release::of(&authority, &image);
    changed.tar_digest = digest_of(b"another tar");
    assert_eq!(check(&changed, &authority).0, ErrorToken::BundleSubject);
    // Signed by another workflow.
    let mut spec = Spec::github(&service().signer, FILE, &release.tar_digest);
    let mut signer = service().signer;
    signer.workflow = ".github/workflows/other.yml".into();
    spec.identity = Identity::for_signer(&signer, "push");
    let mut wrong = Release::of(&authority, &image);
    wrong.bundle = authority.bundle(&spec).to_string().into_bytes();
    assert_eq!(check(&wrong, &authority).0, ErrorToken::BundleSigner);
    // A chain from another root.
    let elsewhere = Authority::public_good();
    let foreign = Release::of(&elsewhere, &image);
    let mut chained = Release::of(&authority, &image);
    chained.bundle = foreign.bundle.clone();
    assert_eq!(check(&chained, &authority).0, ErrorToken::BundleChain);
}

#[test]
fn a_tar_that_is_not_an_oci_layout_is_tar_invalid_and_not_bound() {
    let authority = Authority::public_good();
    let digest = digest_of(b"x");
    let cases: [(&str, Vec<u8>); 3] = [
        ("garbage", vec![b'x'; 2048]),
        ("empty", vec![0u8; 1024]),
        (
            "no index",
            build(&[("oci-layout".to_owned(), b"{}".to_vec())]),
        ),
    ];
    for (what, tar) in cases {
        let error = refusal(verify_tar(
            &Release::new(&authority, &tar, &digest).job(&authority),
        ));
        assert_eq!(
            (error.token(), error.digest_bound()),
            (ErrorToken::TarInvalid, false),
            "{what}: {error}"
        );
    }
    // An index.json that is not JSON, one that is too large.
    for index in [b"[".to_vec(), vec![b' '; 4 * 1024 * 1024 + 1]] {
        let tar = build(&[("index.json".to_owned(), index)]);
        let error = refusal(verify_tar(
            &Release::new(&authority, &tar, &digest).job(&authority),
        ));
        assert_eq!(error.token(), ErrorToken::TarInvalid);
        assert!(!error.digest_bound());
    }
    // A leading ./ on the names is read through.
    let image = OciImage::new("a").build();
    let dotted: Vec<(String, Vec<u8>)> = entries(&image.tar)
        .into_iter()
        .map(|(n, b)| (format!("./{n}"), b))
        .collect();
    let tar = build(&dotted);
    let release = Release::new(&authority, &tar, &image.manifest_digest);
    assert!(verify_tar(&release.job(&authority)).is_ok());
}

#[test]
fn a_manifest_the_tar_does_not_hold_or_that_disagrees_is_tar_invalid_and_bound() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    let mut manifest: Value = serde_json::from_slice(&image.manifest).unwrap();
    let mut wrong_size = manifest.clone();
    wrong_size["layers"][0]["size"] = json!(1);
    manifest["mediaType"] = json!("application/x-unknown");
    let mut cases: Vec<(&str, Vec<u8>, Digest)> = Vec::new();
    for (what, bytes) in [
        ("unsupported media type", manifest.to_string().into_bytes()),
        ("not JSON", b"[".to_vec()),
        (
            "a layer of another size",
            wrong_size.to_string().into_bytes(),
        ),
    ] {
        let (tar, digest) = with_manifest(&image, &bytes);
        cases.push((what, tar, digest));
    }
    // The index names a manifest the tar has no blob for.
    let mut all = entries(&image.tar);
    all.retain(|(n, _)| *n != format!("blobs/sha256/{}", image.manifest_digest.hex()));
    cases.push((
        "manifest missing",
        build(&all),
        image.manifest_digest.clone(),
    ));
    // The manifest blob's size in the index is not its size.
    let mut all = entries(&image.tar);
    for (name, bytes) in &mut all {
        if name == "index.json" {
            *bytes = json!({"schemaVersion": 2, "manifests": [{"mediaType": image.media_type, "digest": image.manifest_digest, "size": 1}]})
                .to_string()
                .into_bytes();
        }
    }
    cases.push(("index size", build(&all), image.manifest_digest.clone()));
    for (what, tar, digest) in cases {
        let release = Release::new(&authority, &tar, &digest);
        let error = refusal(verify_tar(&release.job(&authority)));
        assert_eq!(
            (error.token(), error.digest_bound()),
            (ErrorToken::TarInvalid, true),
            "{what}: {error}"
        );
    }
}

#[test]
fn an_unreadable_tar_is_fetch_failed() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    let release = Release::of(&authority, &image);
    std::fs::remove_file(&release.tar).unwrap();
    let error = refusal(verify_tar(&release.job(&authority)));
    assert_eq!(
        (error.token(), error.digest_bound()),
        (ErrorToken::FetchFailed, false)
    );
    assert!(error.to_string().contains(FILE));
    let error = hash_file(&release.tar).unwrap_err();
    assert_eq!(error.token(), ErrorToken::FetchFailed);
}

#[tokio::test]
async fn push_writes_the_blobs_and_the_manifest_by_digest() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").layers(2).build();
    let release = Release::of(&authority, &image);
    let verified = verify_tar(&release.job(&authority)).unwrap();
    let registry = FakeRegistry::start(Mode::Normal).await;
    let client = Registry::new(registry.addr());
    push_tar(&client, "app", &verified).await.unwrap();
    let (media_type, bytes) = registry.manifest("app", &image.manifest_digest).unwrap();
    assert_eq!(
        (media_type.as_str(), bytes),
        (image.media_type, image.manifest.clone())
    );
    for blob in &verified.image.blobs {
        assert!(registry.has_blob("app", &blob.digest));
    }
}

#[tokio::test]
async fn a_registry_that_fails_or_answers_another_digest_is_registry_failed() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    let release = Release::of(&authority, &image);
    let verified = verify_tar(&release.job(&authority)).unwrap();
    for mode in [Mode::FailBlobUpload, Mode::AnswerOtherDigest] {
        let registry = FakeRegistry::start(mode).await;
        let error = push_tar(&Registry::new(registry.addr()), "app", &verified)
            .await
            .unwrap_err();
        assert_eq!(
            (error.token(), error.digest_bound()),
            (ErrorToken::RegistryFailed, false)
        );
        assert!(!error.detail().contains('\n'));
    }
}

#[test]
fn directory_entries_are_skipped_and_a_blob_of_the_right_size_but_other_bytes_is_refused() {
    let authority = Authority::public_good();
    let image = OciImage::new("a").build();
    // A tar that also holds a directory entry, as real image tars do.
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    builder
        .append_data(&mut header, "blobs/", std::io::empty())
        .unwrap();
    let mut with_directory = builder.into_inner().unwrap();
    // Strip the end-of-archive blocks, then append the image's entries.
    with_directory.truncate(with_directory.len() - 1024);
    with_directory.extend_from_slice(&image.tar);
    let release = Release::new(&authority, &with_directory, &image.manifest_digest);
    assert!(verify_tar(&release.job(&authority)).is_ok());

    // The layer's first byte changed: same length, other hash.
    let mut all = entries(&image.tar);
    for (_, bytes) in &mut all {
        if bytes.starts_with(b"layer") {
            bytes[0] = b'L';
        }
    }
    let release = Release::new(&authority, &build(&all), &image.manifest_digest);
    let error = refusal(verify_tar(&release.job(&authority)));
    assert_eq!(
        (error.token(), error.digest_bound()),
        (ErrorToken::TarInvalid, true)
    );
    assert!(error.detail().contains("hash to"), "{error}");
}
