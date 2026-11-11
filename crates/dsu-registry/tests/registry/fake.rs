//! `dsu-registry` against the fake registry of `dsu-testkit`, with images built by its OCI
//! tar builder.

use std::path::Path;

use dsu_core::ids::Digest;
use dsu_registry::{BlobSource, Image, Registry, RegistryError};
use dsu_testkit::oci::{BuiltImage, Flaw, ManifestKind, OciImage};
use dsu_testkit::registry::{Event, FakeRegistry, Mode, other_digest};
use http::StatusCode;
use sha2::{Digest as _, Sha256};

const REPO: &str = "example-org/app";

/// The image of `built`, its blobs read from the tar at `tar_path`.
fn image_of(built: &BuiltImage, tar_path: &Path) -> Image {
    Image {
        manifest_digest: built.manifest_digest.clone(),
        manifest_media_type: built.media_type.to_owned(),
        manifest: built.manifest.clone(),
        blobs: built
            .blobs
            .iter()
            .filter(|b| b.digest != built.manifest_digest)
            .map(|b| BlobSource {
                digest: b.digest.clone(),
                path: tar_path.to_owned(),
                offset: b.offset,
                len: b.len,
            })
            .collect(),
    }
}

/// Writes the tar into `dir` and returns the image to push.
fn written(dir: &Path, built: &BuiltImage) -> Image {
    let path = dir.join("image.tar");
    built.write_to(&path).unwrap();
    image_of(built, &path)
}

fn pushed_digests(registry: &FakeRegistry) -> Vec<Digest> {
    registry
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::BlobUploaded { digest, .. } => Some(digest),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn pushes_an_image_by_digest_for_both_manifest_kinds() {
    for kind in [ManifestKind::Oci, ManifestKind::DockerV2] {
        let dir = tempfile::tempdir().unwrap();
        let built = OciImage::new("push").kind(kind).layers(2).build();
        let image = written(dir.path(), &built);
        let fake = FakeRegistry::start(Mode::Normal).await;
        let registry = Registry::new(fake.addr());

        registry.push_image(REPO, &image).await.unwrap();

        let stored = fake.manifest(REPO, &built.manifest_digest).unwrap();
        assert_eq!(
            stored,
            (built.media_type.to_owned(), built.manifest.clone())
        );
        for blob in &image.blobs {
            assert!(fake.has_blob(REPO, &blob.digest), "{}", blob.digest);
        }
        let events = fake.events();
        assert_eq!(events.len(), 4);
        assert_eq!(
            events[3],
            Event::ManifestPushed {
                repository: REPO.to_owned(),
                digest: built.manifest_digest.clone()
            }
        );
    }
}

#[tokio::test]
async fn blobs_the_registry_has_are_not_uploaded_again() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("again").build();
    let image = written(dir.path(), &built);
    let fake = FakeRegistry::start(Mode::Normal).await;
    let registry = Registry::new(fake.addr());

    registry.push_image(REPO, &image).await.unwrap();
    registry.push_image(REPO, &image).await.unwrap();

    assert_eq!(pushed_digests(&fake).len(), 2);
    assert_eq!(fake.events().len(), 4);
}

#[tokio::test]
async fn upload_locations_may_be_absolute() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("absolute").build();
    let fake = FakeRegistry::start(Mode::AbsoluteLocation).await;
    Registry::new(fake.addr())
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap();
    assert!(fake.manifest(REPO, &built.manifest_digest).is_some());
}

#[tokio::test]
async fn a_blob_is_streamed_from_the_middle_of_a_large_file() {
    // The blob is larger than one body chunk and sits between other bytes, as in a tar.
    let blob: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let digest_of = |bytes: &[u8]| Digest::from_sha256(Sha256::digest(bytes).into());
    let (blob_digest, config_digest) = (digest_of(&blob), digest_of(&config));
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "config": {"digest": config_digest, "size": config.len()},
        "layers": [{"digest": blob_digest, "size": blob.len()}],
    }))
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    let mut file = vec![7u8; 1000];
    file.extend(&blob);
    file.extend(&config);
    file.extend([9u8; 33]);
    std::fs::write(&path, &file).unwrap();
    let image = Image {
        manifest_digest: digest_of(&manifest),
        manifest_media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
        manifest,
        blobs: vec![
            BlobSource {
                digest: blob_digest.clone(),
                path: path.clone(),
                offset: 1000,
                len: blob.len() as u64,
            },
            BlobSource {
                digest: config_digest,
                path,
                offset: 1000 + blob.len() as u64,
                len: config.len() as u64,
            },
        ],
    };
    let fake = FakeRegistry::start(Mode::Normal).await;
    Registry::new(fake.addr())
        .push_image(REPO, &image)
        .await
        .unwrap();
    assert!(fake.has_blob(REPO, &blob_digest));
}

#[tokio::test]
async fn an_empty_blob_is_uploaded() {
    let empty = Digest::from_sha256(Sha256::digest(b"").into());
    let manifest = serde_json::to_vec(&serde_json::json!({
        "config": {"digest": empty},
        "layers": [],
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty");
    std::fs::write(&path, b"").unwrap();
    let image = Image {
        manifest_digest: Digest::from_sha256(Sha256::digest(&manifest).into()),
        manifest_media_type: "application/vnd.oci.image.manifest.v1+json".to_owned(),
        manifest,
        blobs: vec![BlobSource {
            digest: empty.clone(),
            path,
            offset: 0,
            len: 0,
        }],
    };
    let fake = FakeRegistry::start(Mode::Normal).await;
    Registry::new(fake.addr())
        .push_image(REPO, &image)
        .await
        .unwrap();
    assert!(fake.has_blob(REPO, &empty));
}

#[tokio::test]
async fn a_registry_answering_another_digest_fails_the_push() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("other").build();
    let fake = FakeRegistry::start(Mode::AnswerOtherDigest).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap_err();
    match err {
        RegistryError::ManifestDigest { expected, answered } => {
            assert_eq!(expected, built.manifest_digest);
            assert_eq!(answered.as_deref(), Some(other_digest().as_str()));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_failing_blob_upload_fails_the_push_before_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("failing").build();
    let fake = FakeRegistry::start(Mode::FailBlobUpload).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::Status { status, .. } if *status == StatusCode::INTERNAL_SERVER_ERROR),
        "{err:?}"
    );
    assert!(err.to_string().contains("500"), "{err}");
    assert!(fake.events().is_empty());
}

#[tokio::test]
async fn a_mis_hashed_blob_is_refused_by_the_registry() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("mishashed").flaw(Flaw::MisHashedBlob).build();
    let fake = FakeRegistry::start(Mode::Normal).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::Status { status, .. } if *status == StatusCode::BAD_REQUEST),
        "{err:?}"
    );
    assert!(fake.manifest(REPO, &built.manifest_digest).is_none());
}

#[tokio::test]
async fn a_manifest_naming_a_missing_blob_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("missing").flaw(Flaw::MissingBlob).build();
    let fake = FakeRegistry::start(Mode::Normal).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::Status { method, .. } if method == http::Method::PUT),
        "{err:?}"
    );
}

#[tokio::test]
async fn deletes_a_manifest_by_digest_and_a_missing_one_counts_as_gone() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("delete").build();
    let fake = FakeRegistry::start(Mode::Normal).await;
    let registry = Registry::new(fake.addr());
    registry
        .push_image(REPO, &written(dir.path(), &built))
        .await
        .unwrap();

    registry
        .delete_manifest(REPO, &built.manifest_digest)
        .await
        .unwrap();
    assert!(fake.manifest(REPO, &built.manifest_digest).is_none());
    registry
        .delete_manifest(REPO, &built.manifest_digest)
        .await
        .unwrap();

    let deleted: Vec<_> = fake
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::ManifestDeleted { .. }))
        .collect();
    assert_eq!(
        deleted,
        [Event::ManifestDeleted {
            repository: REPO.to_owned(),
            digest: built.manifest_digest.clone()
        }]
    );
}

#[tokio::test]
async fn repository_names_are_checked() {
    let fake = FakeRegistry::start(Mode::Normal).await;
    let registry = Registry::new(fake.addr());
    let digest = Digest::from_sha256([1; 32]);
    let image = Image {
        manifest_digest: digest.clone(),
        manifest_media_type: String::new(),
        manifest: Vec::new(),
        blobs: Vec::new(),
    };
    for good in ["app", "example-org/app", "a.b_c-d/e9", "9/0"] {
        // Valid names reach the registry, which refuses the empty manifest.
        let err = registry.push_image(good, &image).await.unwrap_err();
        assert!(
            matches!(err, RegistryError::Status { .. }),
            "{good}: {err:?}"
        );
    }
    for bad in [
        "", "/", "app/", "/app", "a//b", "App", "a b", "-a", "a-", ".a", "a.", "a/../b", "a:b",
        "a@b", "a?x=1",
    ] {
        let pushed = registry.push_image(bad, &image).await.unwrap_err();
        let deleted = registry.delete_manifest(bad, &digest).await.unwrap_err();
        for err in [pushed, deleted] {
            assert!(
                matches!(&err, RegistryError::InvalidRepository { name } if name == bad),
                "{bad:?}: {err:?}"
            );
        }
    }
}

#[tokio::test]
async fn an_unreachable_registry_is_a_connect_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let err = Registry::new(addr.clone())
        .delete_manifest(REPO, &Digest::from_sha256([1; 32]))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::Connect { addr: a, .. } if *a == addr),
        "{err:?}"
    );
    assert!(err.to_string().contains(&addr), "{err}");
}

#[tokio::test]
async fn an_address_that_cannot_be_a_host_header_is_a_request_error() {
    let err = Registry::new("bad\nhost:1")
        .delete_manifest(REPO, &Digest::from_sha256([1; 32]))
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::Request { .. }), "{err:?}");
}

#[tokio::test]
async fn blob_files_that_cannot_be_opened_or_positioned_are_blob_read_errors() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("unreadable").build();
    let good = written(dir.path(), &built);
    let fake = FakeRegistry::start(Mode::Normal).await;
    let registry = Registry::new(fake.addr());

    let mut missing_file = good.clone();
    missing_file.blobs[0].path = dir.path().join("absent.tar");
    // An offset no file position can be (it is negative as an `off_t`).
    let mut impossible_offset = good.clone();
    impossible_offset.blobs[0].offset = u64::MAX;
    for (image, kind) in [
        (missing_file, std::io::ErrorKind::NotFound),
        (impossible_offset, std::io::ErrorKind::InvalidInput),
    ] {
        let err = registry.push_image(REPO, &image).await.unwrap_err();
        match &err {
            RegistryError::BlobRead { digest, source, .. } => {
                assert_eq!(*digest, image.blobs[0].digest);
                assert_eq!(source.kind(), kind);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            err.to_string().contains(image.blobs[0].digest.as_str()),
            "{err}"
        );
    }
    // No upload session was started for a blob that could not be opened.
    assert!(fake.events().is_empty());
}

#[tokio::test]
async fn a_range_past_the_end_of_the_file_fails_the_upload() {
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("short").build();
    let mut image = written(dir.path(), &built);
    image.blobs[0].offset = built.tar.len() as u64 - 1;
    let fake = FakeRegistry::start(Mode::Normal).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &image)
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::Transport { .. }), "{err:?}");
    assert!(!fake.has_blob(REPO, &image.blobs[0].digest));
}

#[tokio::test]
async fn a_read_failure_while_streaming_is_a_transport_error() {
    // A directory opens but cannot be read, so the body fails after the upload began.
    let dir = tempfile::tempdir().unwrap();
    let built = OciImage::new("directory").build();
    let mut image = written(dir.path(), &built);
    image.blobs[0].path = dir.path().to_owned();
    image.blobs[0].offset = 0;
    image.blobs[0].len = 1;
    let fake = FakeRegistry::start(Mode::Normal).await;
    let err = Registry::new(fake.addr())
        .push_image(REPO, &image)
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::Transport { .. }), "{err:?}");
    assert!(err.to_string().contains(&fake.addr()), "{err}");
}
