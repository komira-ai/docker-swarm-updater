//! Verifying and pushing a downloaded image tar (docs/design.md sections 3.3 and 3.4), shared
//! by the deploy runner and `import`.
//!
//! [`verify_tar`] reads the OCI layout tar from its file by offsets and checks, in this
//! order: `index.json` lists exactly the manifest `image_digest` (before anything else, so a
//! wrong URL or a tar of another digest is recognised as such); the Sigstore bundle
//! (`dsu-verify`); then every blob and the platform. [`push_tar`] writes what
//! [`verify_tar`] approved to the registry. Section 3.3 step 5 (the signed-time floor) needs
//! the service's state and is the caller's.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dsu_core::config::ServiceConfig;
use dsu_core::ids::Digest;
use dsu_core::oci::{Descriptor, OciError, check_index, check_platform, parse_manifest};
use dsu_core::record::ErrorToken;
use dsu_registry::{BlobSource, Image, Registry, RegistryError};
use dsu_verify::{TrustedRoots, VerifyError, VerifyInput, verify};
use sha2::{Digest as _, Sha256};

/// The largest JSON document (`index.json`, a manifest, an image config) read from a tar.
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

/// Why a tar was not verified or pushed.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The tar file cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The operating system error.
        source: io::Error,
    },
    /// `index.json` is missing, malformed, or does not list exactly the digest asked for.
    #[error("{0}")]
    Index(#[source] OciError),
    /// The bundle does not verify.
    #[error("{0}")]
    Verify(#[from] VerifyError),
    /// A blob is missing or mis-hashed, or the platform is not the service's.
    #[error("{0}")]
    Layout(#[source] OciError),
    /// The registry refused or failed.
    #[error("{0}")]
    Registry(#[from] RegistryError),
}

impl PipelineError {
    /// The error token of the deploy record.
    pub fn token(&self) -> ErrorToken {
        match self {
            Self::Read { .. } => ErrorToken::FetchFailed,
            Self::Index(e) | Self::Layout(e) => match e {
                OciError::DigestMismatch { .. } => ErrorToken::DigestMismatch,
                OciError::PlatformMismatch { .. } => ErrorToken::PlatformMismatch,
                OciError::TarInvalid(_) | OciError::BadPlatform(_) => ErrorToken::TarInvalid,
            },
            Self::Verify(VerifyError::Invalid { .. }) => ErrorToken::BundleInvalid,
            Self::Verify(VerifyError::Subject { .. }) => ErrorToken::BundleSubject,
            Self::Verify(VerifyError::Signer { .. }) => ErrorToken::BundleSigner,
            Self::Verify(VerifyError::Chain { .. }) => ErrorToken::BundleChain,
            Self::Registry(_) => ErrorToken::RegistryFailed,
        }
    }

    /// Whether the failure is bound to the digest asked for, that is, found after
    /// `index.json` named it (section 3.3: only such a failure may enter the failed list).
    pub fn digest_bound(&self) -> bool {
        matches!(self, Self::Verify(_) | Self::Layout(_))
    }

    /// One line for the record.
    pub fn detail(&self) -> String {
        self.to_string().replace('\n', " ")
    }
}

fn read_error(path: &Path) -> impl FnOnce(io::Error) -> PipelineError + '_ {
    move |source| PipelineError::Read {
        path: path.to_owned(),
        source,
    }
}

fn invalid(what: impl Into<String>) -> OciError {
    OciError::TarInvalid(what.into())
}

/// What [`verify_tar`] checks.
#[derive(Debug, Clone)]
pub struct VerifyJob {
    /// The image tar.
    pub tar: PathBuf,
    /// The SHA-256 of the whole tar file.
    pub tar_digest: Digest,
    /// The bundle file's bytes.
    pub bundle: Vec<u8>,
    /// The manifest digest the caller expects.
    pub image_digest: Digest,
    /// The service the image is for.
    pub service: ServiceConfig,
    /// The trusted roots.
    pub roots: Arc<TrustedRoots>,
}

/// A tar that passed every check of sections 3.3 steps 1 to 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTar {
    /// The bundle's verified signing time.
    pub signed_time: jiff::Timestamp,
    /// The image to push.
    pub image: Image,
}

/// The SHA-256 of the file `path`.
pub fn hash_file(path: &Path) -> Result<Digest, PipelineError> {
    let mut file = File::open(path).map_err(read_error(path))?;
    hash_reader(&mut file).map_err(read_error(path))
}

fn hash_reader(reader: &mut impl io::Read) -> io::Result<Digest> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            return Ok(Digest::from_sha256(hasher.finalize().into()));
        }
        hasher.update(&buffer[..n]);
    }
}

/// Where the regular files of the tar are: name to (offset of the content, length).
type Entries = BTreeMap<String, (u64, u64)>;

fn scan(path: &Path) -> Result<Entries, PipelineError> {
    let file = File::open(path).map_err(read_error(path))?;
    let mut archive = tar::Archive::new(file);
    let unreadable = |e: io::Error| {
        PipelineError::Index(invalid(format!("the file is not a readable tar: {e}")))
    };
    let mut entries = Entries::new();
    for entry in archive.entries_with_seek().map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        if entry.header().entry_type().is_file() {
            let name = entry
                .path()
                .map_err(unreadable)?
                .to_string_lossy()
                .into_owned();
            let name = name.trim_start_matches("./").to_owned();
            entries.insert(name, (entry.raw_file_position(), entry.size()));
        }
    }
    Ok(entries)
}

/// The bytes of the tar entry `name`, at most [`MAX_JSON_BYTES`] of them.
fn read_entry(
    path: &Path,
    entries: &Entries,
    name: &str,
    wrap: fn(OciError) -> PipelineError,
) -> Result<Vec<u8>, PipelineError> {
    let Some(&(offset, len)) = entries.get(name) else {
        return Err(wrap(invalid(format!("the tar has no {name}"))));
    };
    if len > MAX_JSON_BYTES {
        return Err(wrap(invalid(format!(
            "{name} is larger than {MAX_JSON_BYTES} bytes"
        ))));
    }
    let mut file = File::open(path).map_err(read_error(path))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(read_error(path))?;
    let mut bytes = Vec::new();
    file.take(len)
        .read_to_end(&mut bytes)
        .map_err(read_error(path))?;
    Ok(bytes)
}

/// Checks that the tar holds the blob `descriptor` names, of that size, hashing to its name.
fn check_blob(
    path: &Path,
    entries: &Entries,
    descriptor: &Descriptor,
) -> Result<BlobSource, PipelineError> {
    let layout = |what: String| PipelineError::Layout(invalid(what));
    let name = format!("blobs/sha256/{}", descriptor.digest.hex());
    let Some(&(offset, len)) = entries.get(&name) else {
        return Err(layout(format!(
            "blob {} is not in the tar",
            descriptor.digest
        )));
    };
    if len != descriptor.size {
        return Err(layout(format!(
            "blob {} is {len} bytes in the tar and {} in the manifest",
            descriptor.digest, descriptor.size
        )));
    }
    let mut file = File::open(path).map_err(read_error(path))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(read_error(path))?;
    let found = hash_reader(&mut file.take(len)).map_err(read_error(path))?;
    if found != descriptor.digest {
        return Err(layout(format!(
            "blob {} holds bytes that hash to {found}",
            descriptor.digest
        )));
    }
    Ok(BlobSource {
        digest: descriptor.digest.clone(),
        path: path.to_owned(),
        offset,
        len,
    })
}

/// Sections 3.3 steps 4 (first), 1 to 3, then 4 (the blobs and the platform) on a downloaded
/// tar and bundle. Blocking: it reads the whole tar; async callers run it on a blocking
/// thread.
pub fn verify_tar(job: &VerifyJob) -> Result<VerifiedTar, PipelineError> {
    let entries = scan(&job.tar)?;
    let index = read_entry(&job.tar, &entries, "index.json", PipelineError::Index)?;
    let manifest_ref = check_index(&index, &job.image_digest).map_err(PipelineError::Index)?;
    let verified = verify(&VerifyInput {
        bundle: &job.bundle,
        roots: &job.roots,
        tar_digest: &job.tar_digest,
        signer: &job.service.signer,
        artifact_name: &job.service.artifact_name,
    })?;
    check_blob(&job.tar, &entries, &manifest_ref)?;
    let name = format!("blobs/sha256/{}", manifest_ref.digest.hex());
    let manifest_bytes = read_entry(&job.tar, &entries, &name, PipelineError::Layout)?;
    let manifest = parse_manifest(&manifest_bytes).map_err(PipelineError::Layout)?;
    let mut seen = BTreeSet::new();
    let mut blobs = Vec::new();
    for descriptor in manifest.blobs().filter(|d| seen.insert(d.digest.clone())) {
        blobs.push(check_blob(&job.tar, &entries, descriptor)?);
    }
    let name = format!("blobs/sha256/{}", manifest.config.digest.hex());
    let config = read_entry(&job.tar, &entries, &name, PipelineError::Layout)?;
    check_platform(&config, &job.service.platform).map_err(PipelineError::Layout)?;
    Ok(VerifiedTar {
        signed_time: verified.signed_time,
        image: Image {
            manifest_digest: job.image_digest.clone(),
            manifest_media_type: manifest.media_type,
            manifest: manifest_bytes,
            blobs,
        },
    })
}

/// Section 3.4: writes the verified image's blobs and manifest to `repository` of the
/// registry, by digest.
pub async fn push_tar(
    registry: &Registry,
    repository: &str,
    verified: &VerifiedTar,
) -> Result<(), PipelineError> {
    Ok(registry.push_image(repository, &verified.image).await?)
}
