//! The OCI distribution API subset docker-swarm-updater uses to push by digest
//! (docs/design.md section 3.4): plain HTTP/1.1 to the configured `host:port`, one
//! connection per request. [`Registry::push_image`] writes an image's blobs and its
//! manifest, byte for byte, and checks that the registry names the manifest by the digest
//! that was attested; [`Registry::delete_manifest`] removes a manifest by digest.

mod error;
mod payload;

use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};

use bytes::Bytes;
use dsu_core::ids::Digest;
use http::header::{ACCEPT, CONTENT_TYPE, HOST, LOCATION};
use http::{HeaderMap, HeaderName, Method, Request, StatusCode, Uri};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
use tokio::net::TcpStream;

pub use crate::error::RegistryError;
use crate::payload::Payload;

/// The header in which a registry names the digest of a manifest.
const CONTENT_DIGEST: HeaderName = HeaderName::from_static("docker-content-digest");

/// Where the bytes of one blob are: a byte range of a file (a downloaded image tar).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobSource {
    /// The blob's digest; the registry checks the bytes against it.
    pub digest: Digest,
    /// The file holding the bytes.
    pub path: PathBuf,
    /// Offset of the first byte in the file.
    pub offset: u64,
    /// Number of bytes. A file that ends before the range does fails the upload.
    pub len: u64,
}

/// An image to push: its manifest and the blobs (config and layers) the manifest names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The manifest's digest, the reference it is pushed under.
    pub manifest_digest: Digest,
    /// The manifest's own media type, sent as its `Content-Type`.
    pub manifest_media_type: String,
    /// The manifest's exact bytes.
    pub manifest: Vec<u8>,
    /// The blobs to make present before the manifest is written.
    pub blobs: Vec<BlobSource>,
}

/// A client of one registry.
#[derive(Debug, Clone)]
pub struct Registry {
    addr: String,
}

/// What a request got back: its status and headers (the body is not needed).
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    method: Method,
    path: String,
}

impl Reply {
    fn unexpected(&self) -> RegistryError {
        RegistryError::Status {
            method: self.method.clone(),
            path: self.path.clone(),
            status: self.status,
        }
    }

    fn ensure_success(self) -> Result<Self, RegistryError> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(self.unexpected())
        }
    }
}

impl Registry {
    /// A client of the registry at `addr`, a `host:port` that `TcpStream::connect` accepts.
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// Writes `image` to `repository`: each blob the registry lacks is uploaded from its
    /// file range, then the manifest is written under its digest with its own media type,
    /// and the registry must name that digest when asked for the manifest.
    pub async fn push_image(&self, repository: &str, image: &Image) -> Result<(), RegistryError> {
        check_repository(repository)?;
        for blob in &image.blobs {
            if !self.blob_exists(repository, &blob.digest).await? {
                self.upload_blob(repository, blob).await?;
            }
        }
        let path = format!("/v2/{repository}/manifests/{}", image.manifest_digest);
        let media_type = image.manifest_media_type.as_str();
        let body = Payload::bytes(Bytes::from(image.manifest.clone()));
        self.call(Method::PUT, &path, &[(CONTENT_TYPE, media_type)], body)
            .await?
            .ensure_success()?;
        let reply = self
            .call(
                Method::HEAD,
                &path,
                &[(ACCEPT, media_type)],
                Payload::empty(),
            )
            .await?
            .ensure_success()?;
        let answered = reply
            .headers
            .get(CONTENT_DIGEST)
            .and_then(|v| v.to_str().ok());
        if answered == Some(image.manifest_digest.as_str()) {
            Ok(())
        } else {
            Err(RegistryError::ManifestDigest {
                expected: image.manifest_digest.clone(),
                answered: answered.map(str::to_owned),
            })
        }
    }

    /// Deletes the manifest `digest` from `repository`. A manifest the registry does not
    /// have counts as already gone.
    pub async fn delete_manifest(
        &self,
        repository: &str,
        digest: &Digest,
    ) -> Result<(), RegistryError> {
        check_repository(repository)?;
        let path = format!("/v2/{repository}/manifests/{digest}");
        let reply = self
            .call(Method::DELETE, &path, &[], Payload::empty())
            .await?;
        if reply.status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        reply.ensure_success().map(drop)
    }

    async fn blob_exists(&self, repository: &str, digest: &Digest) -> Result<bool, RegistryError> {
        let path = format!("/v2/{repository}/blobs/{digest}");
        let reply = self
            .call(Method::HEAD, &path, &[], Payload::empty())
            .await?;
        match reply.status {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(reply.unexpected()),
        }
    }

    /// Monolithic upload: open an upload session, then `PUT` the bytes with the digest.
    async fn upload_blob(&self, repository: &str, blob: &BlobSource) -> Result<(), RegistryError> {
        let body =
            open_at(&blob.path, blob.offset)
                .await
                .map_err(|source| RegistryError::BlobRead {
                    digest: blob.digest.clone(),
                    path: blob.path.clone(),
                    source,
                })?;
        let start_path = format!("/v2/{repository}/blobs/uploads/");
        let started = self
            .call(Method::POST, &start_path, &[], Payload::empty())
            .await?
            .ensure_success()?;
        let location = started
            .headers
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let target = upload_target(location, &blob.digest)?;
        let headers = [(CONTENT_TYPE, "application/octet-stream")];
        let payload = Payload::range(body, blob.len);
        self.call(Method::PUT, &target, &headers, payload)
            .await?
            .ensure_success()
            .map(drop)
    }

    /// One request on a fresh connection.
    async fn call(
        &self,
        method: Method,
        path: &str,
        headers: &[(HeaderName, &str)],
        body: Payload,
    ) -> Result<Reply, RegistryError> {
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(HOST, &self.addr);
        for (name, value) in headers {
            builder = builder.header(name, *value);
        }
        let request = builder
            .body(body)
            .map_err(|source| RegistryError::Request {
                method: method.clone(),
                path: path.to_owned(),
                source,
            })?;
        let stream =
            TcpStream::connect(&self.addr)
                .await
                .map_err(|source| RegistryError::Connect {
                    addr: self.addr.clone(),
                    source,
                })?;
        let transport = |source| RegistryError::Transport {
            addr: self.addr.clone(),
            method: method.clone(),
            path: path.to_owned(),
            source,
        };
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(transport)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.map_err(transport)?;
        Ok(Reply {
            status: response.status(),
            headers: response.headers().clone(),
            method: method.clone(),
            path: path.to_owned(),
        })
    }
}

/// The request target that finishes an upload: the registry's `Location` (an absolute URI
/// or a path; only its path and query are used, the request always goes to the configured
/// address) with the blob's digest added to the query.
fn upload_target(location: &str, digest: &Digest) -> Result<String, RegistryError> {
    let bad = || RegistryError::BadLocation {
        location: location.to_owned(),
    };
    let uri: Uri = location.parse().map_err(|_| bad())?;
    let target = uri.path_and_query().ok_or_else(bad)?;
    let separator = if target.query().is_some() { '&' } else { '?' };
    Ok(format!("{}{separator}digest={digest}", target.as_str()))
}

/// The file opened and positioned at `offset`.
async fn open_at(path: &Path, offset: u64) -> io::Result<File> {
    let mut file = File::open(path).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    Ok(file)
}

fn check_repository(name: &str) -> Result<(), RegistryError> {
    if name.split('/').all(valid_component) {
        Ok(())
    } else {
        Err(RegistryError::InvalidRepository {
            name: name.to_owned(),
        })
    }
}

/// One path component of a repository name: lower-case letters and digits, with `.`, `_`
/// and `-` allowed between them.
fn valid_component(component: &str) -> bool {
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = component.as_bytes();
    bytes.first().copied().is_some_and(alphanumeric)
        && bytes.last().copied().is_some_and(alphanumeric)
        && bytes
            .iter()
            .all(|&b| alphanumeric(b) || matches!(b, b'.' | b'_' | b'-'))
}
