//! The fake registry of docs/design.md section 6: the distribution API subset by digest on
//! `127.0.0.1:0`. It stores blobs and manifests, verifies uploaded digests, records what was
//! pushed and deleted, and has the failure modes the design names.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dsu_core::ids::Digest;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// How the registry misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Behaves as a registry should.
    Normal,
    /// `HEAD` on a manifest answers another digest in `Docker-Content-Digest`.
    AnswerOtherDigest,
    /// The final `PUT` of a blob upload answers 500.
    FailBlobUpload,
    /// Upload locations are absolute URIs instead of paths.
    AbsoluteLocation,
}

/// A change the registry accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A blob was uploaded and stored.
    BlobUploaded {
        /// The repository.
        repository: String,
        /// The blob's digest.
        digest: Digest,
    },
    /// A manifest was stored under its digest.
    ManifestPushed {
        /// The repository.
        repository: String,
        /// The manifest's digest.
        digest: Digest,
    },
    /// A manifest was deleted by its digest.
    ManifestDeleted {
        /// The repository.
        repository: String,
        /// The manifest's digest.
        digest: Digest,
    },
}

/// What `HEAD` answers for a manifest in [`Mode::AnswerOtherDigest`].
pub fn other_digest() -> Digest {
    Digest::from_sha256([0; 32])
}

struct State {
    mode: Mode,
    blobs: BTreeMap<(String, Digest), Vec<u8>>,
    manifests: BTreeMap<(String, Digest), (String, Vec<u8>)>,
    uploads: BTreeMap<String, String>,
    next_upload: u32,
    events: Vec<Event>,
}

/// A running fake registry; the server stops when it is dropped.
pub struct FakeRegistry {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl FakeRegistry {
    /// Starts a registry in `mode` on a free loopback port.
    pub async fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            mode,
            blobs: BTreeMap::new(),
            manifests: BTreeMap::new(),
            uploads: BTreeMap::new(),
            next_upload: 0,
            events: Vec::new(),
        }));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let state = shared.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(handle(&state, addr, req).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, state, task }
    }

    /// The registry's `host:port`.
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// The media type and bytes of the manifest `digest` in `repository`, if stored.
    pub fn manifest(&self, repository: &str, digest: &Digest) -> Option<(String, Vec<u8>)> {
        self.state
            .lock()
            .unwrap()
            .manifests
            .get(&(repository.to_owned(), digest.clone()))
            .cloned()
    }

    /// Whether the blob `digest` is stored in `repository`.
    pub fn has_blob(&self, repository: &str, digest: &Digest) -> bool {
        self.state
            .lock()
            .unwrap()
            .blobs
            .contains_key(&(repository.to_owned(), digest.clone()))
    }

    /// Every accepted change, in order.
    pub fn events(&self) -> Vec<Event> {
        self.state.lock().unwrap().events.clone()
    }
}

impl Drop for FakeRegistry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Route<'a> {
    UploadStart {
        repository: &'a str,
    },
    Upload {
        repository: &'a str,
        id: &'a str,
    },
    Blob {
        repository: &'a str,
        digest: &'a str,
    },
    Manifest {
        repository: &'a str,
        reference: &'a str,
    },
}

fn route(path: &str) -> Option<Route<'_>> {
    let rest = path.strip_prefix("/v2/")?;
    if let Some((repository, id)) = rest.split_once("/blobs/uploads/") {
        return Some(if id.is_empty() {
            Route::UploadStart { repository }
        } else {
            Route::Upload { repository, id }
        });
    }
    if let Some((repository, digest)) = rest.rsplit_once("/blobs/") {
        return Some(Route::Blob { repository, digest });
    }
    let (repository, reference) = rest.rsplit_once("/manifests/")?;
    Some(Route::Manifest {
        repository,
        reference,
    })
}

fn reply(status: StatusCode, headers: &[(&str, String)]) -> Response<Full<Bytes>> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    builder.body(Full::new(Bytes::new())).unwrap()
}

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::from_sha256(Sha256::digest(bytes).into())
}

/// The `digest` parameter of a query string.
fn digest_param(query: Option<&str>) -> Option<&str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("digest="))
}

async fn handle(
    state: &Mutex<State>,
    addr: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let mut state = state.lock().unwrap();
    let mode = state.mode;
    let route = route(parts.uri.path());
    match (&parts.method, route) {
        (&Method::POST, Some(Route::UploadStart { repository })) => {
            state.next_upload += 1;
            let id = format!("upload-{}", state.next_upload);
            state.uploads.insert(id.clone(), repository.to_owned());
            let path = format!("/v2/{repository}/blobs/uploads/{id}?_state={id}");
            let location = if mode == Mode::AbsoluteLocation {
                format!("http://{addr}{path}")
            } else {
                path
            };
            reply(StatusCode::ACCEPTED, &[("location", location)])
        }
        (&Method::PUT, Some(Route::Upload { repository, id })) => {
            if mode == Mode::FailBlobUpload {
                return reply(StatusCode::INTERNAL_SERVER_ERROR, &[]);
            }
            if state.uploads.get(id).map(String::as_str) != Some(repository) {
                return reply(StatusCode::NOT_FOUND, &[]);
            }
            let digest = digest_of(&body);
            if digest_param(parts.uri.query()) != Some(digest.as_str()) {
                return reply(StatusCode::BAD_REQUEST, &[]);
            }
            state.uploads.remove(id);
            state
                .blobs
                .insert((repository.to_owned(), digest.clone()), body.to_vec());
            state.events.push(Event::BlobUploaded {
                repository: repository.to_owned(),
                digest: digest.clone(),
            });
            reply(
                StatusCode::CREATED,
                &[("docker-content-digest", digest.to_string())],
            )
        }
        (&Method::HEAD, Some(Route::Blob { repository, digest })) => {
            let stored = Digest::parse(digest)
                .is_ok_and(|d| state.blobs.contains_key(&(repository.to_owned(), d)));
            reply(
                if stored {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                },
                &[],
            )
        }
        (
            &Method::PUT,
            Some(Route::Manifest {
                repository,
                reference,
            }),
        ) => {
            let media_type = parts
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let Some(manifest_digest) = Digest::parse(reference)
                .ok()
                .filter(|d| *d == digest_of(&body))
            else {
                return reply(StatusCode::BAD_REQUEST, &[]);
            };
            let Some(referenced) = referenced_digests(&body) else {
                return reply(StatusCode::BAD_REQUEST, &[]);
            };
            if referenced.iter().any(|d| {
                !state
                    .blobs
                    .contains_key(&(repository.to_owned(), d.clone()))
            }) {
                return reply(StatusCode::BAD_REQUEST, &[]);
            }
            state.manifests.insert(
                (repository.to_owned(), manifest_digest.clone()),
                (media_type, body.to_vec()),
            );
            state.events.push(Event::ManifestPushed {
                repository: repository.to_owned(),
                digest: manifest_digest.clone(),
            });
            reply(
                StatusCode::CREATED,
                &[("docker-content-digest", manifest_digest.to_string())],
            )
        }
        (
            &Method::HEAD,
            Some(Route::Manifest {
                repository,
                reference,
            }),
        ) => {
            let stored = Digest::parse(reference).ok().filter(|d| {
                state
                    .manifests
                    .contains_key(&(repository.to_owned(), d.clone()))
            });
            match stored {
                None => reply(StatusCode::NOT_FOUND, &[]),
                Some(digest) => {
                    let answered = if mode == Mode::AnswerOtherDigest {
                        other_digest()
                    } else {
                        digest
                    };
                    reply(
                        StatusCode::OK,
                        &[("docker-content-digest", answered.to_string())],
                    )
                }
            }
        }
        (
            &Method::DELETE,
            Some(Route::Manifest {
                repository,
                reference,
            }),
        ) => {
            let removed = Digest::parse(reference).ok().filter(|d| {
                state
                    .manifests
                    .remove(&(repository.to_owned(), d.clone()))
                    .is_some()
            });
            match removed {
                None => reply(StatusCode::NOT_FOUND, &[]),
                Some(digest) => {
                    state.events.push(Event::ManifestDeleted {
                        repository: repository.to_owned(),
                        digest,
                    });
                    reply(StatusCode::ACCEPTED, &[])
                }
            }
        }
        (_, Some(_)) => reply(StatusCode::METHOD_NOT_ALLOWED, &[]),
        (_, None) => reply(StatusCode::NOT_FOUND, &[]),
    }
}

/// The config and layer digests a manifest names; `None` when it is not a JSON manifest.
fn referenced_digests(manifest: &[u8]) -> Option<Vec<Digest>> {
    let value: serde_json::Value = serde_json::from_slice(manifest).ok()?;
    let layers = value["layers"].as_array()?;
    let config = std::iter::once(&value["config"]);
    config
        .chain(layers)
        .map(|d| Digest::parse(d["digest"].as_str()?).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::OciImage;

    /// One request on a fresh connection: status, headers and body.
    async fn request(
        registry: &FakeRegistry,
        method: Method,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, http::HeaderMap) {
        let stream = tokio::net::TcpStream::connect(registry.addr())
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .header("host", registry.addr());
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = sender
            .send_request(
                builder
                    .body(Full::new(Bytes::copy_from_slice(body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        (response.status(), response.headers().clone())
    }

    fn location(headers: &http::HeaderMap) -> String {
        headers["location"].to_str().unwrap().to_owned()
    }

    async fn upload(
        registry: &FakeRegistry,
        repo: &str,
        bytes: &[u8],
        digest: &Digest,
    ) -> StatusCode {
        let (status, headers) = request(
            registry,
            Method::POST,
            &format!("/v2/{repo}/blobs/uploads/"),
            &[],
            b"",
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let target = format!("{}&digest={digest}", location(&headers));
        request(registry, Method::PUT, &target, &[], bytes).await.0
    }

    #[tokio::test]
    async fn blob_upload_then_head() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let digest = digest_of(b"blob");
        let target = format!("/v2/example-org/app/blobs/{digest}");
        assert_eq!(
            request(&registry, Method::HEAD, &target, &[], b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            upload(&registry, "example-org/app", b"blob", &digest).await,
            StatusCode::CREATED
        );
        assert_eq!(
            request(&registry, Method::HEAD, &target, &[], b"").await.0,
            StatusCode::OK
        );
        assert!(registry.has_blob("example-org/app", &digest));
        assert!(!registry.has_blob("other/app", &digest));
        assert_eq!(
            registry.events(),
            [Event::BlobUploaded {
                repository: "example-org/app".into(),
                digest
            }]
        );
    }

    #[tokio::test]
    async fn blob_head_of_a_malformed_digest_is_not_found() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let status = request(
            &registry,
            Method::HEAD,
            "/v2/example-org/app/blobs/latest",
            &[],
            b"",
        )
        .await
        .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn upload_with_the_wrong_digest_is_refused() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let wrong = digest_of(b"other");
        assert_eq!(
            upload(&registry, "example-org/app", b"blob", &wrong).await,
            StatusCode::BAD_REQUEST
        );
        assert!(!registry.has_blob("example-org/app", &wrong));
        assert!(registry.events().is_empty());
    }

    #[tokio::test]
    async fn upload_without_a_digest_is_refused() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let (_, headers) = request(
            &registry,
            Method::POST,
            "/v2/example-org/app/blobs/uploads/",
            &[],
            b"",
        )
        .await;
        let status = request(&registry, Method::PUT, &location(&headers), &[], b"blob")
            .await
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_session_is_unknown_elsewhere_and_after_use() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let digest = digest_of(b"blob");
        let (_, headers) = request(
            &registry,
            Method::POST,
            "/v2/example-org/app/blobs/uploads/",
            &[],
            b"",
        )
        .await;
        let started = location(&headers);
        let other_repo = started.replace("example-org/app", "other/app");
        let status = request(
            &registry,
            Method::PUT,
            &format!("{other_repo}&digest={digest}"),
            &[],
            b"blob",
        )
        .await
        .0;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let finish = format!("{started}&digest={digest}");
        assert_eq!(
            request(&registry, Method::PUT, &finish, &[], b"blob")
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            request(&registry, Method::PUT, &finish, &[], b"blob")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn absolute_locations() {
        let registry = FakeRegistry::start(Mode::AbsoluteLocation).await;
        let (_, headers) = request(
            &registry,
            Method::POST,
            "/v2/example-org/app/blobs/uploads/",
            &[],
            b"",
        )
        .await;
        assert!(location(&headers).starts_with(&format!(
            "http://{}/v2/example-org/app/blobs/uploads/",
            registry.addr()
        )));
    }

    #[tokio::test]
    async fn failing_blob_upload() {
        let registry = FakeRegistry::start(Mode::FailBlobUpload).await;
        let digest = digest_of(b"blob");
        assert_eq!(
            upload(&registry, "example-org/app", b"blob", &digest).await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!registry.has_blob("example-org/app", &digest));
    }

    /// Pushes the blobs of `image`, then returns the target of its manifest.
    async fn push_blobs(registry: &FakeRegistry, image: &crate::oci::BuiltImage) -> String {
        for blob in &image.blobs {
            let start = blob.offset as usize;
            let bytes = &image.tar[start..start + blob.len as usize];
            if blob.digest != image.manifest_digest {
                assert_eq!(
                    upload(registry, "example-org/app", bytes, &blob.digest).await,
                    StatusCode::CREATED
                );
            }
        }
        format!("/v2/example-org/app/manifests/{}", image.manifest_digest)
    }

    #[tokio::test]
    async fn manifest_push_head_delete() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let image = OciImage::new("registry").build();
        let target = push_blobs(&registry, &image).await;
        assert_eq!(
            request(&registry, Method::HEAD, &target, &[], b"").await.0,
            StatusCode::NOT_FOUND
        );
        let put = request(
            &registry,
            Method::PUT,
            &target,
            &[("content-type", image.media_type)],
            &image.manifest,
        )
        .await;
        assert_eq!(put.0, StatusCode::CREATED);
        assert_eq!(
            registry.manifest("example-org/app", &image.manifest_digest),
            Some((image.media_type.into(), image.manifest.clone()))
        );
        let head = request(&registry, Method::HEAD, &target, &[], b"").await;
        assert_eq!(head.0, StatusCode::OK);
        assert_eq!(
            head.1["docker-content-digest"],
            image.manifest_digest.as_str()
        );
        assert_eq!(
            request(&registry, Method::DELETE, &target, &[], b"")
                .await
                .0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            request(&registry, Method::DELETE, &target, &[], b"")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            registry.manifest("example-org/app", &image.manifest_digest),
            None
        );
        let events = registry.events();
        assert_eq!(
            events[events.len() - 2..],
            [
                Event::ManifestPushed {
                    repository: "example-org/app".into(),
                    digest: image.manifest_digest.clone()
                },
                Event::ManifestDeleted {
                    repository: "example-org/app".into(),
                    digest: image.manifest_digest.clone()
                },
            ]
        );
    }

    #[tokio::test]
    async fn manifest_without_content_type_is_stored_with_an_empty_type() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let image = OciImage::new("registry").build();
        let target = push_blobs(&registry, &image).await;
        assert_eq!(
            request(&registry, Method::PUT, &target, &[], &image.manifest)
                .await
                .0,
            StatusCode::CREATED
        );
        assert_eq!(
            registry
                .manifest("example-org/app", &image.manifest_digest)
                .unwrap()
                .0,
            ""
        );
    }

    #[tokio::test]
    async fn manifest_pushes_are_checked() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        let image = OciImage::new("registry").build();
        let target = format!("/v2/example-org/app/manifests/{}", image.manifest_digest);
        // The blobs are missing.
        assert_eq!(
            request(&registry, Method::PUT, &target, &[], &image.manifest)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        push_blobs(&registry, &image).await;
        // The path digest is not the bytes' digest, is a tag, or the bytes are not a manifest.
        let wrong = format!("/v2/example-org/app/manifests/{}", digest_of(b"x"));
        assert_eq!(
            request(&registry, Method::PUT, &wrong, &[], &image.manifest)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let tag = "/v2/example-org/app/manifests/latest";
        assert_eq!(
            request(&registry, Method::PUT, tag, &[], &image.manifest)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let junk = format!("/v2/example-org/app/manifests/{}", digest_of(b"junk"));
        assert_eq!(
            request(&registry, Method::PUT, &junk, &[], b"junk").await.0,
            StatusCode::BAD_REQUEST
        );
        let bad_digest = br#"{"config":{"digest":"x"},"layers":[]}"#;
        let bad = format!("/v2/example-org/app/manifests/{}", digest_of(bad_digest));
        assert_eq!(
            request(&registry, Method::PUT, &bad, &[], bad_digest)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert!(
            registry
                .events()
                .iter()
                .all(|e| matches!(e, Event::BlobUploaded { .. }))
        );
    }

    #[tokio::test]
    async fn other_digest_mode_answers_another_digest() {
        let registry = FakeRegistry::start(Mode::AnswerOtherDigest).await;
        let image = OciImage::new("registry").build();
        let target = push_blobs(&registry, &image).await;
        assert_eq!(
            request(&registry, Method::PUT, &target, &[], &image.manifest)
                .await
                .0,
            StatusCode::CREATED
        );
        let head = request(&registry, Method::HEAD, &target, &[], b"").await;
        assert_eq!(head.1["docker-content-digest"], other_digest().as_str());
    }

    #[tokio::test]
    async fn deleting_a_tag_or_unknown_manifest_is_not_found() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        for reference in ["latest".to_owned(), digest_of(b"none").to_string()] {
            let target = format!("/v2/example-org/app/manifests/{reference}");
            assert_eq!(
                request(&registry, Method::DELETE, &target, &[], b"")
                    .await
                    .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                request(&registry, Method::HEAD, &target, &[], b"").await.0,
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn unknown_routes_and_methods() {
        let registry = FakeRegistry::start(Mode::Normal).await;
        for target in ["/", "/v2/", "/v2/example-org/app/tags/list", "/other"] {
            assert_eq!(
                request(&registry, Method::GET, target, &[], b"").await.0,
                StatusCode::NOT_FOUND
            );
        }
        let digest = digest_of(b"blob");
        for target in [
            format!("/v2/example-org/app/blobs/{digest}"),
            format!("/v2/example-org/app/manifests/{digest}"),
            "/v2/example-org/app/blobs/uploads/".to_owned(),
            "/v2/example-org/app/blobs/uploads/upload-1".to_owned(),
        ] {
            let status = request(&registry, Method::PATCH, &target, &[], b"").await.0;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    #[test]
    fn digest_param_finds_the_digest_among_others() {
        assert_eq!(digest_param(None), None);
        assert_eq!(digest_param(Some("_state=x")), None);
        assert_eq!(
            digest_param(Some("_state=x&digest=sha256:a")),
            Some("sha256:a")
        );
    }
}
