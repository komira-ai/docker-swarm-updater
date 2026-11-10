//! `dsu-registry` against registries that answer what a script says: the answers a
//! well-behaved registry never gives.

use std::sync::Arc;

use bytes::Bytes;
use dsu_core::ids::Digest;
use dsu_registry::{BlobSource, Image, Registry, RegistryError};
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const REPO: &str = "example-org/app";
const MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// What the scripted registry answers: a status and headers, or (no status) hanging up.
struct Answer(Option<StatusCode>, Vec<(&'static str, String)>);

fn answer(status: u16) -> Answer {
    Answer(Some(StatusCode::from_u16(status).unwrap()), Vec::new())
}

fn hangup() -> Answer {
    Answer(None, Vec::new())
}

fn with(mut a: Answer, name: &'static str, value: &str) -> Answer {
    a.1.push((name, value.to_owned()));
    a
}

/// A registry on a loopback port that answers each request (method and target) with
/// `script`; stops when dropped.
struct Scripted {
    addr: String,
    task: JoinHandle<()>,
}

impl Scripted {
    async fn start(
        script: impl Fn(&Method, &str) -> Answer + Clone + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let script = script.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let Answer(status, headers) = script(req.method(), &req.uri().to_string());
                        let result = match status {
                            None => Err(std::io::Error::other("hang up")),
                            Some(status) => {
                                let mut response = Response::builder().status(status);
                                for (name, value) in headers {
                                    response = response.header(name, value);
                                }
                                Ok(response.body(Full::new(Bytes::new())).unwrap())
                            }
                        };
                        async move { result }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, task }
    }

    fn registry(&self) -> Registry {
        Registry::new(self.addr.clone())
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn digest() -> Digest {
    Digest::from_sha256([3; 32])
}

/// An image with one blob (the bytes `blob` in a temporary file) and a manifest the
/// scripted registries never inspect.
fn image(dir: &tempfile::TempDir) -> Image {
    let path = dir.path().join("blob");
    std::fs::write(&path, b"blob").unwrap();
    Image {
        manifest_digest: digest(),
        manifest_media_type: MEDIA_TYPE.to_owned(),
        manifest: b"{}".to_vec(),
        blobs: vec![BlobSource {
            digest: Digest::from_sha256([4; 32]),
            path,
            offset: 0,
            len: 4,
        }],
    }
}

fn manifest_path() -> String {
    format!("/v2/{REPO}/manifests/{}", digest())
}

fn blob_path() -> String {
    format!("/v2/{REPO}/blobs/{}", Digest::from_sha256([4; 32]))
}

const UPLOADS: &str = "/v2/example-org/app/blobs/uploads/";

/// A script that answers a well-behaved registry's answers, except where `deviate` has one.
fn script(
    deviate: impl Fn(&Method, &str) -> Option<Answer> + Clone + Send + Sync + 'static,
    location: &'static str,
) -> impl Fn(&Method, &str) -> Answer + Clone + Send + Sync + 'static {
    move |method, target| {
        if let Some(a) = deviate(method, target) {
            return a;
        }
        match (method.as_str(), target) {
            ("HEAD", t) if t == blob_path() => answer(404),
            ("POST", UPLOADS) => with(answer(202), "location", location),
            ("PUT", t) if t.starts_with("/v2/example-org/app/blobs/uploads/") => answer(201),
            ("PUT", t) if t == manifest_path() => answer(201),
            ("HEAD", t) if t == manifest_path() => {
                with(answer(200), "docker-content-digest", digest().as_str())
            }
            _ => answer(500),
        }
    }
}

fn status_error(err: &RegistryError) -> (&Method, &str, StatusCode) {
    match err {
        RegistryError::Status {
            method,
            path,
            status,
        } => (method, path, *status),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn the_scripted_registry_accepts_a_push() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Scripted::start(script(
        |_, _| None,
        "/v2/example-org/app/blobs/uploads/u1?_state=s",
    ))
    .await;
    registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_location_without_a_query_gets_the_digest_as_its_query() {
    let dir = tempfile::tempdir().unwrap();
    let expected = format!(
        "/v2/example-org/app/blobs/uploads/u1?digest={}",
        Digest::from_sha256([4; 32])
    );
    let registry = Scripted::start(script(
        move |method, target| {
            (method == Method::PUT && target.contains("uploads/u1")).then(|| {
                if target == expected {
                    answer(201)
                } else {
                    answer(400)
                }
            })
        },
        "/v2/example-org/app/blobs/uploads/u1",
    ))
    .await;
    registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_location_with_a_query_gets_the_digest_added_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let expected = format!(
        "/v2/example-org/app/blobs/uploads/u1?_state=s&digest={}",
        Digest::from_sha256([4; 32])
    );
    let registry = Scripted::start(script(
        move |method, target| {
            (method == Method::PUT && target.contains("uploads/u1")).then(|| {
                if target == expected {
                    answer(201)
                } else {
                    answer(400)
                }
            })
        },
        "/v2/example-org/app/blobs/uploads/u1?_state=s",
    ))
    .await;
    registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_absolute_location_on_another_host_is_sent_to_the_configured_address() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Scripted::start(script(
        |_, _| None,
        "http://registry.example.test:5000/v2/example-org/app/blobs/uploads/u2?_state=s",
    ))
    .await;
    registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_unusable_location_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for location in ["", "uuid", "http://[bad", "/v2/a b"] {
        let registry = Scripted::start(script(|_, _| None, location)).await;
        let err = registry
            .registry()
            .push_image(REPO, &image(&dir))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, RegistryError::BadLocation { location: l } if l == location),
            "{location:?}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_missing_location_header_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Scripted::start(|method, target| match (method.as_str(), target) {
        ("HEAD", _) => answer(404),
        _ => answer(202),
    })
    .await;
    let err = registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::BadLocation { location } if location.is_empty()),
        "{err:?}"
    );
}

#[tokio::test]
async fn unexpected_statuses_name_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let loc = "/v2/example-org/app/blobs/uploads/u1?_state=s";
    type Deviation = Arc<dyn Fn(&Method, &str) -> Option<Answer> + Send + Sync>;
    let cases: Vec<(&str, Deviation, Method, String, u16)> = vec![
        (
            "blob head",
            Arc::new(|m, t| (m == Method::HEAD && t == blob_path()).then(|| answer(503))),
            Method::HEAD,
            blob_path(),
            503,
        ),
        (
            "upload start",
            Arc::new(|m, t| (m == Method::POST && t == UPLOADS).then(|| answer(401))),
            Method::POST,
            UPLOADS.to_owned(),
            401,
        ),
        (
            "upload finish",
            Arc::new(|m, t| (m == Method::PUT && t.contains("uploads/u1")).then(|| answer(400))),
            Method::PUT,
            format!("{loc}&digest={}", Digest::from_sha256([4; 32])),
            400,
        ),
        (
            "manifest put",
            Arc::new(|m, t| (m == Method::PUT && t == manifest_path()).then(|| answer(400))),
            Method::PUT,
            manifest_path(),
            400,
        ),
        (
            "manifest head",
            Arc::new(|m, t| (m == Method::HEAD && t == manifest_path()).then(|| answer(404))),
            Method::HEAD,
            manifest_path(),
            404,
        ),
    ];
    for (name, deviate, method, path, status) in cases {
        let registry = Scripted::start(script(
            move |m, t| deviate(m, t),
            "/v2/example-org/app/blobs/uploads/u1?_state=s",
        ))
        .await;
        let err = registry
            .registry()
            .push_image(REPO, &image(&dir))
            .await
            .unwrap_err();
        let (got_method, got_path, got_status) = status_error(&err);
        assert_eq!(
            (got_method, got_path, got_status.as_u16()),
            (&method, path.as_str(), status),
            "{name}"
        );
        assert!(
            err.to_string().contains(&status.to_string()),
            "{name}: {err}"
        );
    }
}

#[tokio::test]
async fn a_manifest_head_without_the_digest_header_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Scripted::start(script(
        |m, t| (m == Method::HEAD && t == manifest_path()).then(|| answer(200)),
        "/v2/example-org/app/blobs/uploads/u1?_state=s",
    ))
    .await;
    let err = registry
        .registry()
        .push_image(REPO, &image(&dir))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RegistryError::ManifestDigest { answered: None, .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn delete_statuses() {
    let target = manifest_path();
    for (status, ok) in [
        (202, true),
        (200, true),
        (404, true),
        (400, false),
        (500, false),
    ] {
        let registry = Scripted::start(move |_, _| answer(status)).await;
        let result = registry.registry().delete_manifest(REPO, &digest()).await;
        match (ok, result) {
            (true, Ok(())) => {}
            (false, Err(err)) => {
                let (method, path, got) = status_error(&err);
                assert_eq!(
                    (method, path, got.as_u16()),
                    (&Method::DELETE, target.as_str(), status)
                );
            }
            (_, other) => panic!("{status}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_registry_that_hangs_up_is_a_transport_error_at_every_step() {
    let dir = tempfile::tempdir().unwrap();
    let steps = [
        (Method::HEAD, blob_path()),
        (Method::POST, UPLOADS.to_owned()),
        (
            Method::PUT,
            "/v2/example-org/app/blobs/uploads/u1?_state=s&digest=".to_owned(),
        ),
        (Method::PUT, manifest_path()),
        (Method::HEAD, manifest_path()),
    ];
    for (hangup_method, hangup_target) in steps {
        let registry = Scripted::start(script(
            {
                let (method, target) = (hangup_method.clone(), hangup_target.clone());
                move |m, t| (*m == method && t.starts_with(&target)).then(hangup)
            },
            "/v2/example-org/app/blobs/uploads/u1?_state=s",
        ))
        .await;
        let err = registry
            .registry()
            .push_image(REPO, &image(&dir))
            .await
            .unwrap_err();
        match &err {
            RegistryError::Transport { method, path, .. } => {
                assert_eq!(
                    (method, path.starts_with(&hangup_target)),
                    (&hangup_method, true)
                );
            }
            other => panic!("{other:?}"),
        }
    }
    let registry = Scripted::start(|_, _| hangup()).await;
    let err = registry
        .registry()
        .delete_manifest(REPO, &digest())
        .await
        .unwrap_err();
    assert!(matches!(err, RegistryError::Transport { .. }), "{err:?}");
    assert!(err.to_string().contains(&registry.addr), "{err}");
}
