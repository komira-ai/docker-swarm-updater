//! The Docker Engine API subset docker-swarm-updater uses, over a Unix socket: ping,
//! inspect and update a Swarm service, list the running tasks of a service and read the
//! updater's own Swarm service name from its container. One connection per request.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use dsu_core::ids::{DeployId, Digest};
use http::header::{CONTENT_TYPE, HOST};
use http::{HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use tokio::net::UnixStream;

/// Service label holding the id of the deploy that last changed the service.
pub const DEPLOY_LABEL: &str = "org.docker-swarm-updater.deploy";
/// Service label holding the image digest of the deploy that last changed the service.
pub const DIGEST_LABEL: &str = "org.docker-swarm-updater.digest";
/// Container label Swarm sets to the name of the service a task belongs to.
pub const SWARM_SERVICE_NAME_LABEL: &str = "com.docker.swarm.service.name";

/// The largest response body read from the daemon unless overridden: 16 MiB.
const DEFAULT_MAX_BODY: usize = 16 * 1024 * 1024;
/// The longest daemon message carried in an error, in characters.
const MAX_MESSAGE_CHARS: usize = 512;

/// A failed call to the Docker Engine API.
#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    /// The request target is not a valid URI (an over-long name or id).
    #[error("docker request target for {request} is not valid: {source}")]
    BadTarget {
        /// The request, `METHOD /path`, with the path cut to its start.
        request: String,
        /// Why the target was refused.
        source: http::uri::InvalidUri,
    },
    /// The socket could not be opened.
    #[error("cannot connect to the docker socket {}: {source}", socket.display())]
    Connect {
        /// The socket path.
        socket: PathBuf,
        /// The operating system error.
        source: std::io::Error,
    },
    /// The HTTP exchange with the daemon failed.
    #[error("docker request {request} failed: {source}")]
    Transport {
        /// The request, `METHOD /path`.
        request: String,
        /// The HTTP error.
        source: hyper::Error,
    },
    /// The response body is longer than the cap.
    #[error("docker response to {request} is longer than {limit} bytes")]
    BodyTooLarge {
        /// The request, `METHOD /path`.
        request: String,
        /// The cap in bytes.
        limit: usize,
    },
    /// The response is not JSON of the expected shape.
    #[error("docker response to {request} is not the expected {what}: {source}")]
    Decode {
        /// The request, `METHOD /path`.
        request: String,
        /// What was expected (`service`, `tasks`, `container`).
        what: &'static str,
        /// The JSON error.
        source: serde_json::Error,
    },
    /// A service spec lacks a field the updater needs, or the field has the wrong type.
    #[error("docker service data is malformed: {what} is missing or of the wrong type")]
    Malformed {
        /// The field, as a path in the spec.
        what: &'static str,
    },
    /// The service does not exist.
    #[error("docker service {service:?} not found")]
    ServiceNotFound {
        /// The name or id asked for.
        service: String,
    },
    /// An update was refused because the service changed since it was read.
    #[error("docker update refused as out of sequence: {message}")]
    VersionConflict {
        /// The daemon's message.
        message: String,
    },
    /// An update was refused by the daemon.
    #[error("docker refused the update with status {status}: {message}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The daemon's message.
        message: String,
    },
    /// A request got a status that the call does not expect.
    #[error("docker request {request} answered {status}: {message}")]
    Unexpected {
        /// The request, `METHOD /path`.
        request: String,
        /// The HTTP status.
        status: u16,
        /// The daemon's message.
        message: String,
    },
}

/// The `UpdateStatus` of a Swarm service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    /// `updating`, `paused`, `completed`, `rollback_started`, `rollback_paused` or
    /// `rollback_completed`.
    pub state: String,
    /// When the update that this status describes started.
    pub started_at: Option<jiff::Timestamp>,
    /// The daemon's message about the update.
    pub message: Option<String>,
}

/// What the updater reads of a Swarm service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    /// The service id.
    pub id: String,
    /// `Version.Index`, the number an update must quote.
    pub version_index: u64,
    /// The whole `Spec`, as read, so an update round-trips fields the updater does not know.
    pub spec: Value,
    /// The update status, when the service has been updated.
    pub update_status: Option<UpdateStatus>,
    /// `Spec.TaskTemplate.ContainerSpec.Image`.
    pub image: String,
    /// The image of `PreviousSpec`, when the service has one.
    pub previous_image: Option<String>,
    /// The [`DEPLOY_LABEL`] value of the spec.
    pub deploy_label: Option<String>,
    /// The [`DIGEST_LABEL`] value of the spec.
    pub digest_label: Option<String>,
}

/// One task of a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskView {
    /// The task id.
    pub id: String,
    /// The image the task runs.
    pub image: String,
    /// The task state (`running`, `starting`, `failed`, ...).
    pub state: String,
    /// The task's error text, when it has one.
    pub error: Option<String>,
}

/// The `{"message": ...}` body the daemon answers errors with.
#[derive(Deserialize)]
struct DaemonMessage {
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawVersion {
    index: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawUpdateStatus {
    state: String,
    started_at: Option<jiff::Timestamp>,
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawService {
    #[serde(rename = "ID")]
    id: String,
    version: RawVersion,
    spec: Value,
    previous_spec: Option<Value>,
    update_status: Option<RawUpdateStatus>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTask {
    #[serde(rename = "ID")]
    id: String,
    spec: RawTaskSpec,
    status: RawTaskStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTaskSpec {
    container_spec: RawContainerSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainerSpec {
    image: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawTaskStatus {
    state: String,
    err: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainer {
    config: RawContainerConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainerConfig {
    labels: Option<Map<String, Value>>,
}

/// The `Image` of a spec: `TaskTemplate.ContainerSpec.Image`.
fn spec_image(spec: &Value) -> Option<&str> {
    spec.pointer("/TaskTemplate/ContainerSpec/Image")
        .and_then(Value::as_str)
}

fn spec_label(spec: &Value, label: &str) -> Option<String> {
    spec.pointer("/Labels")?
        .get(label)?
        .as_str()
        .map(str::to_owned)
}

/// The spec an update sends: `spec` with `TaskTemplate.ContainerSpec.Image` set to `image`
/// and the labels [`DEPLOY_LABEL`] and [`DIGEST_LABEL`] set to `deploy_id` and `digest`
/// under `Labels`; nothing else differs.
pub fn updated_spec(
    spec: &Value,
    image: &str,
    deploy_id: &DeployId,
    digest: &Digest,
) -> Result<Value, DockerError> {
    let mut out = spec.clone();
    let Some(root) = out.as_object_mut() else {
        return Err(DockerError::Malformed { what: "Spec" });
    };
    let Some(container) = root
        .get_mut("TaskTemplate")
        .and_then(|template| template.get_mut("ContainerSpec"))
        .and_then(Value::as_object_mut)
    else {
        return Err(DockerError::Malformed {
            what: "TaskTemplate.ContainerSpec",
        });
    };
    container.insert("Image".to_owned(), Value::String(image.to_owned()));
    let labels = root.entry("Labels").or_insert(Value::Null);
    if labels.is_null() {
        *labels = Value::Object(Map::new());
    }
    let Some(labels) = labels.as_object_mut() else {
        return Err(DockerError::Malformed { what: "Labels" });
    };
    labels.insert(
        DEPLOY_LABEL.to_owned(),
        Value::String(deploy_id.to_string()),
    );
    labels.insert(DIGEST_LABEL.to_owned(), Value::String(digest.to_string()));
    Ok(out)
}

/// Percent-encodes everything but the RFC 3986 unreserved characters.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// One answer from the daemon.
struct Reply {
    request: String,
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    /// The daemon's `{"message": ...}` text, or the body itself when it is not that.
    fn message(&self) -> String {
        let text = serde_json::from_slice::<DaemonMessage>(&self.body).map_or_else(
            |_| String::from_utf8_lossy(&self.body).into_owned(),
            |m| m.message,
        );
        text.trim().chars().take(MAX_MESSAGE_CHARS).collect()
    }

    fn unexpected(&self) -> DockerError {
        DockerError::Unexpected {
            request: self.request.clone(),
            status: self.status.as_u16(),
            message: self.message(),
        }
    }

    fn decode<T: DeserializeOwned>(&self, what: &'static str) -> Result<T, DockerError> {
        serde_json::from_slice(&self.body).map_err(|source| DockerError::Decode {
            request: self.request.clone(),
            what,
            source,
        })
    }
}

/// A client of the Docker Engine API on a Unix socket.
#[derive(Debug, Clone)]
pub struct DockerClient {
    socket: PathBuf,
    max_body: usize,
}

impl DockerClient {
    /// A client of the daemon listening on `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            max_body: DEFAULT_MAX_BODY,
        }
    }

    /// The same client reading at most `bytes` of any response body (16 MiB by default).
    #[must_use]
    pub fn with_max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// The socket path.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// `GET /_ping`: the daemon answers.
    pub async fn ping(&self) -> Result<(), DockerError> {
        let reply = self.send(Method::GET, "/_ping".to_owned(), None).await?;
        if reply.status.is_success() {
            Ok(())
        } else {
            Err(reply.unexpected())
        }
    }

    /// `GET /services/{name-or-id}`.
    pub async fn inspect_service(&self, name_or_id: &str) -> Result<ServiceView, DockerError> {
        let reply = self
            .send(
                Method::GET,
                format!("/services/{}", percent_encode(name_or_id)),
                None,
            )
            .await?;
        if reply.status == StatusCode::NOT_FOUND {
            return Err(DockerError::ServiceNotFound {
                service: name_or_id.to_owned(),
            });
        }
        if !reply.status.is_success() {
            return Err(reply.unexpected());
        }
        let raw: RawService = reply.decode("service")?;
        let Some(image) = spec_image(&raw.spec).map(str::to_owned) else {
            return Err(DockerError::Malformed {
                what: "TaskTemplate.ContainerSpec.Image",
            });
        };
        Ok(ServiceView {
            id: raw.id,
            version_index: raw.version.index,
            update_status: raw.update_status.map(|s| UpdateStatus {
                state: s.state,
                started_at: s.started_at,
                message: s.message,
            }),
            image,
            previous_image: raw
                .previous_spec
                .as_ref()
                .and_then(spec_image)
                .map(str::to_owned),
            deploy_label: spec_label(&raw.spec, DEPLOY_LABEL),
            digest_label: spec_label(&raw.spec, DIGEST_LABEL),
            spec: raw.spec,
        })
    }

    /// `POST /services/{id}/update?version=N`: the spec of `service` with `image`, the deploy
    /// label and the digest label changed (see [`updated_spec`]), quoting the version read.
    /// [`DockerError::VersionConflict`] when the service changed since, so the caller can
    /// inspect again and retry; [`DockerError::Refused`] for any other refusal.
    pub async fn update_service(
        &self,
        service: &ServiceView,
        image: &str,
        deploy_id: &DeployId,
        digest: &Digest,
    ) -> Result<(), DockerError> {
        let body = updated_spec(&service.spec, image, deploy_id, digest)?
            .to_string()
            .into_bytes();
        let target = format!(
            "/services/{}/update?version={}",
            percent_encode(&service.id),
            service.version_index
        );
        let reply = self.send(Method::POST, target, Some(body)).await?;
        if reply.status.is_success() {
            return Ok(());
        }
        let message = reply.message();
        if message.contains("out of sequence") {
            Err(DockerError::VersionConflict { message })
        } else {
            Err(DockerError::Refused {
                status: reply.status.as_u16(),
                message,
            })
        }
    }

    /// `GET /tasks` filtered to the tasks of `service_id` whose desired state is `running`.
    pub async fn running_tasks(&self, service_id: &str) -> Result<Vec<TaskView>, DockerError> {
        let filters = serde_json::json!({"service": [service_id], "desired-state": ["running"]});
        let target = format!("/tasks?filters={}", percent_encode(&filters.to_string()));
        let reply = self.send(Method::GET, target, None).await?;
        if !reply.status.is_success() {
            return Err(reply.unexpected());
        }
        let tasks: Vec<RawTask> = reply.decode("tasks")?;
        Ok(tasks
            .into_iter()
            .map(|t| TaskView {
                id: t.id,
                image: t.spec.container_spec.image,
                state: t.status.state,
                error: t.status.err,
            })
            .collect())
    }

    /// The Swarm service name of the container `hostname` (`GET /containers/{hostname}/json`,
    /// label [`SWARM_SERVICE_NAME_LABEL`]); `None` when there is no such container or it
    /// belongs to no service.
    pub async fn own_service_name(&self, hostname: &str) -> Result<Option<String>, DockerError> {
        let reply = self
            .send(
                Method::GET,
                format!("/containers/{}/json", percent_encode(hostname)),
                None,
            )
            .await?;
        if reply.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !reply.status.is_success() {
            return Err(reply.unexpected());
        }
        let container: RawContainer = reply.decode("container")?;
        Ok(container.config.labels.and_then(|labels| {
            labels
                .get(SWARM_SERVICE_NAME_LABEL)
                .and_then(Value::as_str)
                .map(str::to_owned)
        }))
    }

    /// One request on a new connection; reads the whole answer, at most `max_body` bytes.
    async fn send(
        &self,
        method: Method,
        target: String,
        body: Option<Vec<u8>>,
    ) -> Result<Reply, DockerError> {
        let request = format!(
            "{method} {}",
            target.chars().take(MAX_MESSAGE_CHARS).collect::<String>()
        );
        let uri: Uri = target.parse().map_err(|source| DockerError::BadTarget {
            request: request.clone(),
            source,
        })?;
        let transport = |source| DockerError::Transport {
            request: request.clone(),
            source,
        };

        let stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|source| DockerError::Connect {
                    socket: self.socket.clone(),
                    source,
                })?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(transport)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut http_request = Request::new(Full::new(Bytes::from(body.unwrap_or_default())));
        *http_request.method_mut() = method;
        *http_request.uri_mut() = uri;
        http_request
            .headers_mut()
            .insert(HOST, HeaderValue::from_static("docker"));
        http_request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let response = sender.send_request(http_request).await.map_err(transport)?;
        let (parts, mut incoming) = response.into_parts();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let chunk = frame.map_err(transport)?.into_data().unwrap_or_default();
            if body.len() + chunk.len() > self.max_body {
                return Err(DockerError::BodyTooLarge {
                    request,
                    limit: self.max_body,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Reply {
            request,
            status: parts.status,
            body,
        })
    }
}
