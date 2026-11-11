//! The HTTP server on a Unix socket (docs/design.md sections 1 and 2): the socket and its
//! directory with their modes, one task per connection, the credentials of each connection's
//! peer, the dispatch of each request through the route, peer and claims checks to its
//! handler, and a log line for each request refused 401 or 403.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dsu_core::api::ApiError;
use dsu_core::route::{Route, RouteRefusal, route};
use http::header::{ALLOW, CONTENT_TYPE};
use http::request::Parts;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::task::JoinSet;

use crate::app::App;
use crate::auth::authenticate;
use crate::handlers::{self, Reply};
use crate::peer::Credentials;
use crate::startup::StartError;

/// How long a connection may take to send a request head, or sit idle between requests.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The server stopped on an error.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Accepting a connection failed.
    #[error("cannot accept a connection: {0}")]
    Accept(#[from] io::Error),
}

/// A refused request: the error and, for 405, the method the path answers.
struct Failure {
    error: ApiError,
    allow: Option<&'static str>,
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Failure { error, allow: None }
    }
}

impl From<RouteRefusal> for Failure {
    fn from(refusal: RouteRefusal) -> Self {
        let allow = match refusal {
            RouteRefusal::MethodNotAllowed { allow } => Some(allow),
            RouteRefusal::NotFound => None,
        };
        Failure {
            error: refusal.into(),
            allow,
        }
    }
}

fn response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// The peer of a connection: the kernel's credentials, or why they cannot be read.
type Peer = Result<Credentials, String>;

/// Routes and answers one request from `peer`.
async fn respond(
    app: &Arc<App>,
    peer: &Peer,
    parts: &Parts,
    body: Incoming,
) -> Result<Reply, Failure> {
    let origin_form = parts.uri.scheme().is_none() && parts.uri.authority().is_none();
    let target = parts
        .uri
        .path_and_query()
        .filter(|_| origin_form)
        .map_or(&b""[..], |p| p.as_str().as_bytes());
    let route = route(parts.method.as_str(), target)?;
    let peer_uid = peer.as_ref().map(|c| c.uid).map_err(String::as_str);
    let auth = authenticate(app, peer_uid, route == Route::Health, &parts.headers).await?;
    Ok(match route {
        Route::Deploy { service } => handlers::deploy(app, &auth, &service, body).await?,
        Route::Status { id } => handlers::status(app, &auth, &id).await?,
        Route::List => handlers::list(app, &auth).await?,
        Route::ClearFailed { service, digest } => {
            handlers::clear_failed(app, &auth, &service, &digest).await?
        }
        Route::Health => handlers::health(app).await?,
    })
}

/// The log line of a request refused 401 or 403: what was asked, the answer, and the peer.
fn refusal_line(peer: &Peer, parts: &Parts, error: &ApiError) -> String {
    let peer = match peer {
        Ok(credentials) => credentials.to_string(),
        Err(_) => "with unreadable credentials".to_owned(),
    };
    format!(
        "refused {} {} from peer {peer}: {} {error}",
        parts.method,
        parts.uri.path(),
        error.status()
    )
}

async fn handle(
    app: Arc<App>,
    peer: Peer,
    request: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    Ok(match respond(&app, &peer, &parts, body).await {
        Ok(reply) => response(reply.status, reply.body),
        Err(failure) => {
            if matches!(failure.error.status(), 401 | 403) {
                app.log.line(&refusal_line(&peer, &parts, &failure.error));
            }
            let status = StatusCode::from_u16(failure.error.status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut answer = response(status, failure.error.to_json().into_bytes());
            if let Some(allow) = failure.allow {
                answer
                    .headers_mut()
                    .insert(ALLOW, HeaderValue::from_static(allow));
            }
            answer
        }
    })
}

/// Serves one connection until it ends. A connection whose peer's credentials cannot be read
/// is served too: health is answered, every other request is refused 401 `bad_peer` with the
/// reason, and logged.
async fn connection(app: Arc<App>, stream: UnixStream) {
    let peer: Peer = app
        .peer_cred
        .credentials(&stream)
        .map_err(|e| e.to_string());
    let service = service_fn(move |request| handle(Arc::clone(&app), peer.clone(), request));
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(IDLE_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

/// Accepts connections on `listener` until `shutdown` resolves; open connections are then
/// dropped.
pub async fn serve(
    app: Arc<App>,
    listener: UnixListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let mut connections = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                connections.spawn(connection(Arc::clone(&app), stream));
            }
            // Reap the connections that ended, so the set does not grow with every request.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// A stop request: `SIGTERM` or `SIGINT`.
#[derive(Debug)]
pub struct Shutdown {
    terminate: Signal,
    interrupt: Signal,
}

impl Shutdown {
    /// Installs the signal handlers. From here on a stop signal is remembered until
    /// [`Shutdown::wait`] sees it.
    pub fn install() -> Result<Shutdown, StartError> {
        Ok(Shutdown {
            terminate: signal(SignalKind::terminate()).map_err(StartError::Signals)?,
            interrupt: signal(SignalKind::interrupt()).map_err(StartError::Signals)?,
        })
    }

    /// Resolves when a stop signal arrives.
    pub async fn wait(mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

fn socket_error<'a>(
    flag: &'static str,
    action: &'static str,
    path: &'a Path,
) -> impl FnOnce(io::Error) -> StartError + 'a {
    move |source| StartError::Socket {
        flag,
        action,
        path: path.to_owned(),
        source,
    }
}

fn set_group(path: &Path, group: u32) -> Result<(), StartError> {
    rustix::fs::chown(path, None, Some(rustix::fs::Gid::from_raw(group)))
        .map_err(io::Error::from)
        .map_err(socket_error("--socket-group", "change the group of", path))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), StartError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(socket_error(
        "--socket",
        "set the mode of",
        path,
    ))
}

/// The directory of the socket: created with mode 0750 and group `group` when missing; an
/// existing one must not be accessible to other users (it is never changed).
fn prepare_directory(dir: &Path, group: u32) -> Result<(), StartError> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.mode() & 0o007 != 0 => Err(StartError::SocketDirOpen {
            path: dir.to_owned(),
            mode: meta.mode() & 0o7777,
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o750)
                .create(dir)
                .map_err(socket_error("--socket", "create the directory", dir))?;
            set_mode(dir, 0o750)?;
            set_group(dir, group)
        }
        Err(e) => Err(socket_error("--socket", "inspect the directory", dir)(e)),
    }
}

/// Creates the socket `path`: its directory as [`prepare_directory`] says, a stale socket
/// file removed, mode 0660 and group `group`.
pub fn bind_socket(path: &Path, group: u32) -> Result<UnixListener, StartError> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    prepare_directory(dir, group)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)
            .map_err(socket_error("--socket", "remove the stale socket", path))?,
        Ok(_) => {
            return Err(StartError::SocketPathTaken {
                path: path.to_owned(),
            });
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(socket_error("--socket", "inspect", path)(e)),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(socket_error("--socket", "bind", path))?;
    set_mode(path, 0o660)?;
    set_group(path, group)?;
    listener
        .set_nonblocking(true)
        .map_err(socket_error("--socket", "make non-blocking", path))?;
    UnixListener::from_std(listener).map_err(socket_error("--socket", "register", path))
}
