//! `probe` (docs/design.md section 4.3): one GET to a loopback HTTP URL or a Unix socket, for
//! container health checks. The answer is the exit code: 0 for a 2xx status, 1 otherwise.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http::header::HOST;
use http::uri::PathAndQuery;
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use url::{Host, Url};

use crate::clock::{Clock, with_deadline};

/// A probe target the rules refuse; the command line reports it and exits with a usage error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// The text is not a URL.
    #[error("not a URL: {0}")]
    NotAUrl(String),
    /// The URL is not `http://` with a loopback IP address as its host.
    #[error("only http:// URLs whose host is a loopback IP address are probed, not {0}")]
    NotLoopback(String),
    /// The request path is not an absolute path the request line can carry.
    #[error("not a valid request path: {0:?}")]
    BadPath(String),
}

/// What the probe talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeTarget {
    /// A TCP socket on a loopback address.
    Tcp {
        /// The loopback address and port.
        addr: SocketAddr,
        /// The `Host` header value.
        host: String,
        /// The request target: path and query.
        target: String,
    },
    /// A Unix domain socket.
    Unix {
        /// The socket path.
        socket: PathBuf,
        /// The request target: path and query.
        target: String,
    },
}

fn valid_target(target: &str) -> Result<String, TargetError> {
    match target.parse::<PathAndQuery>() {
        Ok(parsed) if target.starts_with('/') => Ok(parsed.as_str().to_owned()),
        _ => Err(TargetError::BadPath(target.to_owned())),
    }
}

impl ProbeTarget {
    /// A target from `http://<loopback ip>[:port]/<path>`. A host name (`localhost` included),
    /// a non-loopback address and any other scheme are refused: a health check must not reach
    /// out of its task.
    pub fn from_url(text: &str) -> Result<Self, TargetError> {
        let url = Url::parse(text).map_err(|e| TargetError::NotAUrl(e.to_string()))?;
        let ip = match url.host() {
            Some(Host::Ipv4(v4)) => IpAddr::V4(v4),
            Some(Host::Ipv6(v6)) => IpAddr::V6(v6),
            _ => return Err(TargetError::NotLoopback(text.to_owned())),
        };
        if url.scheme() != "http" || !ip.is_loopback() {
            return Err(TargetError::NotLoopback(text.to_owned()));
        }
        let port = url.port_or_known_default().unwrap_or(80);
        let target = valid_target(&url[url::Position::BeforePath..url::Position::AfterQuery])?;
        Ok(Self::Tcp {
            addr: SocketAddr::new(ip, port),
            host: url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
            target,
        })
    }

    /// A target on the Unix socket `socket` with the request path `target` (`/v1/health`).
    pub fn unix(socket: impl Into<PathBuf>, target: &str) -> Result<Self, TargetError> {
        Ok(Self::Unix {
            socket: socket.into(),
            target: valid_target(target)?,
        })
    }
}

/// Why a probe did not find the service healthy.
#[derive(Debug, thiserror::Error)]
pub enum ProbeFailure {
    /// The socket could not be connected to.
    #[error("cannot connect: {0}")]
    Connect(#[source] std::io::Error),
    /// The HTTP exchange failed.
    #[error("http error: {0}")]
    Http(#[source] hyper::Error),
    /// The request could not be built.
    #[error("cannot build the request: {0}")]
    Request(#[source] http::Error),
    /// The service answered with a status outside 2xx.
    #[error("the service answered {0}")]
    Status(u16),
    /// No answer came within the timeout.
    #[error("no answer within {0:?}")]
    Timeout(Duration),
}

/// The result of a probe.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// The service answered 2xx.
    Healthy,
    /// It did not.
    Unhealthy(ProbeFailure),
}

impl ProbeOutcome {
    /// The process exit code: 0 for healthy, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Healthy => 0,
            Self::Unhealthy(_) => 1,
        }
    }
}

/// GETs `target` and reports whether the answer is 2xx. The whole exchange, connecting
/// included, must finish before `clock.deadline(timeout)`.
pub async fn probe(target: &ProbeTarget, timeout: Duration, clock: &dyn Clock) -> ProbeOutcome {
    let result = match with_deadline(clock, timeout, exchange(target)).await {
        Ok(result) => result,
        Err(_) => Err(ProbeFailure::Timeout(timeout)),
    };
    match result {
        Ok(()) => ProbeOutcome::Healthy,
        Err(failure) => ProbeOutcome::Unhealthy(failure),
    }
}

async fn exchange(target: &ProbeTarget) -> Result<(), ProbeFailure> {
    match target {
        ProbeTarget::Tcp { addr, host, target } => {
            let stream = TcpStream::connect(addr)
                .await
                .map_err(ProbeFailure::Connect)?;
            get(stream, host, target).await
        }
        ProbeTarget::Unix { socket, target } => {
            let stream = UnixStream::connect(socket)
                .await
                .map_err(ProbeFailure::Connect)?;
            get(stream, "localhost", target).await
        }
    }
}

async fn get<IO>(io: IO, host: &str, target: &str) -> Result<(), ProbeFailure>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io))
        .await
        .map_err(ProbeFailure::Http)?;
    let driver = tokio::spawn(async move {
        // The connection ends with the exchange; its error is the request's error.
        let _ = connection.await;
    });
    let request = Request::builder()
        .uri(target)
        .header(HOST, host)
        .body(Empty::<Bytes>::new())
        .map_err(ProbeFailure::Request)?;
    let response = sender.send_request(request).await;
    driver.abort();
    let status = response.map_err(ProbeFailure::Http)?.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ProbeFailure::Status(status.as_u16()))
    }
}
