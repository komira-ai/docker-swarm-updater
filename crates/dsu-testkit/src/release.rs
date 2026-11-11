//! The fake release server of docs/design.md section 6: HTTPS on 127.0.0.1 port 0 with a test
//! certificate authority whose PEM a test hands to the code under test as its CA file. It
//! serves files at paths, redirects, errors, a body shorter than it declares, and a body that
//! stalls. Every connection serves one request and closes.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

/// The host names the server's certificate is valid for: the release host and the hosts of
/// the default `redirect_hosts`.
pub const HOSTS: [&str; 3] = [
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];

/// What the server answers at a path.
#[derive(Debug, Clone)]
pub enum Route {
    /// 200 with this body and its `Content-Length`.
    File(Vec<u8>),
    /// A redirect with this status and `Location`.
    Redirect {
        /// The status code (301, 302, 303, 307, 308 or any other).
        status: u16,
        /// The `Location` header value.
        location: String,
    },
    /// An empty body with this status.
    Status(u16),
    /// 200 declaring `declared` bytes, sending `body` (fewer) and then closing.
    ShortBody {
        /// The bytes sent.
        body: Vec<u8>,
        /// The declared `Content-Length`.
        declared: usize,
    },
    /// 200 with no `Content-Length`: the body ends when the connection closes.
    Unframed(Vec<u8>),
    /// 200 declaring `declared` bytes, sending `sent` (fewer), signalling [`ReleaseServer::stalled`]
    /// and then waiting forever.
    Stall {
        /// The bytes sent before the stall.
        sent: Vec<u8>,
        /// The declared `Content-Length`.
        declared: usize,
    },
}

/// A request the server received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The request target.
    pub path: String,
    /// Every header as `(lower-case name, value)`.
    pub headers: Vec<(String, String)>,
}

/// A running fake release server; it stops when dropped.
pub struct ReleaseServer {
    addr: SocketAddr,
    ca_pem: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stalled: Arc<Notify>,
    task: JoinHandle<()>,
}

impl ReleaseServer {
    /// Starts a server answering `routes` (path to route); any other path is a 404.
    pub async fn start(routes: Vec<(&str, Route)>) -> Self {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = CertificateParams::new(HOSTS.map(String::from)).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca).unwrap();

        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes: Arc<Vec<(String, Route)>> = Arc::new(
            routes
                .into_iter()
                .map(|(path, route)| (path.to_owned(), route))
                .collect(),
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stalled = Arc::new(Notify::new());

        let task = tokio::spawn({
            let (requests, stalled) = (requests.clone(), stalled.clone());
            async move {
                let mut connections = JoinSet::new();
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    connections.spawn(serve(
                        tcp,
                        acceptor.clone(),
                        routes.clone(),
                        requests.clone(),
                        stalled.clone(),
                    ));
                }
            }
        });
        Self {
            addr,
            ca_pem: ca.pem(),
            requests,
            stalled,
            task,
        }
    }

    /// The loopback port the server listens on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The PEM of the certificate authority that signed the server's certificate.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Resolves once a [`Route::Stall`] response has sent its part of the body and is waiting.
    pub async fn stalled(&self) {
        self.stalled.notified().await;
    }

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for ReleaseServer {
    fn drop(&mut self) {
        // Aborting the accept loop drops its connection set, which aborts every connection.
        self.task.abort();
    }
}

fn head(status: u16, length: Option<usize>) -> String {
    let length = length
        .map(|n| format!("Content-Length: {n}\r\n"))
        .unwrap_or_default();
    format!("HTTP/1.1 {status} \r\n{length}Connection: close\r\n\r\n")
}

async fn serve(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    routes: Arc<Vec<(String, Route)>>,
    requests: Arc<Mutex<Vec<Request>>>,
    stalled: Arc<Notify>,
) -> std::io::Result<()> {
    let mut tls = acceptor.accept(tcp).await?;
    // The request head of a GET with a handful of headers arrives in one read.
    let mut buf = vec![0u8; 16 * 1024];
    let n = tls.read(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    let mut lines = text.split("\r\n");
    let path = lines
        .next()
        .unwrap_or_default()
        .split(' ')
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect();
    requests.lock().unwrap().push(Request {
        path: path.clone(),
        headers,
    });

    let route = routes
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, route)| route.clone())
        .unwrap_or(Route::Status(404));
    let (head, body, stall) = match route {
        Route::File(body) => (head(200, Some(body.len())), body, false),
        Route::Redirect { status, location } => (
            format!(
                "HTTP/1.1 {status} \r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            Vec::new(),
            false,
        ),
        Route::Status(status) => (head(status, Some(0)), Vec::new(), false),
        Route::ShortBody { body, declared } => (head(200, Some(declared)), body, false),
        Route::Unframed(body) => (head(200, None), body, false),
        Route::Stall { sent, declared } => (head(200, Some(declared)), sent, true),
    };
    tls.write_all(head.as_bytes()).await?;
    tls.write_all(&body).await?;
    tls.flush().await?;
    if stall {
        stalled.notify_one();
        std::future::pending::<()>().await;
    }
    tls.shutdown().await
}
