//! The release downloader of docs/design.md section 3.2: an HTTPS GET that follows a bounded
//! number of redirects to hosts the config allows, connects only to public addresses it
//! resolved and checked itself, sends no credentials, and streams the body to a file in the
//! state directory while hashing it.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dsu_core::ids::Digest;
use dsu_core::url::{UrlError, check_redirect_url, is_public};
use http::header::{HOST, LOCATION, USER_AGENT};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest as _, Sha256};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::AbortHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::{Host, Position, Url};

use crate::clock::{BoxFuture, Clock, with_deadline};
use crate::net::Network;

/// Redirects followed before the download is refused.
pub const MAX_REDIRECTS: usize = 5;
/// Time allowed to resolve, connect and finish the TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed for the response head and for each read of the body.
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

const USER_AGENT_VALUE: &str = concat!("docker-swarm-updater/", env!("CARGO_PKG_VERSION"));

/// Why a download did not produce a file.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The URL, or a redirect target, breaks the URL rules.
    #[error(transparent)]
    UrlNotAllowed(#[from] UrlError),
    /// A host resolved to an address a download may not connect to.
    #[error("host {host} resolves to {addr}, which is not a public address")]
    NonPublicAddress {
        /// The host that was resolved.
        host: String,
        /// The refused address.
        addr: IpAddr,
    },
    /// The chain of redirects is longer than [`MAX_REDIRECTS`].
    #[error("more than {max} redirects")]
    TooManyRedirects {
        /// The limit.
        max: usize,
    },
    /// The body is larger than the service's `max_image_bytes`.
    #[error("the download is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: u64,
    },
    /// The TLS configuration could not be built.
    #[error("cannot build the TLS configuration: {0}")]
    TlsConfig(#[source] rustls::Error),
    /// The CA file holds no usable certificate.
    #[error("the CA file is not usable: {0}")]
    CaFile(String),
    /// Resolving a host failed.
    #[error("cannot resolve {host}: {source}")]
    Resolve {
        /// The host.
        host: String,
        /// The resolver's error.
        #[source]
        source: io::Error,
    },
    /// Every address of a host refused the connection.
    #[error("cannot connect to {host}: {source}")]
    Connect {
        /// The host.
        host: String,
        /// The last connection error.
        #[source]
        source: io::Error,
    },
    /// The TLS handshake failed (an untrusted or mismatched certificate included).
    #[error("TLS handshake with {host} failed: {source}")]
    Tls {
        /// The host.
        host: String,
        /// The handshake error.
        #[source]
        source: io::Error,
    },
    /// The request could not be built.
    #[error("cannot build the request: {0}")]
    Request(#[source] http::Error),
    /// The HTTP exchange failed (a body shorter than its Content-Length included).
    #[error("http error: {0}")]
    Http(#[source] hyper::Error),
    /// The server answered with a status other than 200 and not a followed redirect.
    #[error("the server answered {status}")]
    Status {
        /// The status code.
        status: StatusCode,
    },
    /// A redirect carried no readable `Location`.
    #[error("redirect {status} has no usable Location header")]
    NoLocation {
        /// The redirect status.
        status: StatusCode,
    },
    /// A phase took longer than its limit.
    #[error("{phase} timed out after {limit:?}")]
    Timeout {
        /// `connect`, `response` or `read`.
        phase: &'static str,
        /// The limit that passed.
        limit: Duration,
    },
    /// Writing the file would take the disk below `min_free_bytes`.
    #[error("the disk would drop below the minimum: {free} bytes free, {needed} needed")]
    DiskFull {
        /// Free bytes now.
        free: u64,
        /// Bytes needed: the minimum plus what is still to be written.
        needed: u64,
    },
    /// The free space of the directory could not be read.
    #[error("cannot read the free space of {dir}: {source}")]
    FreeSpace {
        /// The directory.
        dir: PathBuf,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// The destination file could not be created.
    #[error("cannot create {path}: {source}")]
    Create {
        /// The file.
        path: PathBuf,
        /// The error.
        #[source]
        source: io::Error,
    },
    /// Writing the destination file failed.
    #[error("cannot write {path}: {source}")]
    Write {
        /// The file.
        path: PathBuf,
        /// The error.
        #[source]
        source: io::Error,
    },
}

impl FetchError {
    /// The error token of the deploy record: `url_not_allowed`, `too_large` or `fetch_failed`.
    pub fn token(&self) -> &'static str {
        match self {
            Self::UrlNotAllowed(_)
            | Self::NonPublicAddress { .. }
            | Self::TooManyRedirects { .. } => "url_not_allowed",
            Self::TooLarge { .. } => "too_large",
            _ => "fetch_failed",
        }
    }
}

/// The disk the download writes to.
pub trait Disk: Send + Sync {
    /// Bytes available to the updater on the file system holding `dir`.
    fn free_bytes(&self, dir: &Path) -> io::Result<u64>;

    /// Writes one chunk of the body to `file`.
    fn write<'a>(&'a self, file: &'a mut File, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
}

/// The real disk: `statvfs` for the free space, plain writes.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDisk;

impl Disk for SystemDisk {
    fn free_bytes(&self, dir: &Path) -> io::Result<u64> {
        let stat = rustix::fs::statvfs(dir)?;
        Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
    }

    fn write<'a>(&'a self, file: &'a mut File, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(file.write_all(chunk))
    }
}

/// The root certificates of Mozilla's bundle, the default trust of downloads.
pub fn default_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// A root store holding exactly the certificates of a PEM file (`--ca-file`), replacing the
/// built-in roots.
pub fn roots_from_pem(pem: &[u8]) -> Result<RootCertStore, FetchError> {
    let mut store = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| FetchError::CaFile(e.to_string()))?;
        store
            .add(cert)
            .map_err(|e| FetchError::CaFile(e.to_string()))?;
    }
    if store.is_empty() {
        return Err(FetchError::CaFile("it holds no certificate".to_owned()));
    }
    Ok(store)
}

/// The size and disk limits of one download.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest body accepted; `None` for no cap.
    pub max_bytes: Option<u64>,
    /// The free space the disk must keep.
    pub min_free_bytes: u64,
}

/// A completed download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The file the body was written to.
    pub path: PathBuf,
    /// The body's length in bytes.
    pub size: u64,
    /// The body's SHA-256.
    pub digest: Digest,
}

/// The downloader. It holds its collaborators so tests substitute the network, the clock and
/// the disk.
pub struct Fetcher {
    network: Arc<dyn Network>,
    clock: Arc<dyn Clock>,
    disk: Arc<dyn Disk>,
    tls: Arc<ClientConfig>,
    redirect_hosts: Vec<String>,
}

/// Aborts the task that drives an HTTP connection when the reply that owns it is dropped.
struct ConnectionTask(AbortHandle);

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An HTTP response with the connection it arrives on.
struct Reply {
    response: Response<Incoming>,
    _sender: http1::SendRequest<Empty<Bytes>>,
    _connection: ConnectionTask,
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn not_allowed(url: &Url, rule: &'static str) -> FetchError {
    FetchError::UrlNotAllowed(UrlError::Refused {
        url: url.as_str().to_owned(),
        rule,
    })
}

impl Fetcher {
    /// A downloader that trusts `roots`, follows redirects only to `redirect_hosts`, and talks
    /// through `network`, `clock` and `disk`.
    pub fn new(
        network: Arc<dyn Network>,
        clock: Arc<dyn Clock>,
        disk: Arc<dyn Disk>,
        roots: RootCertStore,
        redirect_hosts: Vec<String>,
    ) -> Result<Self, FetchError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(FetchError::TlsConfig)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            network,
            clock,
            disk,
            tls: Arc::new(config),
            redirect_hosts,
        })
    }

    /// Downloads `url` to the new file `dir/file_name`, hashing it on the way. The file must
    /// not exist. On any error the partial file is removed. `url` is judged by the redirect
    /// and address rules only; the release rule is the caller's (`dsu_core::url`).
    pub async fn fetch(
        &self,
        url: &Url,
        dir: &Path,
        file_name: &str,
        limits: &Limits,
    ) -> Result<Fetched, FetchError> {
        let mut reply = self.follow(url).await?;
        let status = reply.response.status();
        if status != StatusCode::OK {
            return Err(FetchError::Status { status });
        }
        let declared = reply.response.body().size_hint().exact();
        if let Some(limit) = limits
            .max_bytes
            .filter(|max| declared.is_some_and(|n| n > *max))
        {
            return Err(FetchError::TooLarge { limit });
        }
        self.ensure_free(
            dir,
            limits.min_free_bytes.saturating_add(declared.unwrap_or(0)),
        )?;

        let path = dir.join(file_name);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|source| FetchError::Create {
                path: path.clone(),
                source,
            })?;
        match self
            .stream(reply.response.body_mut(), &mut file, &path, dir, limits)
            .await
        {
            Ok((size, digest)) => Ok(Fetched { path, size, digest }),
            Err(error) => {
                drop(file);
                // The error that matters is the download's; a file that cannot be removed
                // stays for the operator to see.
                let _ = tokio::fs::remove_file(&path).await;
                Err(error)
            }
        }
    }

    fn ensure_free(&self, dir: &Path, needed: u64) -> Result<(), FetchError> {
        let free = self
            .disk
            .free_bytes(dir)
            .map_err(|source| FetchError::FreeSpace {
                dir: dir.to_path_buf(),
                source,
            })?;
        if free < needed {
            return Err(FetchError::DiskFull { free, needed });
        }
        Ok(())
    }

    async fn stream(
        &self,
        body: &mut Incoming,
        file: &mut File,
        path: &Path,
        dir: &Path,
        limits: &Limits,
    ) -> Result<(u64, Digest), FetchError> {
        let write_error = |source| FetchError::Write {
            path: path.to_path_buf(),
            source,
        };
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        while let Some(frame) = self.timed(READ_TIMEOUT, "read", body.frame()).await? {
            let data = frame
                .map_err(FetchError::Http)?
                .into_data()
                .unwrap_or_default();
            size += data.len() as u64;
            if let Some(limit) = limits.max_bytes.filter(|max| size > *max) {
                return Err(FetchError::TooLarge { limit });
            }
            self.disk.write(file, &data).await.map_err(write_error)?;
            hasher.update(&data);
            self.ensure_free(dir, limits.min_free_bytes)?;
        }
        file.flush().await.map_err(write_error)?;
        Ok((size, Digest::from_sha256(hasher.finalize().into())))
    }

    async fn timed<T>(
        &self,
        limit: Duration,
        phase: &'static str,
        work: impl Future<Output = T>,
    ) -> Result<T, FetchError> {
        with_deadline(self.clock.as_ref(), limit, work)
            .await
            .map_err(|timed_out| FetchError::Timeout {
                phase,
                limit: timed_out.limit,
            })
    }

    /// Requests `start` and follows redirects until a response that is not one.
    async fn follow(&self, start: &Url) -> Result<Reply, FetchError> {
        let mut current = start.clone();
        let mut redirects = 0;
        loop {
            let reply = self.get(&current).await?;
            let status = reply.response.status();
            if !is_redirect(status) {
                return Ok(reply);
            }
            if redirects == MAX_REDIRECTS {
                return Err(FetchError::TooManyRedirects { max: MAX_REDIRECTS });
            }
            redirects += 1;
            let location = reply
                .response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(FetchError::NoLocation { status })?;
            let next = current.join(location).map_err(|e| {
                FetchError::UrlNotAllowed(UrlError::Unparseable {
                    url: location.to_owned(),
                    reason: e.to_string(),
                })
            })?;
            check_redirect_url(&next, &self.redirect_hosts)?;
            current = next;
        }
    }

    /// One GET of `url` on a fresh connection. Nothing but the request line, `Host` and
    /// `User-Agent` is sent: no token, cookie or authorization of any kind.
    async fn get(&self, url: &Url) -> Result<Reply, FetchError> {
        let Some(Host::Domain(host)) = url.host() else {
            return Err(not_allowed(url, "the host must be a domain name"));
        };
        if url.scheme() != "https" {
            return Err(not_allowed(url, "the scheme must be https"));
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let tls = self
            .timed(CONNECT_TIMEOUT, "connect", self.open(host, port))
            .await??;

        let (sender, connection) = http1::handshake(TokioIo::new(tls))
            .await
            .map_err(FetchError::Http)?;
        let driver = tokio::spawn(async move {
            // The connection ends with the exchange; its error is the request's error.
            let _ = connection.await;
        });
        let _connection = ConnectionTask(driver.abort_handle());
        let request = Request::builder()
            .uri(&url[Position::BeforePath..Position::AfterQuery])
            .header(HOST, &url[Position::BeforeHost..Position::AfterPort])
            .header(USER_AGENT, USER_AGENT_VALUE)
            .body(Empty::<Bytes>::new())
            .map_err(FetchError::Request)?;
        let mut sender = sender;
        let response = self
            .timed(READ_TIMEOUT, "response", sender.send_request(request))
            .await?
            .map_err(FetchError::Http)?;
        Ok(Reply {
            response,
            _sender: sender,
            _connection,
        })
    }

    /// Resolves `host` once, refuses it when any answer is not public, and connects to a
    /// checked address and completes the TLS handshake with `host` as the server name.
    async fn open(&self, host: &str, port: u16) -> Result<TlsStream<TcpStream>, FetchError> {
        let name = ServerName::try_from(host.to_owned()).map_err(|_| FetchError::Tls {
            host: host.to_owned(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "not a valid server name"),
        })?;
        let addrs = self
            .network
            .resolve(host)
            .await
            .map_err(|source| FetchError::Resolve {
                host: host.to_owned(),
                source,
            })?;
        if let Some(addr) = addrs.iter().find(|addr| !is_public(**addr)) {
            return Err(FetchError::NonPublicAddress {
                host: host.to_owned(),
                addr: *addr,
            });
        }
        let mut failure =
            io::Error::new(io::ErrorKind::NotFound, "the host resolved to no address");
        for ip in addrs {
            match self.network.connect(SocketAddr::new(ip, port)).await {
                Ok(tcp) => {
                    return TlsConnector::from(self.tls.clone())
                        .connect(name, tcp)
                        .await
                        .map_err(|source| FetchError::Tls {
                            host: host.to_owned(),
                            source,
                        });
                }
                Err(error) => failure = error,
            }
        }
        Err(FetchError::Connect {
            host: host.to_owned(),
            source: failure,
        })
    }
}
