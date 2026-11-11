//! `cargo xtask fetch --url <https url> [--url <https url> ...] --sha256 <64 hex> --out <path>
//! [--member <path>]`: downloads a file pinned by SHA-256 from the first of its URLs that serves
//! it. Every `--url` names the same file; they are tried in the order given. In this order:
//!
//! - Each URL is downloaded whole over HTTPS (at most [`MAX_REDIRECTS`] redirects, each to an
//!   `https` URL, any status outside 2xx an error, at most [`MAX_BYTES`] bytes). A transient
//!   failure (the name does not resolve, the connection fails, is cut or times out, a 5xx) is
//!   tried again after each pause of [`BACKOFF`], so at most `BACKOFF.len() + 1` times; any
//!   other failure (a 4xx, a certificate the roots do not vouch for, a redirect refused, a body
//!   over the cap) is not. When a URL has failed, the next one is tried.
//! - The SHA-256 of the first body downloaded is compared with `--sha256`. A mismatch is fatal:
//!   no other URL is tried, and nothing is unpacked or written.
//! - The one regular-file `--member` of the gzip tar is extracted (without `--member` the body
//!   is taken as it is); `<out>.part` is written, made executable (0755) and renamed over
//!   `--out`.
//!
//! A failure removes `.part` and leaves an existing `--out` as it was. When every URL failed,
//! the error lists each attempt.

use std::fmt::Write as _;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use ureq::tls::{RootCerts, TlsConfig};

use crate::Report;

/// Redirects followed before the download is refused.
const MAX_REDIRECTS: u32 = 5;
/// The largest body accepted, in bytes.
const MAX_BYTES: u64 = 512 * 1024 * 1024;
/// The whole request, connect to last byte, may take this long.
const TIMEOUT: Duration = Duration::from_secs(600);
/// Resolving the name may take this long, and so may connecting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// The pauses before the second and the third attempt of one URL after a transient failure.
const BACKOFF: [Duration; 2] = [Duration::from_secs(5), Duration::from_secs(20)];

const USAGE: &str = "usage: xtask fetch --url <https url> [--url <https url> ...] --sha256 <64 hex> --out <path> [--member <path>]";

/// Parsed command-line options of `fetch`.
#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    /// The URLs of the one file, in the order they are tried; never empty.
    urls: Vec<String>,
    sha256: String,
    out: PathBuf,
    member: Option<String>,
}

/// Why one attempt to download a URL failed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Failure {
    message: String,
    /// The same URL may serve the file on a later attempt.
    transient: bool,
}

impl Failure {
    fn permanent(message: String) -> Self {
        Failure {
            message,
            transient: false,
        }
    }
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    let (mut urls, mut sha256, mut out, mut member) = (Vec::new(), None, None, None);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--url" => urls.push(value.clone()),
            "--sha256" => sha256 = Some(value.to_ascii_lowercase()),
            "--out" => out = Some(PathBuf::from(value)),
            "--member" => member = Some(value.clone()),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let (false, Some(sha256), Some(out)) = (urls.is_empty(), sha256, out) else {
        return Err(USAGE.into());
    };
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--sha256 must be 64 hex digits".into());
    }
    Ok(Options {
        urls,
        sha256,
        out,
        member,
    })
}

/// Runs `fetch` (`args` without the command word) with the Mozilla roots, pausing the thread
/// between attempts.
pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    run_with(args, RootCerts::WebPki, MAX_BYTES, &mut std::thread::sleep)
}

/// [`run`] trusting `roots`, accepting at most `max_bytes` of body and pausing with `pause`.
fn run_with(
    args: &[String],
    roots: RootCerts,
    max_bytes: u64,
    pause: &mut dyn FnMut(Duration),
) -> Result<Report, String> {
    let opts = parse_args(args)?;
    let agent = agent(roots);
    let log = fetch(&opts, &mut |url| download(&agent, url, max_bytes), pause)?;
    Ok(Report {
        text: log,
        passed: true,
    })
}

/// Gets `opts` with `get`, verifies, unpacks and installs it, and returns what it did, one
/// line per failed attempt and a last line naming the URL that served the file. `pause` is
/// called with each pause of [`BACKOFF`] before a URL is tried again.
pub(crate) fn fetch(
    opts: &Options,
    get: &mut dyn FnMut(&str) -> Result<Vec<u8>, Failure>,
    pause: &mut dyn FnMut(Duration),
) -> Result<String, String> {
    let mut log = String::new();
    let mut served = None;
    'urls: for url in &opts.urls {
        for attempt in 0..=BACKOFF.len() {
            match get(url) {
                Ok(body) => {
                    served = Some((url, body));
                    break 'urls;
                }
                Err(failure) => {
                    let n = attempt + 1;
                    let _ = write!(
                        log,
                        "fetch: {url}: attempt {n} of {}: {}",
                        BACKOFF.len() + 1,
                        failure.message
                    );
                    match BACKOFF.get(attempt).filter(|_| failure.transient) {
                        Some(&wait) => {
                            let _ = writeln!(log, "; again in {}s", wait.as_secs());
                            pause(wait);
                        }
                        None => {
                            log.push('\n');
                            continue 'urls;
                        }
                    }
                }
            }
        }
    }
    let Some((url, body)) = served else {
        return Err(format!("no URL served {}:\n{log}", opts.out.display()));
    };
    let digest = hex::encode(Sha256::digest(&body));
    if digest != opts.sha256 {
        return Err(format!(
            "sha256 mismatch for {url}: expected {}, got {digest}",
            opts.sha256
        ));
    }
    let bytes = match &opts.member {
        Some(member) => extract(&body, member)?,
        None => body,
    };
    install(&bytes, &opts.out)?;
    let _ = writeln!(log, "fetch: wrote {} from {url}", opts.out.display());
    Ok(log)
}

/// The HTTPS-only client trusting `roots`; it follows no redirect itself.
fn agent(roots: RootCerts) -> ureq::Agent {
    let tls = TlsConfig::builder()
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .timeout_resolve(Some(CONNECT_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .build()
        .into()
}

/// Whether a request that failed with `e` may succeed when it is made again: the name did not
/// resolve, the connection failed, was cut or timed out, or a timeout passed. A TLS failure (a
/// certificate the roots do not vouch for) is `InvalidData` and is not transient.
fn is_transient(e: &ureq::Error) -> bool {
    use std::io::ErrorKind as K;
    match e {
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed | ureq::Error::Timeout(_) => true,
        ureq::Error::Io(io) => matches!(
            io.kind(),
            K::ConnectionRefused
                | K::ConnectionReset
                | K::ConnectionAborted
                | K::NotConnected
                | K::BrokenPipe
                | K::TimedOut
                | K::UnexpectedEof
                | K::Interrupted
                | K::HostUnreachable
                | K::NetworkUnreachable
                | K::NetworkDown
                | K::AddrNotAvailable
        ),
        _ => false,
    }
}

fn download(agent: &ureq::Agent, start: &str, max_bytes: u64) -> Result<Vec<u8>, Failure> {
    let mut url =
        url::Url::parse(start).map_err(|e| Failure::permanent(format!("{start}: {e}")))?;
    let mut redirects = 0;
    loop {
        if url.scheme() != "https" {
            return Err(Failure::permanent(format!(
                "{url}: only https URLs are fetched"
            )));
        }
        let response = agent.get(url.as_str()).call().map_err(|e| Failure {
            message: format!("{url}: {e}"),
            transient: is_transient(&e),
        })?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if redirects == MAX_REDIRECTS {
                return Err(Failure::permanent(format!(
                    "{start}: more than {MAX_REDIRECTS} redirects"
                )));
            }
            redirects += 1;
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    Failure::permanent(format!("{url}: redirect without a usable Location"))
                })?;
            url = url
                .join(location)
                .map_err(|e| Failure::permanent(format!("{url}: bad Location {location}: {e}")))?;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(Failure {
                message: format!("{url}: status {status}"),
                transient: (500..600).contains(&status),
            });
        }
        let reader = response
            .into_body()
            .into_with_config()
            .limit(u64::MAX)
            .reader();
        let mut body = Vec::new();
        reader
            .take(max_bytes + 1)
            .read_to_end(&mut body)
            .map_err(|e| {
                let message = format!("{url}: reading the body: {e}");
                Failure {
                    message,
                    transient: is_transient(&ureq::Error::from(e)),
                }
            })?;
        if body.len() as u64 > max_bytes {
            return Err(Failure::permanent(format!(
                "{url}: body is larger than {max_bytes} bytes"
            )));
        }
        return Ok(body);
    }
}

/// The bytes of the regular file `member` in the gzip tar `body`.
fn extract(body: &[u8], member: &str) -> Result<Vec<u8>, String> {
    let bad = |e: std::io::Error| format!("reading the archive: {e}");
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(body));
    for entry in archive.entries().map_err(bad)? {
        let mut entry = entry.map_err(bad)?;
        let wanted = entry.header().entry_type().is_file()
            && entry.path().is_ok_and(|p| p == Path::new(member));
        if wanted {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).map_err(bad)?;
            return Ok(bytes);
        }
    }
    Err(format!("the archive has no regular file {member}"))
}

/// Writes `<out>.part`, makes it executable and renames it over `out`; a failure removes it.
fn install(bytes: &[u8], out: &Path) -> Result<(), String> {
    let mut part = out.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let result = std::fs::write(&part, bytes)
        .and_then(|()| std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o755)))
        .and_then(|()| std::fs::rename(&part, out))
        .map_err(|e| format!("writing {}: {e}", out.display()));
    if result.is_err() {
        // Best effort: the .part may not exist when the write itself failed.
        let _ = std::fs::remove_file(&part);
    }
    result
}

#[cfg(test)]
mod tests;
