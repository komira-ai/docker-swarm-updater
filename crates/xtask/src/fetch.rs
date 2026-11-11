//! `cargo xtask fetch --url <https url> --sha256 <64 hex> --out <path> [--member <path>]`:
//! downloads a CI tool pinned by artifact URL and SHA-256. In this order: the whole body is
//! downloaded over HTTPS (at most [`MAX_REDIRECTS`] redirects, each to an `https` URL, any
//! status outside 2xx an error, at most [`MAX_BYTES`] bytes); its SHA-256 is compared with
//! `--sha256` and a mismatch is refused before anything is unpacked or written; the one
//! regular-file `--member` of the gzip tar is extracted (without `--member` the body is taken
//! as it is); `<out>.part` is written, made executable (0755) and renamed over `--out`. A
//! failure removes `.part` and leaves an existing `--out` as it was.

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

const USAGE: &str =
    "usage: xtask fetch --url <https url> --sha256 <64 hex> --out <path> [--member <path>]";

/// Parsed command-line options of `fetch`.
#[derive(Debug, PartialEq)]
pub(crate) struct Options {
    url: String,
    sha256: String,
    out: PathBuf,
    member: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    let (mut url, mut sha256, mut out, mut member) = (None, None, None, None);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--url" => url = Some(value.clone()),
            "--sha256" => sha256 = Some(value.to_ascii_lowercase()),
            "--out" => out = Some(PathBuf::from(value)),
            "--member" => member = Some(value.clone()),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let (Some(url), Some(sha256), Some(out)) = (url, sha256, out) else {
        return Err(USAGE.into());
    };
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--sha256 must be 64 hex digits".into());
    }
    Ok(Options {
        url,
        sha256,
        out,
        member,
    })
}

/// Runs `fetch` (`args` without the command word) with the Mozilla roots.
pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    run_with(args, RootCerts::WebPki, MAX_BYTES)
}

/// [`run`] trusting `roots` and accepting at most `max_bytes` of body.
fn run_with(args: &[String], roots: RootCerts, max_bytes: u64) -> Result<Report, String> {
    let opts = parse_args(args)?;
    fetch(&opts, roots, max_bytes)?;
    Ok(Report {
        text: format!("fetch: wrote {}\n", opts.out.display()),
        passed: true,
    })
}

/// Downloads, verifies, unpacks and installs `opts`, trusting `roots` and accepting at most
/// `max_bytes` of body.
pub(crate) fn fetch(opts: &Options, roots: RootCerts, max_bytes: u64) -> Result<(), String> {
    let body = download(&opts.url, roots, max_bytes)?;
    let digest = hex::encode(Sha256::digest(&body));
    if digest != opts.sha256 {
        return Err(format!(
            "sha256 mismatch for {}: expected {}, got {digest}",
            opts.url, opts.sha256
        ));
    }
    let bytes = match &opts.member {
        Some(member) => extract(&body, member)?,
        None => body,
    };
    install(&bytes, &opts.out)
}

fn download(start: &str, roots: RootCerts, max_bytes: u64) -> Result<Vec<u8>, String> {
    let tls = TlsConfig::builder()
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let mut url = url::Url::parse(start).map_err(|e| format!("{start}: {e}"))?;
    let mut redirects = 0;
    loop {
        if url.scheme() != "https" {
            return Err(format!("{url}: only https URLs are fetched"));
        }
        let response = agent
            .get(url.as_str())
            .call()
            .map_err(|e| format!("{url}: {e}"))?;
        let status = response.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if redirects == MAX_REDIRECTS {
                return Err(format!("{start}: more than {MAX_REDIRECTS} redirects"));
            }
            redirects += 1;
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("{url}: redirect without a usable Location"))?;
            url = url
                .join(location)
                .map_err(|e| format!("{url}: bad Location {location}: {e}"))?;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(format!("{url}: status {status}"));
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
            .map_err(|e| format!("{url}: reading the body: {e}"))?;
        if body.len() as u64 > max_bytes {
            return Err(format!("{url}: body is larger than {max_bytes} bytes"));
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
