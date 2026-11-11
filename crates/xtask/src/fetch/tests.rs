//! Tests of `fetch`: the order of URLs, the retries and the fatal mismatch with a scripted
//! getter and no network; the download itself against an in-process HTTPS server on 127.0.0.1
//! with a test CA.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::*;

const FILE: &[u8] = b"tool-bytes";

struct Reply {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
    /// Bytes the Content-Length claims beyond the body (the connection then ends early).
    missing: usize,
}

fn reply(status: u16, location: Option<&str>, body: &[u8]) -> Reply {
    Reply {
        status,
        location: location.map(str::to_owned),
        body: body.to_vec(),
        missing: 0,
    }
}

/// A gzip tar of `(path, is_directory)` entries, each regular file holding [`FILE`].
fn tar_gz(entries: &[(&str, bool)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, dir) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(if *dir {
            tar::EntryType::Directory
        } else {
            tar::EntryType::Regular
        });
        header.set_size(if *dir { 0 } else { FILE.len() as u64 });
        header.set_mode(0o644);
        let data: &[u8] = if *dir { b"" } else { FILE };
        builder.append_data(&mut header, path, data).unwrap();
    }
    let tar = builder.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

fn route(path: &str, port: u16) -> Reply {
    match path {
        "/file" => reply(200, None, FILE),
        "/tar" => reply(
            200,
            None,
            &tar_gz(&[("bin/", true), ("bin/other", false), ("bin/tool", false)]),
        ),
        "/tar-no-file" => reply(
            200,
            None,
            &tar_gz(&[("bin/tool", true), ("bin/other", false)]),
        ),
        "/tar-truncated" => {
            // 64 KiB of pseudo-random bytes do not compress: cutting the stream lands
            // inside the member's data.
            let mut state = 0x2545_f491_4f6c_dd1d_u64;
            let data: Vec<u8> = (0..65536)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect();
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, "bin/tool", &data[..])
                .unwrap();
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&builder.into_inner().unwrap()).unwrap();
            let mut gz = gz.finish().unwrap();
            gz.truncate(gz.len() / 2);
            reply(200, None, &gz)
        }
        "/short" => Reply {
            missing: 5,
            ..reply(200, None, FILE)
        },
        "/503" => reply(503, None, b"try later"),
        "/rel" => reply(307, Some("/file"), b""),
        "/abs" => reply(301, Some(&format!("https://127.0.0.1:{port}/file")), b""),
        "/http" => reply(302, Some("http://127.0.0.1:1/file"), b""),
        "/no-location" => reply(302, None, b""),
        "/bad-location" => reply(302, Some("https://["), b""),
        _ => match path
            .strip_prefix("/hop/")
            .and_then(|n| n.parse::<u32>().ok())
        {
            Some(0) => reply(200, None, FILE),
            Some(n) => reply(302, Some(&format!("/hop/{}", n - 1)), b""),
            None => reply(404, None, b"nothing here"),
        },
    }
}

struct Server {
    port: u16,
    ca_der: Vec<u8>,
}

/// One server for every test: a test CA, a leaf for 127.0.0.1, a thread per connection.
fn server() -> &'static Server {
    static SERVER: OnceLock<Server> = OnceLock::new();
    SERVER.get_or_init(|| {
        let (ca_der, leaf_der, key) = test_pki();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der.into()], key)
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let config = Arc::clone(&config);
                std::thread::spawn(move || serve(stream.unwrap(), config, port));
            }
        });
        Server { port, ca_der }
    })
}

fn test_pki() -> (Vec<u8>, Vec<u8>, PrivateKeyDer<'static>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (ca.der().to_vec(), leaf.der().to_vec(), key)
}

/// Answers one request on `stream` and closes. A client that rejects the certificate makes
/// the handshake fail; that ends the connection and is not an error of the server.
fn serve(stream: std::net::TcpStream, config: Arc<rustls::ServerConfig>, port: u16) {
    let conn = rustls::ServerConnection::new(config).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, stream);
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut chunk) {
            Ok(n) if n > 0 => head.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let path = text.split(' ').nth(1).unwrap_or("/");
    let r = route(path, port);
    let mut out = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", r.status);
    if let Some(location) = &r.location {
        out.push_str(&format!("Location: {location}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\n\r\n",
        r.body.len() + r.missing
    ));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&r.body);
    let _ = tls.write_all(&bytes);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

fn roots() -> RootCerts {
    RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(&server().ca_der).to_owned()])
}

fn url(path: &str) -> String {
    format!("https://127.0.0.1:{}{path}", server().port)
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn opts(path: &str, sha256: String, out: &Path, member: Option<&str>) -> Options {
    Options {
        urls: vec![url(path)],
        sha256,
        out: out.to_path_buf(),
        member: member.map(str::to_owned),
    }
}

/// [`fetch`] from the test server with no pause.
fn get(o: &Options) -> Result<String, String> {
    let agent = agent(roots());
    fetch(o, &mut |u| download(&agent, u, MAX_BYTES), &mut |_| ())
}

/// One download from the test server.
fn down(path: &str) -> Result<Vec<u8>, Failure> {
    download(&agent(roots()), &url(path), MAX_BYTES)
}

fn transient(message: String) -> Failure {
    Failure {
        message,
        transient: true,
    }
}

/// Nothing but what the test put there: no `out`, no `.part`.
fn assert_untouched(dir: &Path, expected: &[&str]) {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, expected);
}

// The order of URLs, the retries and the mismatch, with a scripted getter (no network).

/// What the scripted getter answers for one call.
type Answer = Result<Vec<u8>, Failure>;

/// A getter that answers each URL from its own queue of results and records every call, and a
/// pause that records every wait. A URL with an empty queue is a test bug.
struct Script {
    answers: BTreeMap<String, VecDeque<Answer>>,
    calls: Vec<String>,
    pauses: Vec<Duration>,
}

impl Script {
    fn new(answers: &[(&str, Vec<Answer>)]) -> Self {
        let mut map = BTreeMap::new();
        for (u, results) in answers {
            map.insert((*u).to_owned(), results.iter().cloned().collect());
        }
        Script {
            answers: map,
            calls: Vec::new(),
            pauses: Vec::new(),
        }
    }

    fn fetch(&mut self, o: &Options) -> Result<String, String> {
        let (answers, calls, pauses) = (&mut self.answers, &mut self.calls, &mut self.pauses);
        fetch(
            o,
            &mut |u| {
                calls.push(u.to_owned());
                answers.get_mut(u).unwrap().pop_front().unwrap()
            },
            &mut |d| pauses.push(d),
        )
    }
}

fn down_dns(u: &str) -> Answer {
    Err(transient(format!("{u}: host not found")))
}

fn gone(u: &str) -> Answer {
    Err(Failure::permanent(format!("{u}: status 404")))
}

fn scripted(urls: &[&str], out: &Path) -> Options {
    Options {
        urls: urls.iter().map(|u| (*u).to_owned()).collect(),
        sha256: sha(FILE),
        out: out.to_path_buf(),
        member: None,
    }
}

const A: &str = "https://a/f";
const B: &str = "https://b/f";
const C: &str = "https://c/f";
const D: &str = "https://d/f";

#[test]
fn urls_are_tried_in_order_and_the_first_that_serves_the_file_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f.deb");
    // A is gone, B never resolves, C serves the file; D is never asked.
    let mut script = Script::new(&[
        (A, vec![gone(A)]),
        (B, vec![down_dns(B), down_dns(B), down_dns(B)]),
        (C, vec![Ok(FILE.to_vec())]),
        (D, vec![]),
    ]);
    let log = script.fetch(&scripted(&[A, B, C, D], &out)).unwrap();
    assert_eq!(script.calls, [A, B, B, B, C]);
    assert_eq!(script.pauses, BACKOFF);
    assert_eq!(
        log,
        format!(
            "fetch: {A}: attempt 1 of 3: {A}: status 404\n\
             fetch: {B}: attempt 1 of 3: {B}: host not found; again in 5s\n\
             fetch: {B}: attempt 2 of 3: {B}: host not found; again in 20s\n\
             fetch: {B}: attempt 3 of 3: {B}: host not found\n\
             fetch: wrote {} from {C}\n",
            out.display()
        )
    );
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
    assert_untouched(dir.path(), &["f.deb"]);
}

#[test]
fn a_transient_failure_is_tried_again_after_a_pause_and_a_later_url_is_not_asked() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f.deb");
    let mut script = Script::new(&[(A, vec![down_dns(A), Ok(FILE.to_vec())]), (B, vec![])]);
    script.fetch(&scripted(&[A, B], &out)).unwrap();
    assert_eq!(script.calls, [A, A]);
    assert_eq!(script.pauses, [BACKOFF[0]]);
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
}

#[test]
fn a_permanent_failure_is_not_tried_again_and_the_next_url_follows_without_a_pause() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f.deb");
    let mut script = Script::new(&[(A, vec![gone(A)]), (B, vec![Ok(FILE.to_vec())])]);
    script.fetch(&scripted(&[A, B], &out)).unwrap();
    assert_eq!(script.calls, [A, B]);
    assert_eq!(script.pauses, Vec::<Duration>::new());
}

#[test]
fn a_sha256_mismatch_from_any_url_is_fatal_even_when_a_later_url_has_the_file() {
    for wrong_at in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("f.deb");
        std::fs::write(&out, "old").unwrap();
        let urls = [A, B, C, D];
        // The URLs before `wrong_at` fail (A transiently, once, then for good), the one at
        // `wrong_at` serves other bytes, the ones after it would serve the file.
        let answers: Vec<(&str, Vec<Answer>)> = urls
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let results = match i.cmp(&wrong_at) {
                    std::cmp::Ordering::Less if i == 0 => vec![down_dns(u), gone(u)],
                    std::cmp::Ordering::Less => vec![gone(u)],
                    std::cmp::Ordering::Equal => vec![Ok(b"other".to_vec())],
                    std::cmp::Ordering::Greater => vec![Ok(FILE.to_vec())],
                };
                (*u, results)
            })
            .collect();
        let mut script = Script::new(&answers);
        let err = script.fetch(&scripted(&urls, &out)).unwrap_err();
        assert_eq!(
            err,
            format!(
                "sha256 mismatch for {}: expected {}, got {}",
                urls[wrong_at],
                sha(FILE),
                sha(b"other")
            ),
            "wrong at {wrong_at}"
        );
        assert_eq!(script.calls.last().unwrap(), urls[wrong_at]);
        assert!(
            script
                .calls
                .iter()
                .all(|c| urls[..=wrong_at].contains(&c.as_str()))
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "old");
        assert_untouched(dir.path(), &["f.deb"]);
    }
}

#[test]
fn when_every_url_fails_the_error_lists_each_attempt_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("f.deb");
    let mut script = Script::new(&[
        (A, vec![down_dns(A), down_dns(A), down_dns(A)]),
        (B, vec![down_dns(B), gone(B)]),
    ]);
    let err = script.fetch(&scripted(&[A, B], &out)).unwrap_err();
    assert_eq!(
        err,
        format!(
            "no URL served {}:\n\
             fetch: {A}: attempt 1 of 3: {A}: host not found; again in 5s\n\
             fetch: {A}: attempt 2 of 3: {A}: host not found; again in 20s\n\
             fetch: {A}: attempt 3 of 3: {A}: host not found\n\
             fetch: {B}: attempt 1 of 3: {B}: host not found; again in 5s\n\
             fetch: {B}: attempt 2 of 3: {B}: status 404\n",
            out.display()
        )
    );
    assert_eq!(script.calls, [A, A, A, B, B]);
    assert_eq!(script.pauses, [BACKOFF[0], BACKOFF[1], BACKOFF[0]]);
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_url_is_tried_at_most_three_times_5s_then_20s_apart() {
    // The other tests compare pauses with `BACKOFF`; this pins its values.
    assert_eq!(BACKOFF, [Duration::from_secs(5), Duration::from_secs(20)]);
}

// Which failures of a request are transient.

#[test]
fn a_failed_name_lookup_connection_or_timeout_is_transient_and_nothing_else_is() {
    let transient = [
        ureq::Error::HostNotFound,
        ureq::Error::ConnectionFailed,
        ureq::Error::Io(std::io::ErrorKind::ConnectionReset.into()),
        ureq::Error::Timeout(ureq::Timeout::Connect),
        ureq::Error::Timeout(ureq::Timeout::Resolve),
        ureq::Error::Timeout(ureq::Timeout::Global),
        ureq::Error::Io(std::io::ErrorKind::ConnectionRefused.into()),
        ureq::Error::Io(std::io::ErrorKind::UnexpectedEof.into()),
        ureq::Error::Io(std::io::ErrorKind::TimedOut.into()),
        ureq::Error::Io(std::io::ErrorKind::NetworkUnreachable.into()),
    ];
    for e in &transient {
        assert!(is_transient(e), "{e:?}");
    }
    let permanent = [
        ureq::Error::StatusCode(404),
        ureq::Error::BadUri("x".into()),
        ureq::Error::Tls("bad"),
        ureq::Error::RequireHttpsOnly("http://x".into()),
        ureq::Error::TooManyRedirects,
        ureq::Error::LargeResponseHeader(1, 1),
        // How a certificate the roots do not vouch for arrives.
        ureq::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid peer certificate",
        )),
        ureq::Error::Io(std::io::ErrorKind::PermissionDenied.into()),
    ];
    for e in &permanent {
        assert!(!is_transient(e), "{e:?}");
    }
}

#[test]
fn a_refused_connection_is_transient() {
    // A port that was just free on loopback: nothing listens on it.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let u = format!("https://127.0.0.1:{port}/x");
    let failure = download(&agent(roots()), &u, MAX_BYTES).unwrap_err();
    assert!(failure.transient, "{failure:?}");
    assert!(
        failure.message.starts_with(&format!("{u}: ")),
        "{failure:?}"
    );
}

#[test]
fn a_5xx_is_transient_and_a_4xx_is_not() {
    assert_eq!(
        down("/503").unwrap_err(),
        transient(format!("{}: status 503", url("/503")))
    );
    assert_eq!(
        down("/404").unwrap_err(),
        Failure::permanent(format!("{}: status 404", url("/404")))
    );
}

#[test]
fn a_body_cut_short_is_transient() {
    let failure = down("/short").unwrap_err();
    assert!(failure.transient, "{failure:?}");
    assert!(
        failure
            .message
            .starts_with(&format!("{}: reading the body: ", url("/short"))),
        "{failure:?}"
    );
}

// The download and the install, against the test server.

#[test]
fn a_file_with_the_right_sha256_is_written_executable() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let log = get(&opts("/file", sha(FILE), &out, None)).unwrap();
    assert_eq!(
        log,
        format!("fetch: wrote {} from {}\n", out.display(), url("/file"))
    );
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_untouched(dir.path(), &["tool"]);
}

#[test]
fn a_member_of_a_gzip_tar_is_extracted_after_the_whole_body_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let body = route("/tar", 0).body;
    get(&opts("/tar", sha(&body), &out, Some("bin/tool"))).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
}

#[test]
fn a_sha256_mismatch_writes_nothing_and_unpacks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    // The body is not even an archive: the mismatch is reported first.
    let err = get(&opts("/file", sha(b"other"), &out, Some("bin/tool"))).unwrap_err();
    assert_eq!(
        err,
        format!(
            "sha256 mismatch for {}: expected {}, got {}",
            url("/file"),
            sha(b"other"),
            sha(FILE)
        )
    );
    assert_untouched(dir.path(), &[]);
}

#[test]
fn an_existing_out_survives_every_failure() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    std::fs::write(&out, "old").unwrap();
    assert!(get(&opts("/file", sha(b"other"), &out, None)).is_err());
    assert!(get(&opts("/404", sha(FILE), &out, None)).is_err());
    assert!(get(&opts("/file", sha(FILE), &out, Some("bin/tool"))).is_err());
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "old");
    assert_untouched(dir.path(), &["tool"]);
}

#[test]
fn a_missing_member_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    // `/tar` has no `bin/absent`; `/tar-no-file` has `bin/tool` only as a directory.
    for (path, member) in [("/tar", "bin/absent"), ("/tar-no-file", "bin/tool")] {
        let body = route(path, 0).body;
        let err = get(&opts(path, sha(&body), &out, Some(member))).unwrap_err();
        assert_eq!(err, format!("the archive has no regular file {member}"));
    }
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_body_that_is_not_a_gzip_tar_or_is_cut_short_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/file", sha(FILE), &out, Some("bin/tool"))).unwrap_err();
    assert!(err.starts_with("reading the archive:"), "{err}");
    let body = route("/tar-truncated", 0).body;
    let err = get(&opts("/tar-truncated", sha(&body), &out, Some("bin/tool"))).unwrap_err();
    assert!(err.starts_with("reading the archive:"), "{err}");
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_body_cut_short_on_every_attempt_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/short", sha(FILE), &out, None)).unwrap_err();
    assert_eq!(err.matches("reading the body").count(), 3, "{err}");
    assert_untouched(dir.path(), &[]);
}

#[test]
fn redirects_are_followed_relative_or_absolute_up_to_five() {
    let dir = tempfile::tempdir().unwrap();
    for path in ["/rel", "/abs", "/hop/5"] {
        let out = dir.path().join("tool");
        get(&opts(path, sha(FILE), &out, None)).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), FILE, "{path}");
        std::fs::remove_file(&out).unwrap();
    }
}

#[test]
fn a_sixth_redirect_is_refused_for_good() {
    assert_eq!(
        down("/hop/6").unwrap_err(),
        Failure::permanent(format!("{}: more than 5 redirects", url("/hop/6")))
    );
}

#[test]
fn a_redirect_to_http_is_refused_for_good_and_so_is_an_http_url() {
    assert_eq!(
        down("/http").unwrap_err(),
        Failure::permanent("http://127.0.0.1:1/file: only https URLs are fetched".into())
    );
    assert_eq!(
        download(&agent(roots()), "http://127.0.0.1:1/file", MAX_BYTES).unwrap_err(),
        Failure::permanent("http://127.0.0.1:1/file: only https URLs are fetched".into())
    );
}

#[test]
fn an_unusable_url_or_location_is_refused_for_good() {
    assert_eq!(
        down("/no-location").unwrap_err(),
        Failure::permanent(format!(
            "{}: redirect without a usable Location",
            url("/no-location")
        ))
    );
    let failure = down("/bad-location").unwrap_err();
    assert!(!failure.transient);
    assert!(
        failure.message.contains("bad Location https://["),
        "{failure:?}"
    );
    let failure = download(&agent(roots()), "not a url", MAX_BYTES).unwrap_err();
    assert!(!failure.transient);
    assert!(failure.message.starts_with("not a url:"), "{failure:?}");
}

#[test]
fn a_server_the_roots_do_not_vouch_for_is_refused_for_good() {
    let (other_ca, _, _) = test_pki();
    let other =
        RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(&other_ca).to_owned()]);
    let failure = download(&agent(other), &url("/file"), MAX_BYTES).unwrap_err();
    assert!(!failure.transient, "{failure:?}");
}

#[test]
fn a_body_over_the_cap_is_refused_for_good() {
    let size = FILE.len() as u64;
    let agent = agent(roots());
    assert_eq!(download(&agent, &url("/file"), size).unwrap(), FILE);
    assert_eq!(
        download(&agent, &url("/file"), size - 1).unwrap_err(),
        Failure::permanent(format!(
            "{}: body is larger than {} bytes",
            url("/file"),
            size - 1
        ))
    );
}

#[test]
fn a_write_that_fails_leaves_no_part_file() {
    let dir = tempfile::tempdir().unwrap();
    // The directory of `out` does not exist.
    let out = dir.path().join("missing/tool");
    let err = get(&opts("/file", sha(FILE), &out, None)).unwrap_err();
    assert!(err.starts_with("writing "), "{err}");
    // `out` is a directory: the rename fails after `.part` was written.
    let out = dir.path().join("occupied");
    std::fs::create_dir(&out).unwrap();
    assert!(get(&opts("/file", sha(FILE), &out, None)).is_err());
    assert_untouched(dir.path(), &["occupied"]);
}

// The command line.

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
fn the_command_line_needs_a_url_sha256_and_out_and_keeps_the_urls_in_order() {
    let hex = "0".repeat(64);
    let o = parse_args(&s(&[
        "--url",
        "https://h/x",
        "--sha256",
        &hex.to_uppercase(),
        "--out",
        "o",
        "--url",
        "https://g/x",
        "--member",
        "m",
    ]))
    .unwrap();
    assert_eq!(
        o,
        Options {
            urls: vec!["https://h/x".into(), "https://g/x".into()],
            sha256: hex.clone(),
            out: "o".into(),
            member: Some("m".into())
        }
    );
    assert_eq!(
        parse_args(&s(&["--url", "u", "--sha256", &hex, "--out", "o"]))
            .unwrap()
            .member,
        None
    );
    for args in [
        s(&[]),
        s(&["--url", "u", "--sha256", &hex]),
        s(&["--url", "u", "--out", "o"]),
        s(&["--sha256", &hex, "--out", "o"]),
    ] {
        assert_eq!(parse_args(&args).unwrap_err(), USAGE);
    }
    assert_eq!(
        parse_args(&s(&["--url"])).unwrap_err(),
        "--url needs a value"
    );
    assert_eq!(
        parse_args(&s(&["--x", "1"])).unwrap_err(),
        "unknown flag --x"
    );
    for bad in ["abc", &"g".repeat(64)] {
        let err = parse_args(&s(&["--url", "u", "--sha256", bad, "--out", "o"])).unwrap_err();
        assert_eq!(err, "--sha256 must be 64 hex digits");
    }
}

#[test]
fn run_tries_the_next_url_and_reports_what_it_did() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let hex = sha(FILE);
    let args = s(&[
        "--url",
        &url("/503"),
        "--url",
        &url("/file"),
        "--sha256",
        &hex,
        "--out",
        &out.to_string_lossy(),
    ]);
    let mut pauses = Vec::new();
    let report = run_with(&args, roots(), MAX_BYTES, &mut |d| pauses.push(d)).unwrap();
    assert!(report.passed);
    let failed = format!(
        "fetch: {0}: attempt {{}} of 3: {0}: status 503",
        url("/503")
    );
    assert_eq!(
        report.text,
        format!(
            "{}; again in 5s\n{}; again in 20s\n{}\nfetch: wrote {} from {}\n",
            failed.replace("{}", "1"),
            failed.replace("{}", "2"),
            failed.replace("{}", "3"),
            out.display(),
            url("/file")
        )
    );
    assert_eq!(pauses, BACKOFF);
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
}

#[test]
fn run_uses_the_built_in_roots_and_reports_the_error() {
    // The built-in roots do not vouch for the test CA: refused for good, so `run` never pauses.
    let args = s(&[
        "--url",
        &url("/file"),
        "--sha256",
        &"0".repeat(64),
        "--out",
        "unused",
    ]);
    let err = run(&args).unwrap_err();
    let first = format!(
        "no URL served unused:\nfetch: {0}: attempt 1 of 3: {0}: ",
        url("/file")
    );
    assert!(err.starts_with(&first), "{err}");
    assert_eq!(err.lines().count(), 2, "{err}");
}
