//! Tests of `fetch` against an in-process HTTPS server on 127.0.0.1 with a test CA.

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
        url: url(path),
        sha256,
        out: out.to_path_buf(),
        member: member.map(str::to_owned),
    }
}

fn get(o: &Options) -> Result<(), String> {
    fetch(o, roots(), MAX_BYTES)
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

#[test]
fn a_file_with_the_right_sha256_is_written_executable() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    get(&opts("/file", sha(FILE), &out, None)).unwrap();
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
    assert!(
        err.starts_with("sha256 mismatch for https://127.0.0.1:"),
        "{err}"
    );
    assert!(err.contains(&sha(FILE)), "{err}");
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
fn a_body_cut_short_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/short", sha(FILE), &out, None)).unwrap_err();
    assert!(err.contains("reading the body"), "{err}");
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_status_outside_2xx_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/404", sha(FILE), &out, None)).unwrap_err();
    assert!(err.ends_with("/404: status 404"), "{err}");
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
fn a_sixth_redirect_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/hop/6", sha(FILE), &out, None)).unwrap_err();
    assert!(err.ends_with("more than 5 redirects"), "{err}");
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_redirect_to_http_is_refused_and_so_is_an_http_url() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/http", sha(FILE), &out, None)).unwrap_err();
    assert_eq!(err, "http://127.0.0.1:1/file: only https URLs are fetched");
    let mut o = opts("/file", sha(FILE), &out, None);
    o.url = "http://127.0.0.1:1/file".into();
    assert!(get(&o).unwrap_err().contains("only https"));
    assert_untouched(dir.path(), &[]);
}

#[test]
fn an_unusable_url_or_location_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let err = get(&opts("/no-location", sha(FILE), &out, None)).unwrap_err();
    assert!(err.ends_with("redirect without a usable Location"), "{err}");
    let err = get(&opts("/bad-location", sha(FILE), &out, None)).unwrap_err();
    assert!(err.contains("bad Location https://["), "{err}");
    let mut o = opts("/file", sha(FILE), &out, None);
    o.url = "not a url".into();
    assert!(get(&o).unwrap_err().starts_with("not a url:"));
}

#[test]
fn a_server_the_roots_do_not_vouch_for_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let o = opts("/file", sha(FILE), &out, None);
    let (other_ca, _, _) = test_pki();
    let other =
        RootCerts::new_with_certs(&[ureq::tls::Certificate::from_der(&other_ca).to_owned()]);
    assert!(fetch(&o, other, MAX_BYTES).is_err());
    assert_untouched(dir.path(), &[]);
}

#[test]
fn a_body_over_the_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let o = opts("/file", sha(FILE), &out, None);
    let size = FILE.len() as u64;
    fetch(&o, roots(), size).unwrap();
    std::fs::remove_file(&out).unwrap();
    let err = fetch(&o, roots(), size - 1).unwrap_err();
    assert!(
        err.ends_with(&format!("body is larger than {} bytes", size - 1)),
        "{err}"
    );
    assert_untouched(dir.path(), &[]);
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

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
fn the_command_line_needs_url_sha256_and_out() {
    let hex = "0".repeat(64);
    let o = parse_args(&s(&[
        "--url",
        "https://h/x",
        "--sha256",
        &hex.to_uppercase(),
        "--out",
        "o",
        "--member",
        "m",
    ]))
    .unwrap();
    assert_eq!(
        o,
        Options {
            url: "https://h/x".into(),
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
fn run_installs_the_file_and_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("tool");
    let hex = sha(FILE);
    let args = s(&[
        "--url",
        &url("/file"),
        "--sha256",
        &hex,
        "--out",
        &out.to_string_lossy(),
    ]);
    let report = run_with(&args, roots(), MAX_BYTES).unwrap();
    assert!(report.passed);
    assert_eq!(report.text, format!("fetch: wrote {}\n", out.display()));
    assert_eq!(std::fs::read(&out).unwrap(), FILE);
}

#[test]
fn run_uses_the_built_in_roots_and_reports_the_error() {
    // Nothing listens on port 1: the connection is refused.
    let args = s(&[
        "--url",
        "https://127.0.0.1:1/x",
        "--sha256",
        &"0".repeat(64),
        "--out",
        "unused",
    ]);
    assert!(
        run(&args)
            .unwrap_err()
            .starts_with("https://127.0.0.1:1/x:")
    );
}
