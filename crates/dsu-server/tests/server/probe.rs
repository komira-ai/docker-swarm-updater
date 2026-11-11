//! `probe` (docs/design.md section 4.3): 200, 503, refused, timeout, a non-loopback URL and a
//! Unix socket.
use std::net::SocketAddr;
use std::time::Duration;

use crate::support::FakeClock;
use dsu_server::probe::{ProbeFailure, ProbeOutcome, ProbeTarget, TargetError, probe};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinHandle;

const TIMEOUT: Duration = Duration::from_secs(2);

/// Answers one request with `status` and returns the request head it received. `None` closes
/// the connection without an answer.
fn answer_once<L: Listener>(listener: L, status: Option<u16>) -> JoinHandle<String> {
    tokio::spawn(async move {
        let mut stream = listener.accept_one().await;
        let mut buf = vec![0u8; 4096];
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        if let Some(status) = status {
            let reply =
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(reply.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        String::from_utf8(buf[..n].to_vec()).unwrap()
    })
}

trait Listener: Send + 'static {
    type Stream: AsyncReadExt + AsyncWriteExt + Unpin + Send;
    fn accept_one(self) -> impl std::future::Future<Output = Self::Stream> + Send;
}

impl Listener for TcpListener {
    type Stream = tokio::net::TcpStream;
    async fn accept_one(self) -> Self::Stream {
        self.accept().await.unwrap().0
    }
}

impl Listener for UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept_one(self) -> Self::Stream {
        self.accept().await.unwrap().0
    }
}

async fn tcp_target(path: &str) -> (TcpListener, ProbeTarget) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = ProbeTarget::from_url(&format!("http://127.0.0.1:{port}{path}")).unwrap();
    (listener, target)
}

/// Probes on a clock that never moves, so the deadline cannot fire before an answer.
async fn run(target: &ProbeTarget) -> ProbeOutcome {
    probe(target, TIMEOUT, &FakeClock::new()).await
}

#[tokio::test]
async fn a_2xx_answer_is_exit_0_and_the_request_is_a_plain_get() {
    for status in [200, 204, 299] {
        let (listener, target) = tcp_target("/readyz?full=1").await;
        let server = answer_once(listener, Some(status));
        let outcome = run(&target).await;
        assert!(
            matches!(outcome, ProbeOutcome::Healthy),
            "{status}: {outcome:?}"
        );
        assert_eq!(outcome.exit_code(), 0);
        let head = server.await.unwrap();
        assert!(
            head.starts_with("GET /readyz?full=1 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("host: 127.0.0.1:"),
            "{head}"
        );
    }
}

#[tokio::test]
async fn other_statuses_are_exit_1() {
    for status in [301, 404, 503] {
        let (listener, target) = tcp_target("/readyz").await;
        let server = answer_once(listener, Some(status));
        let outcome = run(&target).await;
        assert!(
            matches!(&outcome, ProbeOutcome::Unhealthy(ProbeFailure::Status(s)) if *s == status),
            "{status}: {outcome:?}"
        );
        assert_eq!(outcome.exit_code(), 1);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_refused_connection_is_exit_1() {
    let (listener, target) = tcp_target("/readyz").await;
    drop(listener);
    let outcome = run(&target).await;
    assert!(
        matches!(outcome, ProbeOutcome::Unhealthy(ProbeFailure::Connect(_))),
        "{outcome:?}"
    );
    assert_eq!(outcome.exit_code(), 1);
}

#[tokio::test]
async fn a_connection_closed_without_an_answer_is_exit_1() {
    let (listener, target) = tcp_target("/readyz").await;
    let server = answer_once(listener, None);
    let outcome = run(&target).await;
    assert!(
        matches!(outcome, ProbeOutcome::Unhealthy(ProbeFailure::Http(_))),
        "{outcome:?}"
    );
    assert_eq!(outcome.exit_code(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn no_answer_within_the_timeout_is_exit_1() {
    let (listener, target) = tcp_target("/readyz").await;
    // The listener accepts nothing and answers nothing; the test moves the clock.
    let clock = FakeClock::new();
    let outcome = clock.pump(TIMEOUT, probe(&target, TIMEOUT, &clock)).await;
    assert!(
        matches!(&outcome, ProbeOutcome::Unhealthy(ProbeFailure::Timeout(t)) if *t == TIMEOUT),
        "{outcome:?}"
    );
    assert_eq!(outcome.exit_code(), 1);
    drop(listener);
}

#[tokio::test]
async fn an_answer_in_time_does_not_need_the_clock_to_move() {
    let (listener, target) = tcp_target("/").await;
    let server = answer_once(listener, Some(200));
    let clock = FakeClock::new();
    assert_eq!(probe(&target, TIMEOUT, &clock).await.exit_code(), 0);
    server.await.unwrap();
}

#[tokio::test]
async fn a_unix_socket_is_probed_with_the_given_path() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dsu.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = answer_once(listener, Some(200));
    let target = ProbeTarget::unix(&socket, "/v1/health").unwrap();
    assert_eq!(run(&target).await.exit_code(), 0);
    let head = server.await.unwrap();
    assert!(head.starts_with("GET /v1/health HTTP/1.1\r\n"), "{head}");

    let listener = UnixListener::bind(dir.path().join("sick.sock")).unwrap();
    let server = answer_once(listener, Some(503));
    let target = ProbeTarget::unix(dir.path().join("sick.sock"), "/v1/health").unwrap();
    assert_eq!(run(&target).await.exit_code(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn a_missing_unix_socket_is_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let target = ProbeTarget::unix(dir.path().join("none.sock"), "/v1/health").unwrap();
    let outcome = run(&target).await;
    assert!(
        matches!(outcome, ProbeOutcome::Unhealthy(ProbeFailure::Connect(_))),
        "{outcome:?}"
    );
}

#[test]
fn only_http_urls_on_a_loopback_ip_are_accepted() {
    let ok = ProbeTarget::from_url("http://127.0.0.1:8080/readyz").unwrap();
    assert_eq!(
        ok,
        ProbeTarget::Tcp {
            addr: "127.0.0.1:8080".parse().unwrap(),
            host: "127.0.0.1:8080".into(),
            target: "/readyz".into()
        }
    );
    let default_port = ProbeTarget::from_url("http://127.1.2.3/a?b=c").unwrap();
    assert_eq!(
        default_port,
        ProbeTarget::Tcp {
            addr: "127.1.2.3:80".parse().unwrap(),
            host: "127.1.2.3".into(),
            target: "/a?b=c".into()
        }
    );
    let v6 = ProbeTarget::from_url("http://[::1]:9/x").unwrap();
    assert_eq!(
        v6,
        ProbeTarget::Tcp {
            addr: "[::1]:9".parse::<SocketAddr>().unwrap(),
            host: "[::1]:9".into(),
            target: "/x".into()
        }
    );
    let root = ProbeTarget::from_url("http://127.0.0.1:1").unwrap();
    assert!(matches!(root, ProbeTarget::Tcp { target, .. } if target == "/"));
}

#[test]
fn urls_that_reach_out_of_the_task_are_refused() {
    for raw in [
        "http://192.0.2.1/x",
        "http://10.0.0.1/x",
        "http://0.0.0.0/x",
        "http://[2001:db8::1]/x",
        "http://example.com/x",
        "http://localhost:8080/x",
        "https://127.0.0.1/x",
        "ftp://127.0.0.1/x",
        "unix:///run/x.sock",
        "data:text/plain,x",
    ] {
        let err = ProbeTarget::from_url(raw).unwrap_err();
        assert!(matches!(err, TargetError::NotLoopback(_)), "{raw}: {err:?}");
        assert!(err.to_string().contains(raw));
    }
    assert!(matches!(
        ProbeTarget::from_url("not a url").unwrap_err(),
        TargetError::NotAUrl(_)
    ));
    assert!(matches!(
        ProbeTarget::from_url("").unwrap_err(),
        TargetError::NotAUrl(_)
    ));
}

#[test]
fn request_paths_must_be_absolute_and_valid() {
    assert!(ProbeTarget::unix("/s", "/v1/health").is_ok());
    assert!(ProbeTarget::unix("/s", "/").is_ok());
    for bad in ["", "v1/health", "*", "/a b", "/a\r\nHost: x"] {
        let err = ProbeTarget::unix("/s", bad).unwrap_err();
        assert!(
            matches!(&err, TargetError::BadPath(p) if p == bad),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn failures_are_described_on_one_line() {
    let failures = [
        ProbeFailure::Connect(std::io::Error::other("x")),
        ProbeFailure::Status(503),
        ProbeFailure::Timeout(TIMEOUT),
    ];
    for failure in failures {
        assert!(!failure.to_string().contains('\n'), "{failure}");
    }
}
