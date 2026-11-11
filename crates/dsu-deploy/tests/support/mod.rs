//! Shared by the test binaries: an HTTP/1.1 server on 127.0.0.1 port 0 in a thread, and the
//! fakes of `Http` and `Clock`.
#![allow(
    dead_code,
    reason = "each test binary uses a different part of this module"
)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dsu_deploy::client::{Clock, Http, Request, Response, TransportError};

/// A valid deploy id.
pub const ID: &str = "d-abcdefghijklmnopqrstuvwxyz";
/// Another valid deploy id.
pub const OTHER_ID: &str = "d-234567abcdefghijklmnopqrst";
/// A valid digest.
pub const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
/// The token endpoint of the fakes, as GitHub gives it (with a query already).
pub const TOKEN_URL: &str = "https://tokens.example/token?api-version=2.0";
/// The deploy front of the fakes.
pub const ENDPOINT: &str = "http://deploy.example:8450";

/// One request the loopback server read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// The loopback server: answers each request with `answer(method, target)`.
pub struct Server {
    pub port: u16,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    pub fn start(answer: impl Fn(&str, &str) -> (u16, Vec<u8>) + Send + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_owned();
                let target = parts.next().unwrap_or_default().to_owned();
                let (mut length, mut authorization, mut content_type) = (0usize, None, None);
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    let value = value.trim().to_owned();
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.parse().unwrap(),
                        "authorization" => authorization = Some(value),
                        "content-type" => content_type = Some(value),
                        _ => {}
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                let (status, reply) = answer(&method, &target);
                log.lock().unwrap().push(Seen {
                    method,
                    target,
                    authorization,
                    content_type,
                    body,
                });
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&reply);
            }
        });
        Server { port, seen }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// A record body.
pub fn record(id: &str, state: &str, phase: &str, error: Option<(&str, &str)>) -> Vec<u8> {
    let mut value = serde_json::json!({
        "id": id, "service": "app", "swarm_service": "app_server", "image_digest": DIGEST,
        "version": "1.2.3", "caller": {"repository": "example-org/app"}, "state": state,
        "phase": phase, "steps": [], "started": "2026-11-10T00:00:00Z",
    });
    if let Some((token, detail)) = error {
        value["error"] = serde_json::json!({"token": token, "detail": detail});
    }
    value.to_string().into_bytes()
}

/// An error body.
pub fn error_body(error: &str, detail: &str) -> Vec<u8> {
    serde_json::json!({"error": error, "detail": detail})
        .to_string()
        .into_bytes()
}

/// One scripted answer of [`FakeHttp`].
pub type Answer = Result<Response, TransportError>;

pub fn answer(status: u16, body: Vec<u8>) -> Answer {
    Ok(Response { status, body })
}

pub fn unreachable_answer(url: &str) -> Answer {
    Err(TransportError {
        url: url.to_owned(),
        message: "connection refused".to_owned(),
    })
}

/// [`Http`] in memory: token requests (URLs starting with the token endpoint's origin and path)
/// get `token-1`, `token-2`, ... until `good_tokens` were minted, then `token_answer` if it is
/// set; every other request takes the next scripted answer.
pub struct FakeHttp {
    pub script: RefCell<VecDeque<Answer>>,
    pub token_answer: RefCell<Option<Answer>>,
    pub good_tokens: Cell<u32>,
    pub sent: RefCell<Vec<Request>>,
    minted: Cell<u32>,
}

impl FakeHttp {
    pub fn new(script: Vec<Answer>) -> Self {
        Self {
            script: RefCell::new(script.into()),
            token_answer: RefCell::new(None),
            good_tokens: Cell::new(0),
            sent: RefCell::new(Vec::new()),
            minted: Cell::new(0),
        }
    }

    /// Every request but token requests, as (method, url, bearer).
    pub fn calls(&self) -> Vec<(String, String, String)> {
        self.sent
            .borrow()
            .iter()
            .filter(|r| !r.url.starts_with("https://tokens.example/"))
            .map(|r| (format!("{:?}", r.method), r.url.clone(), r.bearer.clone()))
            .collect()
    }

    /// The token requests' URLs and bearers.
    pub fn token_requests(&self) -> Vec<(String, String)> {
        self.sent
            .borrow()
            .iter()
            .filter(|r| r.url.starts_with("https://tokens.example/"))
            .map(|r| (r.url.clone(), r.bearer.clone()))
            .collect()
    }
}

impl Http for FakeHttp {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        self.sent.borrow_mut().push(request.clone());
        if request.url.starts_with("https://tokens.example/") {
            if self.minted.get() >= self.good_tokens.get()
                && let Some(answer) = self.token_answer.borrow().clone()
            {
                return answer;
            }
            self.minted.set(self.minted.get() + 1);
            let body =
                serde_json::json!({"count": 1, "value": format!("token-{}", self.minted.get())});
            return Ok(Response {
                status: 200,
                body: body.to_string().into_bytes(),
            });
        }
        self.script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("no answer scripted for {request:?}"))
    }
}

/// A virtual clock: `sleep` moves it forward and returns at once.
#[derive(Default)]
pub struct FakeClock {
    now: Cell<Duration>,
    pub sleeps: Cell<u32>,
}

impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.now.get()
    }

    fn sleep(&self, duration: Duration) {
        self.sleeps.set(self.sleeps.get() + 1);
        self.now.set(self.now.get() + duration);
    }
}
