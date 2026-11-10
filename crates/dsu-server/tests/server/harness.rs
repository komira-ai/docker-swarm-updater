//! A running updater for the API tests: the fake Docker daemon, the fake clock, a fake peer
//! uid, the server on a Unix socket in a temporary directory, and a raw HTTP client.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use base64::Engine as _;
use dsu_core::ids::Digest;
use dsu_server::app::{App, Params};
use dsu_server::fetch::{SystemDisk, default_roots};
use dsu_server::peer::PeerCred;
use dsu_server::server::{ServeError, bind_socket, serve};
use dsu_server::startup::load_config;
use dsu_testkit::docker::{FakeDocker, FakeService, FakeTask};
use dsu_testkit::mint::Authority;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::support::{FakeClock, FakeNetwork};

/// The uid of the fronting proxy.
pub const PROXY: u32 = 1234;
/// Another user.
pub const OTHER: u32 = 4321;
/// The registry named in the config; the API tests never connect to it.
pub const REGISTRY: &str = "127.0.0.1:5000";
/// The workflow of the callers.
pub const DEPLOY_WORKFLOW: &str = "example-org/docker-swarm-updater/.github/workflows/deploy.yml@0123456789012345678901234567890123456789";

/// The config of the harness: three services, `ghost` having no Swarm service.
pub fn config_text(trusted_root: &Path, registry: &str) -> String {
    let service = |name: &str, id: &str| {
        format!(
            r#"
[[service]]
name = "{name}"
swarm_service = "{name}_server"
repository = "{name}"
platform = "linux/amd64"
artifact_url = {{ owner = "example-org", repo = "{name}" }}
artifact_name = "{name}-*-linux-x86_64.image.tar"
signer = {{ repository = "example-org/{name}", repository_id = "{id}", workflow = ".github/workflows/artifacts.yml", ref = "refs/heads/main", triggers = ["push"] }}
  [[service.caller]]
  repository = "example-org/{name}"
  repository_id = "{id}"
  job_workflow_ref = "{DEPLOY_WORKFLOW}"
  ref = "refs/heads/main"
  environment = "production"
  runner_environment = "github-hosted"
"#
        )
    };
    format!(
        r#"registry = "{registry}"
trusted_root = "{}"
redirect_hosts = ["objects.githubusercontent.com"]
keep_previous = 3
min_free_bytes = 0
{}{}{}"#,
        trusted_root.display(),
        service("app", "1"),
        service("web", "2"),
        service("ghost", "3"),
    )
}

/// A digest made of one repeated byte.
pub fn digest(n: u8) -> Digest {
    Digest::from_sha256([n; 32])
}

/// The image reference the harness's `app` service runs digest `n` under.
pub fn app_image(n: u8) -> String {
    format!("{REGISTRY}/app@{}", digest(n))
}

/// A peer whose uid the test sets, and that can be made to fail.
pub struct FakePeer {
    uid: AtomicU32,
    fail: AtomicBool,
}

impl PeerCred for FakePeer {
    fn uid(&self, _stream: &UnixStream) -> std::io::Result<u32> {
        if self.fail.load(Ordering::SeqCst) {
            Err(std::io::Error::other("no credentials"))
        } else {
            Ok(self.uid.load(Ordering::SeqCst))
        }
    }
}

/// The parts that outlive one updater process: the directory, the daemon, the clock.
pub struct Env {
    pub dir: tempfile::TempDir,
    pub docker: Option<FakeDocker>,
    pub clock: FakeClock,
    pub config_path: PathBuf,
    pub authority: Authority,
}

impl Env {
    /// The daemon runs `app_server` (digest 1, one task) and `web_server` (digest 2).
    pub async fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let clock = FakeClock::new();
        let authority = Authority::public_good();
        let root = dir.path().join("trusted_root.json");
        write_trusted_root(&root, &authority.trusted_root_json());
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, config_text(&root, REGISTRY)).unwrap();
        let docker = FakeDocker::start(dir.path(), dsu_server::clock::Clock::now(&clock)).await;
        docker.add_service(FakeService::new("id-app", "app_server", &app_image(1)));
        docker.set_tasks("app_server", vec![FakeTask::running("t1", &app_image(1))]);
        docker.add_service(FakeService::new(
            "id-web",
            "web_server",
            &format!("{REGISTRY}/web@{}", digest(2)),
        ));
        Env {
            dir,
            docker: Some(docker),
            clock,
            config_path,
            authority,
        }
    }

    pub fn docker(&self) -> &FakeDocker {
        self.docker.as_ref().unwrap()
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.path().join("run").join("dsu.sock")
    }

    /// The files of a state subdirectory.
    pub fn state_files(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.state_dir().join(sub))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// Options of one updater process.
#[derive(Clone)]
pub struct Options {
    pub allow_local_operator: bool,
    pub hostname: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            allow_local_operator: true,
            hostname: "dsu-test-host".to_owned(),
        }
    }
}

/// One updater process on the environment's socket.
pub struct Updater {
    pub app: Arc<App>,
    peer: Arc<FakePeer>,
    socket: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), ServeError>>>,
    counter: AtomicUsize,
}

pub struct Reply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    /// The `error` token of an error answer.
    pub fn error(&self) -> String {
        self.json()["error"].as_str().unwrap().to_owned()
    }
}

/// An HTTP/1.1 request as bytes.
pub fn http(method: &str, target: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut text = format!(
        "{method} {target} HTTP/1.1\r\nhost: dsu\r\nconnection: close\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Sends `request` on a new connection and reads until the server closes it.
pub async fn raw(socket: &Path, request: &[u8]) -> Reply {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    let _ = stream.write_all(request).await;
    let mut data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => data.extend_from_slice(&buffer[..n]),
        }
    }
    parse_reply(&data)
}

pub fn parse_reply(data: &[u8]) -> Reply {
    let split = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no response: {:?}", String::from_utf8_lossy(data)));
    let head = String::from_utf8_lossy(&data[..split]).into_owned();
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (name, value) = l.split_once(": ").unwrap();
            (name.to_lowercase(), value.to_owned())
        })
        .collect();
    Reply {
        status,
        headers,
        body: data[split + 4..].to_vec(),
    }
}

impl Updater {
    pub async fn start(env: &Env, options: Options) -> Updater {
        let loaded = load_config(&env.config_path).unwrap();
        let peer = Arc::new(FakePeer {
            uid: AtomicU32::new(PROXY),
            fail: AtomicBool::new(false),
        });
        let app = App::start(Params {
            config: loaded.config,
            roots: loaded.roots,
            state_dir: env.state_dir(),
            docker_socket: env.docker().socket().to_owned(),
            proxy_uid: PROXY,
            allow_local_operator: options.allow_local_operator,
            hostname: options.hostname,
            clock: Arc::new(env.clock.clone()),
            peer_cred: peer.clone(),
            network: Arc::new(FakeNetwork::new(0)),
            disk: Arc::new(SystemDisk),
            tls_roots: default_roots(),
        })
        .await
        .unwrap();
        let listener = bind_socket(&env.socket(), current_gid()).unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(Arc::clone(&app), listener, async {
            let _ = stopped.await;
        }));
        Updater {
            app,
            peer,
            socket: env.socket(),
            stop: Some(stop),
            task: Some(task),
            counter: AtomicUsize::new(0),
        }
    }

    /// Stops the server and waits for it to return.
    pub async fn stop(mut self) -> Result<(), ServeError> {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap()
    }

    pub fn set_peer(&self, uid: u32) {
        self.peer.uid.store(uid, Ordering::SeqCst);
    }

    pub fn fail_peer(&self, fail: bool) {
        self.peer.fail.store(fail, Ordering::SeqCst);
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// A claims header value for `caller` with a fresh `jti`, valid for 300 s of fake time.
    pub fn token(&self, caller: &Value) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        self.token_with(caller, &format!("jti-{n}"), 300)
    }

    pub fn token_with(&self, caller: &Value, jti: &str, valid_for: i64) -> String {
        let now = dsu_server::clock::Clock::now(self.app.clock.as_ref()).as_second();
        let mut payload = caller.clone();
        payload["jti"] = json!(jti);
        payload["exp"] = json!(now + valid_for);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
    }

    /// Sends a request as `uid`, with `claims` in the claims header when given.
    pub async fn call(
        &self,
        uid: u32,
        method: &str,
        target: &str,
        claims: Option<String>,
        body: &[u8],
    ) -> Reply {
        self.set_peer(uid);
        let headers: Vec<(&str, String)> =
            claims.into_iter().map(|c| ("x-dsu-claims", c)).collect();
        raw(&self.socket, &http(method, target, &headers, body)).await
    }

    /// A request from the proxy for `caller` with a fresh token.
    pub async fn as_caller(
        &self,
        caller: &Value,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> Reply {
        self.call(PROXY, method, target, Some(self.token(caller)), body)
            .await
    }

    /// A request from the local operator.
    pub async fn as_operator(&self, method: &str, target: &str, body: &[u8]) -> Reply {
        self.call(0, method, target, None, body).await
    }
}

/// Writes a trusted-root file the way the start check wants it: mode 0644, owned by the
/// test's user.
pub fn write_trusted_root(path: &Path, json: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, json).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

pub fn current_gid() -> u32 {
    rustix::process::getgid().as_raw()
}

/// The claims of a caller of the harness service `name` (`app` is repository id 1).
pub fn caller(name: &str) -> Value {
    let id = match name {
        "app" => "1",
        "web" => "2",
        _ => "3",
    };
    json!({
        "repository": format!("example-org/{name}"),
        "repository_id": id,
        "job_workflow_ref": DEPLOY_WORKFLOW,
        "ref": "refs/heads/main",
        "environment": "production",
        "runner_environment": "github-hosted",
        "run_id": "77",
    })
}

/// The body of a deploy of `name`'s digest `n`, with `edit` applied to the JSON.
pub fn deploy_body(name: &str, n: u8, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let file = format!("{name}-1.0-linux-x86_64.image.tar");
    let url = format!("https://github.com/example-org/{name}/releases/download/v1/{file}");
    let mut body = json!({
        "image_digest": digest(n),
        "image_url": url,
        "bundle_url": format!("{url}.sigstore.json"),
        "version": "1.0",
    });
    edit(&mut body);
    body.to_string().into_bytes()
}

pub fn deploys(name: &str) -> String {
    format!("/v1/services/{name}/deploys")
}
