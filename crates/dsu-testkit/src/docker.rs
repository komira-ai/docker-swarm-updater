//! A fake Docker Engine API on a Unix socket (docs/design.md section 6): services with a
//! spec, a version, an update status, a previous spec and tasks; a script saying how the
//! next update goes; a record of every update body received. Time is set by the test. As
//! Swarm, an update that leaves the task template as it was starts no rollout.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use jiff::Timestamp;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

/// How an accepted update ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `completed`: every task runs the new image.
    Converges,
    /// `rollback_completed`: the previous spec is restored and every task runs its image.
    RollsBack,
    /// `paused`.
    Pauses,
    /// `updating` forever.
    NeverEnds,
    /// The update is refused with status 500 and this message; the service is unchanged.
    Refuses(String),
    /// The update is answered 200 and dropped: the spec, the version and the status are
    /// unchanged.
    Ignores,
}

/// How updates go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateScript {
    /// How an accepted update ends.
    pub outcome: Outcome,
    /// Updates answered "out of sequence" before one is accepted: each such update first
    /// bumps the service's `Version.Index`, as another writer would.
    pub conflicts: u32,
    /// Reads of the service after an accepted update that still show the status it had
    /// before (a stale terminal state).
    pub stale_reads: u32,
    /// Reads after those that show `updating`, before the outcome's state shows.
    pub updating_reads: u32,
}

impl UpdateScript {
    /// An update with this outcome, no conflicts, no stale reads, no `updating` reads.
    pub fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            conflicts: 0,
            stale_reads: 0,
            updating_reads: 0,
        }
    }
}

/// A service's `UpdateStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FakeUpdateStatus {
    /// The state, as Docker spells it (`completed`, `rollback_completed`, ...).
    pub state: String,
    /// When the update started.
    pub started_at: Timestamp,
    /// The status message.
    pub message: String,
}

/// A task of a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeTask {
    /// The task id.
    pub id: String,
    /// The image the task runs.
    pub image: String,
    /// The task state (`running`, `failed`, ...).
    pub state: String,
    /// The task's error.
    pub error: Option<String>,
    /// The state the orchestrator wants (`running`, `shutdown`).
    pub desired_state: String,
}

impl FakeTask {
    /// A running task wanted running.
    pub fn running(id: &str, image: &str) -> Self {
        Self {
            id: id.to_owned(),
            image: image.to_owned(),
            state: "running".to_owned(),
            error: None,
            desired_state: "running".to_owned(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "ID": self.id,
            "DesiredState": self.desired_state,
            "Spec": {"ContainerSpec": {"Image": self.image}},
            "Status": {"State": self.state, "Err": self.error},
        })
    }
}

/// A Swarm service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeService {
    /// The service id.
    pub id: String,
    /// The service name.
    pub name: String,
    /// `Version.Index`.
    pub index: u64,
    /// `Spec`, with fields the updater does not touch.
    pub spec: Value,
    /// `PreviousSpec`.
    pub previous_spec: Option<Value>,
    /// `UpdateStatus`.
    pub update_status: Option<FakeUpdateStatus>,
    /// The service's tasks.
    pub tasks: Vec<FakeTask>,
    pending: Option<Pending>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    started_at: Timestamp,
    reads: u32,
}

impl FakeService {
    /// A service at version 1 running `image`, with no update status and no tasks.
    pub fn new(id: &str, name: &str, image: &str) -> Self {
        Self {
            id: id.to_owned(),
            name: name.to_owned(),
            index: 1,
            spec: json!({
                "Name": name,
                "Labels": {"com.example.team": "platform"},
                "TaskTemplate": {
                    "ContainerSpec": {"Image": image, "Env": ["MODE=prod"]},
                    "Resources": {"Limits": {"MemoryBytes": 268_435_456}},
                },
                "Mode": {"Replicated": {"Replicas": 1}},
                "UpdateConfig": {"Order": "start-first", "FailureAction": "rollback"},
            }),
            previous_spec: None,
            update_status: None,
            tasks: Vec::new(),
            pending: None,
        }
    }

    fn image(&self) -> String {
        self.spec
            .pointer("/TaskTemplate/ContainerSpec/Image")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned()
    }

    fn to_json(&self) -> Value {
        json!({
            "ID": self.id,
            "Version": {"Index": self.index},
            "Spec": self.spec,
            "PreviousSpec": self.previous_spec,
            "UpdateStatus": self.update_status,
        })
    }

    fn is(&self, name_or_id: &str) -> bool {
        self.id == name_or_id || self.name == name_or_id
    }
}

/// An update request the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedUpdate {
    /// The service name or id in the request path.
    pub service: String,
    /// The `version` query parameter (0 when absent or not a number).
    pub version: u64,
    /// The request body as JSON (`null` when it is not JSON).
    pub body: Value,
}

struct State {
    now: Timestamp,
    ping_status: u16,
    script: UpdateScript,
    conflicts_left: u32,
    services: Vec<FakeService>,
    containers: BTreeMap<String, BTreeMap<String, String>>,
    updates: Vec<RecordedUpdate>,
}

type Shared = Arc<Mutex<State>>;

/// The fake daemon: serves on `docker.sock` in the directory it was started in, until
/// dropped.
pub struct FakeDocker {
    socket: PathBuf,
    state: Shared,
    accept: JoinHandle<()>,
}

impl Drop for FakeDocker {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl FakeDocker {
    /// Starts serving on `<dir>/docker.sock`; `now` is the fake's time. Updates converge
    /// at once until [`FakeDocker::set_script`] says otherwise.
    pub async fn start(dir: &Path, now: Timestamp) -> Self {
        let socket = dir.join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let state: Shared = Arc::new(Mutex::new(State {
            now,
            ping_status: 200,
            script: UpdateScript::new(Outcome::Converges),
            conflicts_left: 0,
            services: Vec::new(),
            containers: BTreeMap::new(),
            updates: Vec::new(),
        }));
        let served = Arc::clone(&state);
        let accept = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let state = Arc::clone(&served);
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(handle(&state, request).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            socket,
            state,
            accept,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// The socket path to give the client.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Sets the time the fake stamps `StartedAt` with.
    pub fn set_now(&self, now: Timestamp) {
        self.lock().now = now;
    }

    /// Sets the status `GET /_ping` answers with.
    pub fn set_ping_status(&self, status: u16) {
        self.lock().ping_status = status;
    }

    /// Sets how updates go from now on.
    pub fn set_script(&self, script: UpdateScript) {
        let mut state = self.lock();
        state.conflicts_left = script.conflicts;
        state.script = script;
    }

    /// Adds a service.
    pub fn add_service(&self, service: FakeService) {
        self.lock().services.push(service);
    }

    /// A copy of the service with this name or id.
    pub fn service(&self, name_or_id: &str) -> FakeService {
        self.lock()
            .services
            .iter()
            .find(|s| s.is(name_or_id))
            .unwrap()
            .clone()
    }

    /// Replaces the tasks of the service with this name or id.
    pub fn set_tasks(&self, name_or_id: &str, tasks: Vec<FakeTask>) {
        self.lock()
            .services
            .iter_mut()
            .find(|s| s.is(name_or_id))
            .unwrap()
            .tasks = tasks;
    }

    /// Sets the image of the spec of the service with this name or id (its tasks are set
    /// with [`FakeDocker::set_tasks`]).
    pub fn set_image(&self, name_or_id: &str, image: &str) {
        self.lock()
            .services
            .iter_mut()
            .find(|s| s.is(name_or_id))
            .unwrap()
            .spec["TaskTemplate"]["ContainerSpec"]["Image"] = Value::String(image.to_owned());
    }

    /// Starts an update of the service with this name or id that someone else asked for at
    /// `started_at`: from the next read it goes as the script says, like an accepted update.
    pub fn begin_update(&self, name_or_id: &str, started_at: Timestamp) {
        self.lock()
            .services
            .iter_mut()
            .find(|s| s.is(name_or_id))
            .unwrap()
            .pending = Some(Pending {
            started_at,
            reads: 0,
        });
    }

    /// Sets the status of the service with this name or id.
    pub fn set_update_status(&self, name_or_id: &str, status: FakeUpdateStatus) {
        self.lock()
            .services
            .iter_mut()
            .find(|s| s.is(name_or_id))
            .unwrap()
            .update_status = Some(status);
    }

    /// Adds a container (looked up by id or hostname) with these labels.
    pub fn add_container(&self, id_or_hostname: &str, labels: &[(&str, &str)]) {
        let labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        self.lock()
            .containers
            .insert(id_or_hostname.to_owned(), labels);
    }

    /// Every update request received, in order, accepted or not.
    pub fn updates(&self) -> Vec<RecordedUpdate> {
        self.lock().updates.clone()
    }
}

fn reply(status: u16, body: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn message(status: u16, text: &str) -> Response<Full<Bytes>> {
    reply(status, &json!({"message": text}))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap();
            out.push(u8::from_str_radix(hex, 16).unwrap());
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| percent_decode(v))
}

async fn handle(state: &Shared, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let query = parts.uri.query().unwrap_or("");
    let segments: Vec<String> = parts
        .uri
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(percent_decode)
        .collect();
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    let mut state = state.lock().unwrap();
    match (&parts.method, segments.as_slice()) {
        (&Method::GET, ["_ping"]) => Response::builder()
            .status(state.ping_status)
            .body(Full::new(Bytes::from("OK")))
            .unwrap(),
        (&Method::GET, ["services", key]) => inspect(&mut state, key),
        (&Method::POST, ["services", key, "update"]) => update(&mut state, key, query, &body),
        (&Method::GET, ["tasks"]) => tasks(&state, query),
        (&Method::GET, ["containers", host, "json"]) => match state.containers.get(*host) {
            Some(labels) => reply(200, &json!({"Config": {"Labels": labels}})),
            None => message(404, &format!("No such container: {host}")),
        },
        _ => message(404, "page not found"),
    }
}

fn service_not_found(key: &str) -> Response<Full<Bytes>> {
    message(404, &format!("service {key} not found"))
}

/// A read of a service; an update in progress advances by one step first.
fn inspect(state: &mut State, key: &str) -> Response<Full<Bytes>> {
    let Some(service) = state.services.iter_mut().find(|s| s.is(key)) else {
        return service_not_found(key);
    };
    if let Some(pending) = &mut service.pending {
        pending.reads += 1;
        let (reads, started_at) = (pending.reads, pending.started_at);
        advance(service, &state.script, reads, started_at);
    }
    reply(200, &service.to_json())
}

/// The status the `reads`th read after an accepted update shows: the status from before
/// for `stale_reads` reads, `updating` for `updating_reads` more, then the outcome.
fn advance(service: &mut FakeService, script: &UpdateScript, reads: u32, started_at: Timestamp) {
    if reads <= script.stale_reads {
        return;
    }
    let status = |state: &str, message: &str| {
        Some(FakeUpdateStatus {
            state: state.to_owned(),
            started_at,
            message: message.to_owned(),
        })
    };
    service.update_status = status("updating", "update in progress");
    if reads <= script.stale_reads + script.updating_reads {
        return;
    }
    match script.outcome {
        Outcome::Converges => {
            service.update_status = status("completed", "update completed");
            settle(service);
        }
        Outcome::RollsBack => {
            let restored = service.previous_spec.take().unwrap();
            service.previous_spec = Some(std::mem::replace(&mut service.spec, restored));
            service.index += 1;
            service.update_status = status("rollback_completed", "rollback completed");
            settle(service);
        }
        Outcome::Pauses => {
            service.update_status = status(
                "paused",
                "update paused due to failure or early termination of task",
            );
            service.pending = None;
        }
        Outcome::NeverEnds | Outcome::Refuses(_) | Outcome::Ignores => {}
    }
}

/// Every task runs the image of the spec and the update is over.
fn settle(service: &mut FakeService) {
    let image = service.image();
    for task in &mut service.tasks {
        task.image.clone_from(&image);
        "running".clone_into(&mut task.state);
        task.error = None;
    }
    service.pending = None;
}

fn update(state: &mut State, key: &str, query: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let version = query_param(query, "version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let new_spec: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    state.updates.push(RecordedUpdate {
        service: key.to_owned(),
        version,
        body: new_spec.clone(),
    });
    let bump = state.conflicts_left > 0;
    state.conflicts_left -= u32::from(bump);
    let Some(service) = state.services.iter_mut().find(|s| s.is(key)) else {
        return service_not_found(key);
    };
    if let Outcome::Refuses(text) = &state.script.outcome {
        return message(500, text);
    }
    service.index += u64::from(bump);
    if version != service.index {
        return message(500, "update out of sequence");
    }
    if state.script.outcome == Outcome::Ignores {
        return reply(200, &json!({"Warnings": null}));
    }
    // As Swarm: a spec whose task template is unchanged (only service labels differ) is
    // stored, but no rollout starts and the status stays what it was.
    let rolls_out = new_spec.get("TaskTemplate") != service.spec.get("TaskTemplate");
    service.previous_spec = Some(std::mem::replace(&mut service.spec, new_spec));
    service.index += 1;
    if rolls_out {
        service.pending = Some(Pending {
            started_at: state.now,
            reads: 0,
        });
    }
    reply(200, &json!({"Warnings": null}))
}

fn tasks(state: &State, query: &str) -> Response<Full<Bytes>> {
    let filters: Value = serde_json::from_str(&query_param(query, "filters").unwrap_or_default())
        .unwrap_or(Value::Null);
    let wants = |key: &str, value: &str| {
        filters[key]
            .as_array()
            .is_some_and(|list| list.iter().any(|v| v == value))
    };
    let tasks: Vec<Value> = state
        .services
        .iter()
        .filter(|s| wants("service", &s.id) || wants("service", &s.name))
        .flat_map(|s| &s.tasks)
        .filter(|t| wants("desired-state", &t.desired_state))
        .map(FakeTask::to_json)
        .collect();
    reply(200, &Value::Array(tasks))
}
