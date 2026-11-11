//! The state directory (docs/design.md section 3.6): files only, each written to a temporary
//! name, synced and renamed.
//!
//! - `deploys/<id>.json`: one [`Record`] per deploy;
//! - `services/<name>.json`: one [`ServiceState`] per service;
//! - `jti/<sha256 of the jti, hex>`: an accepted token id; the content is its `exp`.
//!
//! Everything is loaded at [`Store::open`] and kept in memory behind one lock. A change is
//! written before it is visible, so a failed write changes nothing.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_core::record::{Record, State};
use dsu_core::state::ServiceState;
use jiff::{SignedDuration, Timestamp};
use sha2::{Digest as _, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, watch};

/// How long after the last prune the next request prunes again.
const PRUNE_INTERVAL: SignedDuration = SignedDuration::from_hours(1);

/// A state file or directory that cannot be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A file system call failed.
    #[error("state directory: {path}: {source}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The operating system error.
        source: io::Error,
    },
    /// A state file does not hold what its name says.
    #[error("state directory: {path} is not a valid state file: {reason}")]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
}

/// The error mapper for file `path`.
fn io_at(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

fn corrupt(path: &Path, reason: impl ToString) -> StoreError {
    StoreError::Corrupt {
        path: path.to_owned(),
        reason: reason.to_string(),
    }
}

/// The file name of a spent token id: the SHA-256 of the `jti`, in hex.
fn jti_file_name(jti: &str) -> String {
    hex::encode(Sha256::digest(jti.as_bytes()))
}

/// The temporary name `path` is written under before it is renamed.
fn temporary(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// Writes `bytes` to a temporary file, syncs it, renames it to `path` and syncs the directory.
async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    async fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let temp = temporary(path);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&temp, path).await?;
        let dir = path.parent().unwrap_or(Path::new("."));
        fs::File::open(dir).await?.sync_all().await
    }
    write(path, bytes).await.map_err(io_at(path))
}

/// Creates `dir` (and its parents) with mode 0700 when it does not exist.
async fn create_dir(dir: &Path) -> Result<(), StoreError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .await
        .map_err(io_at(dir))
}

/// The files of `dir` with their paths, leftover temporary files removed.
async fn list_files(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let mut entries = fs::read_dir(dir).await.map_err(io_at(dir))?;
    let mut files = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(io_at(dir))? {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "tmp") {
            fs::remove_file(&path).await.map_err(io_at(&path))?;
        } else {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// The text of the file `path` and the name before its `.json` extension.
async fn read_json_file(path: &Path) -> Result<(String, Vec<u8>), StoreError> {
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".json"))
        .ok_or_else(|| corrupt(path, "the name does not end in .json"))?;
    let bytes = fs::read(path).await.map_err(io_at(path))?;
    Ok((stem.to_owned(), bytes))
}

struct Inner {
    records: BTreeMap<DeployId, Record>,
    services: BTreeMap<ServiceName, ServiceState>,
    jtis: BTreeMap<String, Timestamp>,
    last_prune: Timestamp,
}

/// The state directory, loaded.
pub struct Store {
    dir: PathBuf,
    inner: Mutex<Inner>,
    changes: watch::Sender<u64>,
}

impl Store {
    /// Opens `dir`, creating it and its three subdirectories when missing, loads every
    /// record, service state and spent token id, and removes the token ids whose `exp` is not
    /// after `now`. A file that is not what its name says is refused.
    pub async fn open(dir: &Path, now: Timestamp) -> Result<Store, StoreError> {
        for sub in ["deploys", "services", "jti"] {
            create_dir(&dir.join(sub)).await?;
        }
        let mut records = BTreeMap::new();
        for path in list_files(&dir.join("deploys")).await? {
            let (stem, bytes) = read_json_file(&path).await?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|e| corrupt(&path, e))?;
            if record.id.as_str() != stem {
                return Err(corrupt(&path, "the record's id is not the file name"));
            }
            records.insert(record.id.clone(), record);
        }
        let mut services = BTreeMap::new();
        for path in list_files(&dir.join("services")).await? {
            let (stem, bytes) = read_json_file(&path).await?;
            let name = ServiceName::parse(&stem).map_err(|e| corrupt(&path, e))?;
            let state = serde_json::from_slice(&bytes).map_err(|e| corrupt(&path, e))?;
            services.insert(name, state);
        }
        let mut jtis = BTreeMap::new();
        for path in list_files(&dir.join("jti")).await? {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| corrupt(&path, "the name is not the SHA-256 of a token id"))?;
            let text = fs::read_to_string(&path).await.map_err(io_at(&path))?;
            let exp: Timestamp = text.trim().parse().map_err(|e| corrupt(&path, e))?;
            jtis.insert(name.to_owned(), exp);
        }
        let store = Store {
            dir: dir.to_owned(),
            inner: Mutex::new(Inner {
                records,
                services,
                jtis,
                last_prune: now,
            }),
            changes: watch::channel(0).0,
        };
        let mut inner = store.inner.lock().await;
        store.prune(&mut inner, now).await;
        drop(inner);
        Ok(store)
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A receiver that is notified after every written record and service state, so a
    /// caller can wait for a change without polling: it reads the store, and when the
    /// state it wants is not there yet, waits on `changed()` and reads again.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Proves the directory can be written to: a file is created, synced and removed. It runs
    /// under the store's lock, so overlapping checks never share the file.
    pub async fn check_writable(&self) -> Result<(), StoreError> {
        let _inner = self.inner.lock().await;
        let path = self.dir.join("health");
        write_atomic(&path, b"ok").await?;
        fs::remove_file(&path).await.map_err(io_at(&path))
    }

    /// The record `id`, if there is one.
    pub async fn record(&self, id: &DeployId) -> Option<Record> {
        self.inner.lock().await.records.get(id).cloned()
    }

    /// Writes `record` and makes it the current one for its id.
    pub async fn put_record(&self, record: &Record) -> Result<(), StoreError> {
        let path = self.dir.join("deploys").join(format!("{}.json", record.id));
        let bytes = serde_json::to_vec_pretty(record).map_err(|e| corrupt(&path, e))?;
        let mut inner = self.inner.lock().await;
        write_atomic(&path, &bytes).await?;
        inner.records.insert(record.id.clone(), record.clone());
        self.changes.send_modify(|n| *n += 1);
        Ok(())
    }

    /// The newest record of `service` for `digest`.
    pub async fn latest_for_digest(
        &self,
        service: &ServiceName,
        digest: &Digest,
    ) -> Option<Record> {
        let inner = self.inner.lock().await;
        newest(
            inner
                .records
                .values()
                .filter(|r| &r.service == service && &r.image_digest == digest),
        )
    }

    /// The newest record of `service`.
    pub async fn last_record(&self, service: &ServiceName) -> Option<Record> {
        let inner = self.inner.lock().await;
        newest(inner.records.values().filter(|r| &r.service == service))
    }

    /// Every record in state `running`, oldest first: what a restart settles.
    pub async fn running_records(&self) -> Vec<Record> {
        let inner = self.inner.lock().await;
        let mut running: Vec<Record> = inner
            .records
            .values()
            .filter(|r| r.state == State::Running)
            .cloned()
            .collect();
        running.sort_by(|a, b| (a.started, &a.id).cmp(&(b.started, &b.id)));
        running
    }

    /// The services whose state still names a deploy as pending although that deploy's
    /// record is final: a conclusion the last process did not finish.
    pub async fn finished_but_pending(&self) -> Vec<(ServiceName, Record)> {
        let inner = self.inner.lock().await;
        inner
            .services
            .iter()
            .filter_map(|(name, state)| {
                let record = inner.records.get(&state.pending.as_ref()?.deploy)?;
                (record.state != State::Running).then(|| (name.clone(), record.clone()))
            })
            .collect()
    }

    /// The state of `service`: the default (nothing failed, nothing converged) when no file
    /// exists yet.
    pub async fn service_state(&self, service: &ServiceName) -> ServiceState {
        let inner = self.inner.lock().await;
        inner.services.get(service).cloned().unwrap_or_default()
    }

    /// Changes the state of `service` with `change`, writes it, and returns what `change`
    /// returned. When the write fails the state is unchanged.
    pub async fn update_service<R>(
        &self,
        service: &ServiceName,
        change: impl FnOnce(&mut ServiceState) -> R,
    ) -> Result<R, StoreError> {
        let path = self.dir.join("services").join(format!("{service}.json"));
        let mut inner = self.inner.lock().await;
        let mut state = inner.services.get(service).cloned().unwrap_or_default();
        let result = change(&mut state);
        let bytes = serde_json::to_vec_pretty(&state).map_err(|e| corrupt(&path, e))?;
        write_atomic(&path, &bytes).await?;
        inner.services.insert(service.clone(), state);
        self.changes.send_modify(|n| *n += 1);
        Ok(result)
    }

    /// Accepts the token id `jti` once: `true` and the id is kept until `exp`; `false` when
    /// it was accepted before. When an hour has passed since the last prune, the ids whose
    /// `exp` is not after `now` are forgotten first.
    pub async fn spend_jti(
        &self,
        jti: &str,
        exp: Timestamp,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().await;
        if now.duration_since(inner.last_prune) >= PRUNE_INTERVAL {
            self.prune(&mut inner, now).await;
        }
        let name = jti_file_name(jti);
        if inner.jtis.contains_key(&name) {
            return Ok(false);
        }
        write_atomic(
            &self.dir.join("jti").join(&name),
            exp.to_string().as_bytes(),
        )
        .await?;
        inner.jtis.insert(name, exp);
        Ok(true)
    }

    /// Forgets the token ids whose `exp` is not after `now`, and their files. A file that
    /// cannot be removed is left: it is loaded and forgotten again at the next start.
    async fn prune(&self, inner: &mut Inner, now: Timestamp) {
        let expired: Vec<String> = inner
            .jtis
            .iter()
            .filter(|(_, exp)| **exp <= now)
            .map(|(name, _)| name.clone())
            .collect();
        for name in expired {
            let _ = fs::remove_file(self.dir.join("jti").join(&name)).await;
            inner.jtis.remove(&name);
        }
        inner.last_prune = now;
    }
}

/// The record that started last (ties broken by id).
fn newest<'a>(records: impl Iterator<Item = &'a Record>) -> Option<Record> {
    records
        .max_by(|a, b| (a.started, &a.id).cmp(&(b.started, &b.id)))
        .cloned()
}
