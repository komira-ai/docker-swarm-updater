//! The deploy runner (docs/design.md sections 3.2 to 3.6). The handlers of
//! [`crate::handlers`] admit a deploy (record written, service locked) and hand it to
//! [`start`], which runs [`run_deploy`] as a task to the end of the record:
//!
//! - fetching: the bundle and the image tar go to `downloads/<id>/` in the state directory;
//! - verifying: `index.json`, the bundle, the blobs and the platform, then the signed-time
//!   floor ([`crate::pipeline::verify_tar`]);
//! - pushing: the blobs and the manifest to the registry, by digest;
//! - updating: the Swarm service's spec with its image and two labels changed (a
//!   self-update writes phase `handed_off` here instead of `updating`);
//! - waiting: polling the service until [`dsu_core::swarm::judge`] settles it.
//!
//! The downloaded files are removed as soon as the push is over. A deploy ends `converged`
//! (floor, converged list, retention), `rolled_back`, `paused` or `failed`. [`recover`]
//! settles the records a restart finds in state `running` with the same rules.

use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dsu_core::config::ServiceConfig;
use dsu_core::ids::{Digest, ServiceName};
use dsu_core::record::{ErrorToken, Phase, Record, State, TransitionError, enters_failed_list};
use dsu_core::retention::to_delete;
use dsu_core::swarm::{self, RestartAction, Snapshot, Verdict, restart_action};
use dsu_core::url::ReleaseUrl;
use dsu_docker::{DockerError, ServiceView, TaskView};
use jiff::SignedDuration;

use crate::app::{App, image_digest, image_reference};
use crate::deployer::Permit;
use crate::fetch::{FetchError, Limits};
use crate::pipeline::{PipelineError, VerifyJob, push_tar, verify_tar};
use crate::store::StoreError;

/// Time between two reads of the Swarm service while waiting for its update.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The largest Sigstore bundle accepted.
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
/// The directory of the state directory that holds the files being downloaded.
const DOWNLOADS: &str = "downloads";

/// An accepted deploy, handed to the task that runs it.
#[derive(Debug)]
pub struct Job {
    /// The record as written at admission: state `running`, phase `queued`.
    pub record: Record,
    /// The configured service.
    pub service: ServiceConfig,
    /// The image tar's release URL, checked against the URL rules.
    pub image_url: ReleaseUrl,
    /// The bundle's release URL, checked against the URL rules.
    pub bundle_url: ReleaseUrl,
    /// The service's lock; released when the deploy ends.
    pub permit: Permit,
}

/// A record or service state that could not be settled or written.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// The state directory failed.
    #[error("{0}")]
    Store(#[from] StoreError),
    /// A record refused a change its deploy made (a defect, not a condition of the world).
    #[error("{0}")]
    Record(#[from] TransitionError),
    /// The Docker API failed while a restart read the service of a running deploy.
    #[error("cannot read the Swarm service of deploy {id}: {source}")]
    Docker {
        /// The deploy.
        id: dsu_core::ids::DeployId,
        /// The Docker error.
        source: DockerError,
    },
}

/// Spawns the task that runs `job`.
pub fn start(app: &Arc<App>, job: Job) {
    app.spawn_deploy(run_deploy(Arc::clone(app), job));
}

/// Runs one deploy to a final record.
pub async fn run_deploy(app: Arc<App>, job: Job) {
    let Job {
        record,
        service,
        image_url,
        bundle_url,
        permit,
    } = job;
    let mut run = Run::new(app, record, service, permit);
    let result = run.deploy(&image_url, &bundle_url).await;
    // A final record that cannot be written leaves the record `running`; the next start
    // settles it.
    let _ = run.conclude(result).await;
}

/// Settles every record a restart finds in state `running` (section 3.6): one before Swarm
/// was asked to update fails `interrupted`; one after is read against the service's
/// `UpdateStatus` and ends, or goes on waiting as a task. Leftover downloads are removed.
pub async fn recover(app: &Arc<App>) -> Result<(), RunnerError> {
    // Best effort: a directory that is not there is the normal case, and leftovers only
    // cost disk.
    let _ = tokio::fs::remove_dir_all(app.store.dir().join(DOWNLOADS)).await;
    // Decided before any wait task starts: these records are final and no task works on them.
    let unfinished = app.store.finished_but_pending().await;
    for record in app.store.running_records().await {
        match app.service(&record.service).cloned() {
            Some(service) => settle(app, record, service).await?,
            None => abandon(app, record).await?,
        }
    }
    for (name, record) in unfinished {
        complete_service_state(app, &name, &record).await?;
    }
    Ok(())
}

/// Finishes the service-state half of a conclusion the last process stopped in the middle
/// of: the record is final, the service still names it as pending.
async fn complete_service_state(
    app: &App,
    name: &ServiceName,
    record: &Record,
) -> Result<(), RunnerError> {
    let digest = record.image_digest.clone();
    let signed_time = record.signed_time.unwrap_or(record.started);
    let id = record.id.clone();
    let converged = record.state == State::Converged;
    let listed = record
        .error
        .as_ref()
        .is_some_and(|e| enters_failed_list(e.token, false));
    app.store
        .update_service(name, |s| {
            s.clear_pending();
            if converged {
                s.record_converged(digest, signed_time, id);
            } else if listed {
                s.add_failed(digest);
            }
        })
        .await?;
    Ok(())
}

/// Ends a running record whose service the config no longer lists.
async fn abandon(app: &App, mut record: Record) -> Result<(), RunnerError> {
    let detail = format!("service {} is no longer configured", record.service);
    record.finish_failed(ErrorToken::Interrupted, detail, app.clock.now())?;
    Ok(app.store.put_record(&record).await?)
}

/// Applies the restart rule to one running record.
async fn settle(app: &Arc<App>, record: Record, service: ServiceConfig) -> Result<(), RunnerError> {
    let docker_error = |source| RunnerError::Docker {
        id: record.id.clone(),
        source,
    };
    let swarm = app
        .swarm_tasks(&service.swarm_service)
        .await
        .map_err(docker_error)?;
    let state = app.store.service_state(&service.name).await;
    let permit = app.deployer.adopt(&service, record.id.clone());
    let expected = image_reference(
        &app.config.registry,
        &service.repository,
        &record.image_digest,
    );
    let id = record.id.clone();
    let phase = record.phase;
    let mut run = Run::new(Arc::clone(app), record, service, permit);
    match (swarm, state.pending_for(&id)) {
        (Some((view, tasks)), Some(pending)) => {
            let images: Vec<String> = tasks.iter().map(|t| t.image.clone()).collect();
            let action = restart_action(
                phase,
                Some(pending),
                &core_view(&view),
                &images,
                &expected,
                &id,
            );
            run.observed = Some(Observation { view, tasks });
            match settled(verdict_of(action)) {
                Some(result) => run.conclude(result).await,
                None => {
                    let snapshot = pending.snapshot();
                    app.spawn_deploy(async move {
                        let result = run.wait(snapshot).await;
                        let _ = run.conclude(result).await;
                    });
                    Ok(())
                }
            }
        }
        _ => {
            let detail = "the updater restarted and nothing says Swarm's update of this deploy ran";
            run.conclude(Err(Failure::new(ErrorToken::Interrupted, detail)))
                .await
        }
    }
}

/// What the restart rule decided, as the verdict the wait loop works with.
fn verdict_of(action: RestartAction) -> Verdict {
    match action {
        RestartAction::FailInterrupted => Verdict::Interrupted,
        RestartAction::Converged => Verdict::Converged,
        RestartAction::RolledBack => Verdict::RolledBack,
        RestartAction::Paused => Verdict::Paused,
        RestartAction::ResumeWait => Verdict::Waiting,
    }
}

/// The end a verdict means, or `None` while Swarm is still updating.
fn settled(verdict: Verdict) -> Option<Result<(), Failure>> {
    match verdict {
        Verdict::Waiting => None,
        Verdict::Converged => Some(Ok(())),
        Verdict::RolledBack => Some(Err(Failure::new(
            ErrorToken::SwarmRolledBack,
            "Swarm rolled the update back",
        ))),
        Verdict::Paused => Some(Err(Failure::new(
            ErrorToken::SwarmPaused,
            "Swarm paused the update; a person must look",
        ))),
        Verdict::Interrupted => Some(Err(Failure::new(
            ErrorToken::Interrupted,
            "the service's spec is not explained by an update of this deploy",
        ))),
    }
}

/// The service as the rule of [`swarm::judge`] reads it.
fn core_view(view: &ServiceView) -> swarm::ServiceView {
    swarm::ServiceView {
        version_index: view.version_index,
        update_status: view.update_status.as_ref().map(|s| swarm::UpdateStatus {
            state: s.state.clone(),
            started_at: s.started_at,
        }),
        image: view.image.clone(),
        deploy_label: view.deploy_label.clone(),
    }
}

/// Why a deploy ended without converging.
#[derive(Debug)]
struct Failure {
    token: ErrorToken,
    detail: String,
    /// Found after `index.json` named `image_digest` (see [`enters_failed_list`]).
    digest_bound: bool,
}

impl Failure {
    fn new(token: ErrorToken, detail: impl Display) -> Self {
        Self {
            token,
            detail: detail.to_string().replace('\n', " "),
            digest_bound: false,
        }
    }

    /// A deploy that cannot go on because its own state cannot be kept or run.
    fn interrupted(error: impl Display) -> Self {
        Self::new(ErrorToken::Interrupted, error)
    }

    fn fetch(error: FetchError) -> Self {
        Self::new(error.token(), error)
    }

    fn pipeline(error: PipelineError) -> Self {
        Self {
            token: error.token(),
            detail: error.detail(),
            digest_bound: error.digest_bound(),
        }
    }

    fn swarm(error: DockerError) -> Self {
        Self::new(ErrorToken::SwarmRefused, error)
    }
}

/// The Swarm service and its tasks as last read.
#[derive(Debug)]
struct Observation {
    view: ServiceView,
    tasks: Vec<TaskView>,
}

/// One deploy in progress.
struct Run {
    app: Arc<App>,
    record: Record,
    service: ServiceConfig,
    permit: Permit,
    observed: Option<Observation>,
    poll_error: Option<String>,
}

impl Run {
    fn new(app: Arc<App>, record: Record, service: ServiceConfig, permit: Permit) -> Self {
        Self {
            app,
            record,
            service,
            permit,
            observed: None,
            poll_error: None,
        }
    }

    fn image(&self) -> String {
        image_reference(
            &self.app.config.registry,
            &self.service.repository,
            &self.record.image_digest,
        )
    }

    fn downloads(&self) -> PathBuf {
        self.app
            .store
            .dir()
            .join(DOWNLOADS)
            .join(self.record.id.as_str())
    }

    /// Moves the record to `phase` and writes it.
    async fn enter(&mut self, phase: Phase) -> Result<(), Failure> {
        self.record
            .enter_phase(phase, self.app.clock.now())
            .map_err(Failure::interrupted)?;
        self.app
            .store
            .put_record(&self.record)
            .await
            .map_err(Failure::interrupted)
    }

    /// Sets the note of the step in progress (written with the next change of the record).
    fn note(&mut self, note: String) -> Result<(), Failure> {
        self.record.annotate(note).map_err(Failure::interrupted)
    }

    /// Sections 3.2 to 3.5: everything up to and including the wait.
    async fn deploy(
        &mut self,
        image_url: &ReleaseUrl,
        bundle_url: &ReleaseUrl,
    ) -> Result<(), Failure> {
        let dir = self.downloads();
        let prepared = self.prepare(image_url, bundle_url, &dir).await;
        // The files are not needed once the push is over, or the deploy failed.
        let _ = tokio::fs::remove_dir_all(&dir).await;
        prepared?;
        let snapshot = self.update().await?;
        self.wait(snapshot).await
    }

    /// Fetches, verifies and pushes the image.
    async fn prepare(
        &mut self,
        image_url: &ReleaseUrl,
        bundle_url: &ReleaseUrl,
        dir: &Path,
    ) -> Result<(), Failure> {
        self.enter(Phase::Fetching).await?;
        let min_free_bytes = self.app.config.min_free_bytes;
        create_dir(dir).await.map_err(|e| {
            Failure::new(
                ErrorToken::FetchFailed,
                format!("cannot create {}: {e}", dir.display()),
            )
        })?;
        let bundle_limits = Limits {
            max_bytes: Some(MAX_BUNDLE_BYTES),
            min_free_bytes,
        };
        let bundle = self
            .app
            .fetcher
            .fetch(
                bundle_url.url(),
                dir,
                "bundle.sigstore.json",
                &bundle_limits,
            )
            .await
            .map_err(Failure::fetch)?;
        let image_limits = Limits {
            max_bytes: self.service.max_image_bytes,
            min_free_bytes,
        };
        let image = self
            .app
            .fetcher
            .fetch(image_url.url(), dir, "image.tar", &image_limits)
            .await
            .map_err(Failure::fetch)?;
        self.note(format!(
            "image {} bytes, sha256 {}; bundle {} bytes",
            image.size, image.digest, bundle.size
        ))?;

        self.enter(Phase::Verifying).await?;
        let bundle_bytes = tokio::fs::read(&bundle.path).await.map_err(|e| {
            Failure::new(
                ErrorToken::FetchFailed,
                format!("cannot read the downloaded bundle: {e}"),
            )
        })?;
        let job = VerifyJob {
            tar: image.path,
            tar_digest: image.digest,
            bundle: bundle_bytes,
            image_digest: self.record.image_digest.clone(),
            service: self.service.clone(),
            roots: Arc::clone(&self.app.roots),
        };
        let verified = tokio::task::spawn_blocking(move || verify_tar(&job))
            .await
            .map_err(Failure::interrupted)?
            .map_err(Failure::pipeline)?;
        self.record
            .set_signed_time(verified.signed_time)
            .map_err(Failure::interrupted)?;
        let state = self.app.store.service_state(&self.service.name).await;
        let older = state.is_older_than_floor(verified.signed_time);
        if older && !self.record.allow_older {
            return Err(Failure::new(
                ErrorToken::OlderThanRunning,
                format!(
                    "signed {}, before the running release's {}",
                    verified.signed_time,
                    state.floor.unwrap_or(verified.signed_time)
                ),
            ));
        }
        let accepted = if older {
            "; older than the running release, accepted because the operator asked (allow_older)"
        } else {
            ""
        };
        self.note(format!("signed {}{accepted}", verified.signed_time))?;

        self.enter(Phase::Pushing).await?;
        let digest = self.record.image_digest.clone();
        self.app
            .store
            .update_service(&self.service.name, |s| s.add_pushed(digest))
            .await
            .map_err(Failure::interrupted)?;
        push_tar(&self.app.registry, &self.service.repository, &verified)
            .await
            .map_err(Failure::pipeline)?;
        self.note(format!("pushed {}", self.image()))
    }

    /// Section 3.5 steps 1 and 2: reads the service, keeps the snapshot in the service state
    /// and asks Swarm for the update. Returns the snapshot of the read that was accepted.
    async fn update(&mut self) -> Result<Snapshot, Failure> {
        let phase = if self.app.deployer.is_self(&self.service.swarm_service) {
            Phase::HandedOff
        } else {
            Phase::Updating
        };
        self.enter(phase).await?;
        let image = self.image();
        let mut conflicts = 0;
        loop {
            let read_at = self.app.clock.now();
            let view = self
                .app
                .docker
                .inspect_service(&self.service.swarm_service)
                .await
                .map_err(Failure::swarm)?;
            let snapshot = Snapshot {
                version_index: view.version_index,
                read_at,
            };
            let id = self.record.id.clone();
            self.app
                .store
                .update_service(&self.service.name, |s| s.set_pending(id, snapshot))
                .await
                .map_err(Failure::interrupted)?;
            let update = self
                .app
                .docker
                .update_service(&view, &image, &self.record.id, &self.record.image_digest)
                .await;
            match update {
                Ok(()) => return Ok(snapshot),
                Err(DockerError::VersionConflict { .. }) if conflicts == 0 => conflicts += 1,
                Err(error) => return Err(Failure::swarm(error)),
            }
        }
    }

    /// Section 3.5 step 3: polls the service until its update is settled for this deploy.
    async fn wait(&mut self, snapshot: Snapshot) -> Result<(), Failure> {
        if self.record.phase < Phase::Waiting {
            self.enter(Phase::Waiting).await?;
        }
        let expected = self.image();
        let started = self
            .record
            .steps
            .last()
            .map_or(self.record.started, |step| step.started);
        let limit = self.service.converge_timeout_secs;
        loop {
            let verdict = self.poll(&snapshot, &expected).await;
            if let Some(result) = settled(verdict) {
                return result;
            }
            let elapsed = self.app.clock.now().duration_since(started);
            if limit != 0
                && elapsed >= SignedDuration::from_secs(i64::try_from(limit).unwrap_or(i64::MAX))
            {
                return Err(Failure::new(
                    ErrorToken::Timeout,
                    format!(
                        "Swarm did not settle the update within {limit} seconds; it is left to Swarm"
                    ),
                ));
            }
            self.app.clock.sleep(POLL_INTERVAL).await;
        }
    }

    /// One read of the service and its tasks, judged. A failed read keeps the wait going.
    async fn poll(&mut self, snapshot: &Snapshot, expected: &str) -> Verdict {
        let docker = &self.app.docker;
        let read = async {
            let view = docker.inspect_service(&self.service.swarm_service).await?;
            let tasks = docker.running_tasks(&view.id).await?;
            Ok::<_, DockerError>((view, tasks))
        }
        .await;
        match read {
            Ok((view, tasks)) => {
                let images: Vec<String> = tasks.iter().map(|t| t.image.clone()).collect();
                let verdict = swarm::judge(
                    snapshot,
                    &core_view(&view),
                    &images,
                    expected,
                    &self.record.id,
                );
                self.observed = Some(Observation { view, tasks });
                self.poll_error = None;
                verdict
            }
            Err(error) => {
                self.poll_error = Some(error.to_string().replace('\n', " "));
                Verdict::Waiting
            }
        }
    }

    /// The task states and errors last seen, and the last failed read, for the last step.
    fn observations(&self) -> Vec<String> {
        let tasks = self.observed.iter().map(|seen| {
            let tasks: Vec<String> = seen
                .tasks
                .iter()
                .map(|t| {
                    let error = t
                        .error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default();
                    format!("{} {} on {}{error}", t.id, t.state, t.image)
                })
                .collect();
            format!("tasks: {}", tasks.join(", "))
        });
        let failed = self
            .poll_error
            .iter()
            .map(|e| format!("the last read of the service failed: {e}"));
        tasks.chain(failed).collect()
    }

    /// Section 3.5 step 4: deletes the manifests the updater pushed that are no longer
    /// wanted. Returns the digests deleted and a note about what happened.
    async fn retire(&self) -> (Vec<Digest>, Option<String>) {
        let state = self.app.store.service_state(&self.service.name).await;
        let digest = &self.record.image_digest;
        let signed_time = self.record.signed_time.unwrap_or(self.record.started);
        let mut after = state;
        after.record_converged(digest.clone(), signed_time, self.record.id.clone());
        let mut running: std::collections::BTreeSet<Digest> = self
            .observed
            .iter()
            .flat_map(|seen| &seen.tasks)
            .filter_map(|t| image_digest(&t.image))
            .collect();
        running.insert(digest.clone());
        let previous = self
            .observed
            .as_ref()
            .and_then(|seen| seen.view.previous_image.as_deref())
            .and_then(image_digest);
        let doomed = to_delete(
            &after.pushed,
            &running,
            previous.as_ref(),
            &after.converged_digests(),
            self.app.config.keep_previous,
        );
        let mut deleted = Vec::new();
        let mut failed = Vec::new();
        for digest in doomed {
            match self
                .app
                .registry
                .delete_manifest(&self.service.repository, &digest)
                .await
            {
                Ok(()) => deleted.push(digest),
                Err(error) => failed.push(format!("{digest}: {error}")),
            }
        }
        let note = (!deleted.is_empty() || !failed.is_empty()).then(|| {
            format!(
                "retention: deleted {} manifests, {} could not be deleted{}",
                deleted.len(),
                failed.len(),
                failed
                    .first()
                    .map(|f| format!(" ({f})"))
                    .unwrap_or_default()
            )
        });
        (deleted, note)
    }

    /// Ends the record: the final record first, then the state of the service (floor, lists,
    /// snapshot), with the lock held throughout. A crash between the two writes leaves a final
    /// record and a service that still names it as pending, which [`recover`] completes; a
    /// crash before them leaves a running record and the pending snapshot, which the restart
    /// rule settles. When a write fails the lock is kept (the service stays busy until the
    /// next start settles it) because releasing it would let a request for the same digest be
    /// answered with a record no task works on.
    async fn conclude(mut self, result: Result<(), Failure>) -> Result<(), RunnerError> {
        let mut notes = self.observations();
        let now = self.app.clock.now();
        let digest = self.record.image_digest.clone();
        let mut deleted = Vec::new();
        let failure = match result {
            Ok(()) => {
                let (gone, note) = self.retire().await;
                deleted = gone;
                notes.extend(note);
                self.annotate(notes)?;
                self.record.finish_converged(now)?;
                None
            }
            Err(failure) => {
                self.annotate(notes)?;
                let listed = enters_failed_list(failure.token, failure.digest_bound);
                self.record
                    .finish_failed(failure.token, failure.detail, now)?;
                Some(listed)
            }
        };
        let written = match self.app.store.put_record(&self.record).await {
            Ok(()) => {
                let signed_time = self.record.signed_time.unwrap_or(self.record.started);
                let id = self.record.id.clone();
                self.app
                    .store
                    .update_service(&self.service.name, |s| {
                        s.clear_pending();
                        match failure {
                            None => {
                                s.record_converged(digest, signed_time, id);
                                s.forget_pushed(&deleted);
                            }
                            Some(true) => s.add_failed(digest),
                            Some(false) => {}
                        }
                    })
                    .await
            }
            Err(error) => Err(error),
        };
        let Run { permit, .. } = self;
        match written {
            Ok(()) => {
                drop(permit);
                Ok(())
            }
            Err(error) => {
                std::mem::forget(permit);
                Err(error.into())
            }
        }
    }

    fn annotate(&mut self, notes: Vec<String>) -> Result<(), TransitionError> {
        if notes.is_empty() {
            Ok(())
        } else {
            self.record.annotate(notes.join("; "))
        }
    }
}

/// Creates `dir` and its parents with mode 0700.
async fn create_dir(dir: &Path) -> io::Result<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .await
}
