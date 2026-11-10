//! The deploy runner's seam. The handlers of [`crate::handlers`] admit a deploy (record
//! written, service locked) and hand it to [`start`], which spawns one task per deploy that
//! runs [`run_deploy`] to the end of the record.
//!
//! [`run_deploy`] is where docs/design.md sections 3.2 to 3.6 run: fetch, verify, push, update
//! Swarm, wait, retention, the failed list and the floor. [`recover`] settles the records a
//! restart finds in state `running` (section 3.6). Until those are filled in, the task keeps
//! its permit and the record stays `queued`.

use std::sync::Arc;

use dsu_core::config::ServiceConfig;
use dsu_core::record::Record;
use dsu_core::url::ReleaseUrl;

use crate::app::App;
use crate::deployer::Permit;

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
    /// The service's lock; released when the task ends.
    pub permit: Permit,
}

/// Spawns the task that runs `job`.
pub fn start(app: &Arc<App>, job: Job) {
    tokio::spawn(run_deploy(Arc::clone(app), job));
}

/// Runs one deploy to a final record. Not yet filled in: holds the permit and does nothing.
pub async fn run_deploy(_app: Arc<App>, job: Job) {
    let _permit = job.permit;
    std::future::pending().await
}

/// Settles every record a restart finds in state `running`. Not yet filled in.
pub async fn recover(_app: &Arc<App>) {}
