//! The in-memory lock of docs/design.md section 3.6: one deploy per service at a time, and a
//! self-update that runs alone. A deploy is admitted, its record written and its lock taken
//! under one gate, so two requests for one (service, digest) never both start.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use dsu_core::api::ApiError;
use dsu_core::config::ServiceConfig;
use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_core::record::{CallerRecord, NewRecord, Record, State};

use crate::clock::Clock;
use crate::store::Store;

/// A deploy that holds its service's lock.
#[derive(Debug, Clone, Copy)]
struct Running {
    is_self: bool,
}

#[derive(Debug, Default)]
struct Locks {
    running: BTreeMap<ServiceName, (DeployId, Running)>,
}

/// The lock of one running deploy. Dropping it releases the service.
#[derive(Debug)]
pub struct Permit {
    locks: Arc<Mutex<Locks>>,
    service: ServiceName,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        locks.running.remove(&self.service);
    }
}

/// What a request asks to deploy.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    /// The configured service.
    pub service: &'a ServiceConfig,
    /// The manifest digest asked for.
    pub digest: &'a Digest,
    /// The caller's `version` text.
    pub version: &'a str,
    /// Who asked.
    pub caller: CallerRecord,
    /// The operator's `allow_older`.
    pub allow_older: bool,
}

/// The outcome of asking to deploy.
#[derive(Debug)]
pub enum Admission {
    /// A new deploy: its record is written (state `running`, phase `queued`) and its service
    /// is locked until the permit is dropped.
    Started {
        /// The record.
        record: Record,
        /// The lock.
        permit: Permit,
    },
    /// A deploy of this digest of this service is already running: its record.
    Existing(Record),
}

/// Decides which deploys may run.
#[derive(Debug)]
pub struct Deployer {
    gate: tokio::sync::Mutex<()>,
    locks: Arc<Mutex<Locks>>,
    own_service: Option<String>,
}

impl Deployer {
    /// A deployer with no deploy running. `own_service` is the Swarm service the updater
    /// itself runs as, when it runs as one.
    pub fn new(own_service: Option<String>) -> Self {
        Self {
            gate: tokio::sync::Mutex::new(()),
            locks: Arc::new(Mutex::new(Locks::default())),
            own_service,
        }
    }

    /// Section 3.1 steps 3 and 4 for a request that passed every check of step 2: a running
    /// deploy of the same digest answers [`Admission::Existing`]; another digest of the service
    /// running is `busy`; a self-update next to any other deploy is `self_update_busy`; a
    /// digest of the failed list is `previously_failed`. Otherwise the record is written and
    /// the service locked.
    pub async fn admit(
        &self,
        store: &Store,
        clock: &dyn Clock,
        id: DeployId,
        candidate: Candidate<'_>,
    ) -> Result<Admission, ApiError> {
        let _gate = self.gate.lock().await;
        let service = &candidate.service.name;
        if let Some(running) = store
            .latest_for_digest(service, candidate.digest)
            .await
            .filter(|r| r.state == State::Running)
        {
            return Ok(Admission::Existing(running));
        }
        let is_self = self.own_service.as_deref() == Some(candidate.service.swarm_service.as_str());
        self.check_free(service, is_self)?;
        if store
            .service_state(service)
            .await
            .is_failed(candidate.digest)
        {
            return Err(ApiError::PreviouslyFailed(format!(
                "{} is in the failed list of service {service}; the operator clears it",
                candidate.digest
            )));
        }
        let record = Record::start(NewRecord {
            id: id.clone(),
            service: service.clone(),
            swarm_service: candidate.service.swarm_service.clone(),
            image_digest: candidate.digest.clone(),
            version: candidate.version.to_owned(),
            caller: candidate.caller,
            allow_older: candidate.allow_older,
            now: clock.now(),
        });
        let permit = self.lock(service, id, Running { is_self });
        store.put_record(&record).await?;
        Ok(Admission::Started { record, permit })
    }

    fn check_free(&self, service: &ServiceName, is_self: bool) -> Result<(), ApiError> {
        let locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((id, _)) = locks.running.get(service) {
            return Err(ApiError::Busy(format!(
                "deploy {id} of service {service} is running another digest"
            )));
        }
        let clash = locks
            .running
            .iter()
            .find(|(_, (_, running))| is_self || running.is_self);
        match clash {
            Some((other, (id, _))) => Err(ApiError::SelfUpdateBusy(format!(
                "deploy {id} of service {other} is running, and a self-update runs alone"
            ))),
            None => Ok(()),
        }
    }

    fn lock(&self, service: &ServiceName, id: DeployId, running: Running) -> Permit {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        locks.running.insert(service.clone(), (id, running));
        Permit {
            locks: Arc::clone(&self.locks),
            service: service.clone(),
        }
    }
}
