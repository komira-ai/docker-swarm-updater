//! The five endpoints (docs/design.md section 2.1). Each handler runs after the route, the
//! peer rule and the claims checks of [`crate::auth`].

use std::collections::BTreeSet;
use std::fmt::Display;
use std::sync::Arc;

use bytes::Bytes;
use dsu_core::api::{
    ApiError, DeployRequest, HealthBody, KeyWindow, ListEntry, ListResponse, MAX_BODY_BYTES,
};
use dsu_core::config::ServiceConfig;
use dsu_core::ids::{DeployId, Digest, ServiceName};
use dsu_core::record::{CallerRecord, Record, State};
use dsu_core::url::{ReleaseSpec, UrlError, check_bundle_url, check_image_url};
use dsu_docker::{DockerError, TaskView};
use http::StatusCode;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::Serialize;

use crate::app::{App, image_reference};
use crate::auth::Authenticated;
use crate::deployer::{Admission, Candidate};
use crate::runner::{self, Job};

/// A successful answer: its status and its JSON body (empty for 204).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: StatusCode,
    /// The body.
    pub body: Vec<u8>,
}

impl Reply {
    fn json(status: StatusCode, value: &impl Serialize) -> Result<Reply, ApiError> {
        let body = serde_json::to_vec(value).map_err(internal)?;
        Ok(Reply { status, body })
    }
}

fn internal(error: impl Display) -> ApiError {
    ApiError::Internal(error.to_string().replace('\n', " "))
}

fn unavailable(error: DockerError) -> ApiError {
    ApiError::Unavailable(format!("the Docker API: {error}").replace('\n', " "))
}

fn url_refused(error: UrlError) -> ApiError {
    ApiError::UrlNotAllowed(error.to_string().replace('\n', " "))
}

impl From<crate::store::StoreError> for ApiError {
    fn from(error: crate::store::StoreError) -> Self {
        internal(error)
    }
}

/// The body, at most [`MAX_BODY_BYTES`]; a longer one is 413 and is not read further.
async fn read_body(body: Incoming) -> Result<Bytes, ApiError> {
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) if e.is::<LengthLimitError>() => Err(ApiError::PayloadTooLarge(format!(
            "the request body is longer than {MAX_BODY_BYTES} bytes"
        ))),
        Err(e) => Err(ApiError::BadRequest(format!(
            "cannot read the request body: {e}"
        ))),
    }
}

/// The configured service `name`, when the request may act on it.
fn actionable<'a>(
    app: &'a App,
    auth: &Authenticated,
    name: &ServiceName,
) -> Result<&'a ServiceConfig, ApiError> {
    let service = app
        .service(name)
        .ok_or_else(|| ApiError::UnknownService(format!("no service {name} is configured")))?;
    if auth.may_act_on(service) {
        Ok(service)
    } else {
        Err(ApiError::NotAllowed(format!(
            "the caller may not act on service {name}"
        )))
    }
}

/// `POST /v1/services/{service}/deploys`, section 3.1 steps 2 to 4.
pub async fn deploy(
    app: &Arc<App>,
    auth: &Authenticated,
    name: &ServiceName,
    body: Incoming,
) -> Result<Reply, ApiError> {
    let service = actionable(app, auth, name)?;
    let request = DeployRequest::from_json(&read_body(body).await?)?;
    request.check_allow_older(auth.principal)?;
    request.check_signer(&service.signer)?;
    let spec = ReleaseSpec {
        owner: &service.artifact_url.owner,
        repo: &service.artifact_url.repo,
        artifact_name: &service.artifact_name,
    };
    let image_url = check_image_url(&request.image_url, &spec).map_err(url_refused)?;
    let bundle_url =
        check_bundle_url(&request.bundle_url, &spec, &image_url).map_err(url_refused)?;
    if let Some(record) = converged_and_running(app, service, &request.image_digest).await? {
        return Reply::json(StatusCode::OK, &record);
    }
    let candidate = Candidate {
        service,
        digest: &request.image_digest,
        version: &request.version,
        caller: auth
            .claims
            .as_ref()
            .map_or(CallerRecord::Operator, CallerRecord::from_claims),
        allow_older: request.allow_older,
    };
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(internal)?;
    let id = DeployId::from_random(id);
    match app
        .deployer
        .admit(&app.store, app.clock.as_ref(), id, candidate)
        .await?
    {
        Admission::Existing(record) => Reply::json(StatusCode::OK, &record),
        Admission::Started { record, permit } => {
            let reply = Reply::json(StatusCode::ACCEPTED, &record)?;
            let job = Job {
                record,
                service: service.clone(),
                image_url,
                bundle_url,
                permit,
            };
            runner::start(app, job);
            Ok(reply)
        }
    }
}

/// Section 3.1 step 3, the second case: the last record for the digest converged and Swarm
/// runs that image on every task.
async fn converged_and_running(
    app: &App,
    service: &ServiceConfig,
    digest: &Digest,
) -> Result<Option<Record>, ApiError> {
    let Some(record) = app
        .store
        .latest_for_digest(&service.name, digest)
        .await
        .filter(|r| r.state == State::Converged)
    else {
        return Ok(None);
    };
    let expected = image_reference(&app.config.registry, &service.repository, digest);
    let running = match app
        .swarm_tasks(&service.swarm_service)
        .await
        .map_err(unavailable)?
    {
        Some((_, tasks)) => !tasks.is_empty() && tasks.iter().all(|t| t.image == expected),
        None => false,
    };
    Ok(running.then_some(record))
}

/// `GET /v1/deploys/{id}`: the record, unless the request may not see its service.
pub async fn status(app: &App, auth: &Authenticated, id: &DeployId) -> Result<Reply, ApiError> {
    let record = app
        .store
        .record(id)
        .await
        .filter(|r| app.service(&r.service).is_some_and(|s| auth.may_act_on(s)))
        .ok_or_else(|| ApiError::UnknownDeploy(format!("no deploy {id}")))?;
    Reply::json(StatusCode::OK, &record)
}

/// The digests of the images `tasks` run, in digest order.
fn running_digests(tasks: &[TaskView]) -> Vec<Digest> {
    let digests: BTreeSet<Digest> = tasks
        .iter()
        .filter_map(|t| t.image.rsplit_once('@'))
        .filter_map(|(_, digest)| Digest::parse(digest).ok())
        .collect();
    digests.into_iter().collect()
}

async fn list_entry(app: &App, service: &ServiceConfig) -> Result<ListEntry, ApiError> {
    let state = app.store.service_state(&service.name).await;
    let last = app.store.last_record(&service.name).await;
    let swarm = app
        .swarm_tasks(&service.swarm_service)
        .await
        .map_err(unavailable)?;
    let (running_digests, update_state) = match swarm {
        Some((view, tasks)) => (running_digests(&tasks), view.update_status.map(|s| s.state)),
        None => (Vec::new(), None),
    };
    Ok(ListEntry {
        service: service.name.clone(),
        swarm_service: service.swarm_service.clone(),
        running_digests,
        update_state,
        last_deploy: last.map(|r| r.id),
        failed_digests: state.failed.into_iter().collect(),
        floor: state.floor,
    })
}

/// `GET /v1/services`: the services the request may act on, and the validity of the trusted
/// root's newest key.
pub async fn list(app: &App, auth: &Authenticated) -> Result<Reply, ApiError> {
    let services: Vec<&ServiceConfig> = app
        .config
        .services
        .iter()
        .filter(|s| auth.may_act_on(s))
        .collect();
    if services.is_empty() {
        return Err(ApiError::NotAllowed(
            "the caller may not act on any service".into(),
        ));
    }
    let mut entries = Vec::new();
    for service in services {
        entries.push(list_entry(app, service).await?);
    }
    Reply::json(
        StatusCode::OK,
        &ListResponse {
            services: entries,
            trusted_root_newest_key: app.roots.newest_key().map(|k| KeyWindow {
                from: k.from,
                until: k.until,
            }),
        },
    )
}

/// `DELETE /v1/services/{service}/failed/{digest}`: the local operator removes one digest
/// from the failed list.
pub async fn clear_failed(
    app: &App,
    auth: &Authenticated,
    name: &ServiceName,
    digest: &Digest,
) -> Result<Reply, ApiError> {
    if !auth.is_operator() {
        return Err(ApiError::NotAllowed(
            "only the local operator clears a failed digest".into(),
        ));
    }
    actionable(app, auth, name)?;
    if !app.store.service_state(name).await.is_failed(digest) {
        return Err(ApiError::NotFound(format!(
            "{digest} is not in the failed list of service {name}"
        )));
    }
    app.store
        .update_service(name, |state| state.clear_failed(digest))
        .await?;
    Ok(Reply {
        status: StatusCode::NO_CONTENT,
        body: Vec::new(),
    })
}

/// `GET /v1/health`: 200 when the state directory is writable and the Docker API answers,
/// else 503.
pub async fn health(app: &App) -> Result<Reply, ApiError> {
    app.store
        .check_writable()
        .await
        .map_err(|e| ApiError::Unavailable(format!("{e}").replace('\n', " ")))?;
    app.docker.ping().await.map_err(unavailable)?;
    Reply::json(StatusCode::OK, &HealthBody { ok: true })
}
