//! The deploy record (docs/design.md section 2.2) and its state machine: a record starts
//! `running` in phase `queued`, moves forward through the phases and ends in one final state.

use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::claims::Claims;
use crate::ids::{DeployId, Digest, ServiceName};

/// How the local operator is named in a record.
pub const OPERATOR_CALLER: &str = "operator (uid 0)";

/// The state of a deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Not finished.
    Running,
    /// Swarm completed the update and every task runs the new image.
    Converged,
    /// Swarm rolled the update back.
    RolledBack,
    /// The deploy ended with an error.
    Failed,
    /// Swarm paused the update: a person must look.
    Paused,
}

/// The phase a deploy is in. The order is the order of the declaration; `HandedOff` is the
/// self-update's stand-in for `Updating`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Accepted, not started.
    Queued,
    /// Downloading the tar and the bundle.
    Fetching,
    /// Verifying the bundle, the identity, the subject and the tar.
    Verifying,
    /// Pushing blobs and the manifest to the registry.
    Pushing,
    /// Self-update: the record is written, then Swarm is asked to replace this task.
    HandedOff,
    /// Asking Swarm for the update.
    Updating,
    /// Waiting for Swarm to settle the update.
    Waiting,
    /// Finished.
    Done,
}

/// One entry of a record's `steps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The phase the step covers.
    pub phase: Phase,
    /// When it began.
    pub started: Timestamp,
    /// When it ended; absent while it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<Timestamp>,
    /// What it did, for a person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The error tokens of a record (section 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorToken {
    /// An HTTP error, a short body, a timeout, a full disk.
    FetchFailed,
    /// A redirect to a forbidden host, scheme or address, or too many hops.
    UrlNotAllowed,
    /// The tar is over `max_image_bytes`.
    TooLarge,
    /// The tar is not the OCI layout the deploy accepts.
    TarInvalid,
    /// The tar's manifest is not `image_digest`.
    DigestMismatch,
    /// Not a parseable Sigstore bundle.
    BundleInvalid,
    /// The bundle does not attest the tar's SHA-256 under `artifact_name`.
    BundleSubject,
    /// An identity check of section 3.3 step 2.
    BundleSigner,
    /// The chain, the log entry or the timestamp does not verify.
    BundleChain,
    /// Signed earlier than the running release.
    OlderThanRunning,
    /// The image is for another platform.
    PlatformMismatch,
    /// The registry push failed.
    RegistryFailed,
    /// Swarm refused the update.
    SwarmRefused,
    /// Swarm rolled the update back.
    SwarmRolledBack,
    /// Swarm paused the update.
    SwarmPaused,
    /// `converge_timeout_secs` passed.
    Timeout,
    /// The updater restarted and the deploy cannot be continued.
    Interrupted,
}

impl ErrorToken {
    /// The token as it appears in the record.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorToken::FetchFailed => "fetch_failed",
            ErrorToken::UrlNotAllowed => "url_not_allowed",
            ErrorToken::TooLarge => "too_large",
            ErrorToken::TarInvalid => "tar_invalid",
            ErrorToken::DigestMismatch => "digest_mismatch",
            ErrorToken::BundleInvalid => "bundle_invalid",
            ErrorToken::BundleSubject => "bundle_subject",
            ErrorToken::BundleSigner => "bundle_signer",
            ErrorToken::BundleChain => "bundle_chain",
            ErrorToken::OlderThanRunning => "older_than_running",
            ErrorToken::PlatformMismatch => "platform_mismatch",
            ErrorToken::RegistryFailed => "registry_failed",
            ErrorToken::SwarmRefused => "swarm_refused",
            ErrorToken::SwarmRolledBack => "swarm_rolled_back",
            ErrorToken::SwarmPaused => "swarm_paused",
            ErrorToken::Timeout => "timeout",
            ErrorToken::Interrupted => "interrupted",
        }
    }

    /// The final state a deploy ends in with this error: `rolled_back` and `paused` for
    /// Swarm's two outcomes, `failed` for the rest.
    pub fn final_state(self) -> State {
        match self {
            ErrorToken::SwarmRolledBack => State::RolledBack,
            ErrorToken::SwarmPaused => State::Paused,
            _ => State::Failed,
        }
    }

    /// Whether this error is about Swarm's update, which no phase before the hand-off or the
    /// update can produce.
    fn needs_swarm_phase(self) -> bool {
        matches!(
            self,
            ErrorToken::SwarmRolledBack | ErrorToken::SwarmPaused | ErrorToken::Timeout
        )
    }
}

/// Section 3.3: whether a failed deploy adds its digest to the service's failed list.
/// `digest_bound` is true when the failure came after `index.json`'s manifest digest matched
/// `image_digest`. `older_than_running` never enters it (the operator's retry must run), a
/// rollback always does, and the verification and tar failures only when bound.
pub fn enters_failed_list(token: ErrorToken, digest_bound: bool) -> bool {
    match token {
        ErrorToken::SwarmRolledBack => true,
        ErrorToken::BundleInvalid
        | ErrorToken::BundleSubject
        | ErrorToken::BundleSigner
        | ErrorToken::BundleChain
        | ErrorToken::TarInvalid
        | ErrorToken::PlatformMismatch => digest_bound,
        ErrorToken::FetchFailed
        | ErrorToken::UrlNotAllowed
        | ErrorToken::TooLarge
        | ErrorToken::DigestMismatch
        | ErrorToken::OlderThanRunning
        | ErrorToken::RegistryFailed
        | ErrorToken::SwarmRefused
        | ErrorToken::SwarmPaused
        | ErrorToken::Timeout
        | ErrorToken::Interrupted => false,
    }
}

/// The `error` object of a failed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordError {
    /// The token.
    pub token: ErrorToken,
    /// One line for a person.
    pub detail: String,
}

/// The claims of a caller worth keeping in a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowCaller {
    /// The `repository` claim.
    pub repository: String,
    /// The `job_workflow_ref` claim.
    pub job_workflow_ref: String,
    /// The `ref` claim.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The `environment` claim.
    pub environment: String,
    /// The `run_id` claim.
    pub run_id: String,
}

/// Who asked for a deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerRecord {
    /// The local operator; rendered as the string `operator (uid 0)`.
    Operator,
    /// A caller named by its claims; rendered as an object.
    Workflow(WorkflowCaller),
}

impl CallerRecord {
    /// The caller a request's claims name.
    pub fn from_claims(claims: &Claims) -> CallerRecord {
        CallerRecord::Workflow(WorkflowCaller {
            repository: claims.repository.clone(),
            job_workflow_ref: claims.job_workflow_ref.clone(),
            git_ref: claims.git_ref.clone(),
            environment: claims.environment.clone(),
            run_id: claims.run_id.clone(),
        })
    }
}

impl Serialize for CallerRecord {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            CallerRecord::Operator => s.serialize_str(OPERATOR_CALLER),
            CallerRecord::Workflow(w) => w.serialize(s),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CallerWire {
    Text(String),
    Fields(WorkflowCaller),
}

impl<'de> Deserialize<'de> for CallerRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match CallerWire::deserialize(d)? {
            CallerWire::Text(t) if t == OPERATOR_CALLER => Ok(CallerRecord::Operator),
            CallerWire::Text(t) => Err(serde::de::Error::custom(format!("unknown caller {t:?}"))),
            CallerWire::Fields(w) => Ok(CallerRecord::Workflow(w)),
        }
    }
}

/// A transition the state machine refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The record already ended.
    #[error("deploy {id} already ended as {state:?}")]
    Finished {
        /// The record.
        id: DeployId,
        /// Its final state.
        state: State,
    },
    /// Phases only move forward.
    #[error("deploy {id} cannot move from phase {from:?} to {to:?}")]
    NotForward {
        /// The record.
        id: DeployId,
        /// The current phase.
        from: Phase,
        /// The refused phase.
        to: Phase,
    },
    /// `done` is reached by finishing the record, not by entering it.
    #[error("deploy {id}: phase done is reached by finishing")]
    DonePhase {
        /// The record.
        id: DeployId,
    },
    /// The outcome needs the update to have started.
    #[error("deploy {id} is in phase {phase:?}, before Swarm was asked to update")]
    BeforeSwarm {
        /// The record.
        id: DeployId,
        /// The current phase.
        phase: Phase,
    },
    /// There is no step to annotate yet.
    #[error("deploy {id} has no step yet")]
    NoStep {
        /// The record.
        id: DeployId,
    },
}

/// A deploy record (`deploys/<id>.json`, the answer of `GET /v1/deploys/{id}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The deploy id.
    pub id: DeployId,
    /// The configured service.
    pub service: ServiceName,
    /// The Swarm service it updates.
    pub swarm_service: String,
    /// The digest asked for.
    pub image_digest: Digest,
    /// The caller's `version` text.
    pub version: String,
    /// The bundle's verified signing time; absent until verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_time: Option<Timestamp>,
    /// Who asked.
    pub caller: CallerRecord,
    /// True when the operator asked to accept a release older than the running one.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_older: bool,
    /// The state.
    pub state: State,
    /// The phase.
    pub phase: Phase,
    /// The phases gone through, in order.
    pub steps: Vec<Step>,
    /// Why it failed; absent on `running` and `converged`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RecordError>,
    /// When the request was accepted.
    pub started: Timestamp,
    /// When it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<Timestamp>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What a new record is made of.
#[derive(Debug, Clone)]
pub struct NewRecord {
    /// The deploy id.
    pub id: DeployId,
    /// The configured service.
    pub service: ServiceName,
    /// The Swarm service it updates.
    pub swarm_service: String,
    /// The digest asked for.
    pub image_digest: Digest,
    /// The caller's `version` text.
    pub version: String,
    /// Who asked.
    pub caller: CallerRecord,
    /// The operator's `allow_older`.
    pub allow_older: bool,
    /// The time of the request.
    pub now: Timestamp,
}

impl Record {
    /// A record in state `running`, phase `queued`, with no steps.
    pub fn start(new: NewRecord) -> Record {
        Record {
            id: new.id,
            service: new.service,
            swarm_service: new.swarm_service,
            image_digest: new.image_digest,
            version: new.version,
            signed_time: None,
            caller: new.caller,
            allow_older: new.allow_older,
            state: State::Running,
            phase: Phase::Queued,
            steps: Vec::new(),
            error: None,
            started: new.now,
            ended: None,
        }
    }

    fn ensure_running(&self) -> Result<(), TransitionError> {
        match self.state {
            State::Running => Ok(()),
            state => Err(TransitionError::Finished {
                id: self.id.clone(),
                state,
            }),
        }
    }

    fn ensure_swarm_phase(&self) -> Result<(), TransitionError> {
        if self.phase >= Phase::HandedOff {
            Ok(())
        } else {
            Err(TransitionError::BeforeSwarm {
                id: self.id.clone(),
                phase: self.phase,
            })
        }
    }

    fn close_open_step(&mut self, now: Timestamp) {
        if let Some(step) = self.steps.last_mut() {
            step.ended.get_or_insert(now);
        }
    }

    /// Moves a running record to a later phase (not `done`), ending the step in progress and
    /// beginning one for `phase`.
    pub fn enter_phase(&mut self, phase: Phase, now: Timestamp) -> Result<(), TransitionError> {
        self.ensure_running()?;
        if phase == Phase::Done {
            return Err(TransitionError::DonePhase {
                id: self.id.clone(),
            });
        }
        if phase <= self.phase {
            return Err(TransitionError::NotForward {
                id: self.id.clone(),
                from: self.phase,
                to: phase,
            });
        }
        self.close_open_step(now);
        self.steps.push(Step {
            phase,
            started: now,
            ended: None,
            note: None,
        });
        self.phase = phase;
        Ok(())
    }

    /// Sets the note of the latest step.
    pub fn annotate(&mut self, note: impl Into<String>) -> Result<(), TransitionError> {
        self.ensure_running()?;
        match self.steps.last_mut() {
            Some(step) => {
                step.note = Some(note.into());
                Ok(())
            }
            None => Err(TransitionError::NoStep {
                id: self.id.clone(),
            }),
        }
    }

    /// Records the bundle's verified signing time.
    pub fn set_signed_time(&mut self, signed_time: Timestamp) -> Result<(), TransitionError> {
        self.ensure_running()?;
        self.signed_time = Some(signed_time);
        Ok(())
    }

    /// Ends the record as `converged`; only once Swarm was asked to update.
    pub fn finish_converged(&mut self, now: Timestamp) -> Result<(), TransitionError> {
        self.ensure_running()?;
        self.ensure_swarm_phase()?;
        self.finish(State::Converged, None, now);
        Ok(())
    }

    /// Ends the record with an error: the state is `token.final_state()`. Swarm's outcomes
    /// (`swarm_rolled_back`, `swarm_paused`, `timeout`) need the update to have started.
    pub fn finish_failed(
        &mut self,
        token: ErrorToken,
        detail: impl Into<String>,
        now: Timestamp,
    ) -> Result<(), TransitionError> {
        self.ensure_running()?;
        if token.needs_swarm_phase() {
            self.ensure_swarm_phase()?;
        }
        self.finish(
            token.final_state(),
            Some(RecordError {
                token,
                detail: detail.into(),
            }),
            now,
        );
        Ok(())
    }

    fn finish(&mut self, state: State, error: Option<RecordError>, now: Timestamp) {
        self.close_open_step(now);
        self.state = state;
        self.phase = Phase::Done;
        self.error = error;
        self.ended = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_790_000_000 + secs).unwrap()
    }

    fn new_record(caller: CallerRecord) -> Record {
        Record::start(NewRecord {
            id: DeployId::parse("d-abcdefghijklmnopqrstuvwxyz").unwrap(),
            service: ServiceName::parse("app").unwrap(),
            swarm_service: "app_server".into(),
            image_digest: Digest::from_sha256([7; 32]),
            version: "1.4.2".into(),
            caller,
            allow_older: false,
            now: t(0),
        })
    }

    fn workflow() -> CallerRecord {
        CallerRecord::Workflow(WorkflowCaller {
            repository: "example-org/app".into(),
            job_workflow_ref: "example-org/dsu/.github/workflows/deploy.yml@abc".into(),
            git_ref: "refs/heads/main".into(),
            environment: "production".into(),
            run_id: "77".into(),
        })
    }

    #[test]
    fn a_new_record_is_running_and_queued() {
        let r = new_record(workflow());
        assert_eq!((r.state, r.phase), (State::Running, Phase::Queued));
        assert!(r.steps.is_empty());
        assert!(r.error.is_none());
        assert!(r.ended.is_none());
        assert!(r.signed_time.is_none());
        assert_eq!(r.started, t(0));
    }

    #[test]
    fn happy_path_records_a_closed_step_per_phase() {
        let mut r = new_record(workflow());
        r.enter_phase(Phase::Fetching, t(1)).unwrap();
        r.annotate("image 812 MiB").unwrap();
        r.enter_phase(Phase::Verifying, t(2)).unwrap();
        r.set_signed_time(t(-100)).unwrap();
        r.enter_phase(Phase::Pushing, t(3)).unwrap();
        r.enter_phase(Phase::Updating, t(4)).unwrap();
        r.enter_phase(Phase::Waiting, t(5)).unwrap();
        r.annotate("2 of 2 tasks running").unwrap();
        r.finish_converged(t(9)).unwrap();
        assert_eq!(
            (r.state, r.phase, r.ended),
            (State::Converged, Phase::Done, Some(t(9)))
        );
        assert!(r.error.is_none());
        assert_eq!(r.signed_time, Some(t(-100)));
        let phases: Vec<Phase> = r.steps.iter().map(|s| s.phase).collect();
        assert_eq!(
            phases,
            [
                Phase::Fetching,
                Phase::Verifying,
                Phase::Pushing,
                Phase::Updating,
                Phase::Waiting
            ]
        );
        assert!(r.steps.iter().all(|s| s.ended.is_some()));
        assert_eq!(r.steps[0].note.as_deref(), Some("image 812 MiB"));
        assert_eq!((r.steps[0].started, r.steps[0].ended), (t(1), Some(t(2))));
        assert_eq!(r.steps[4].ended, Some(t(9)));
    }

    #[test]
    fn phases_only_move_forward() {
        let mut r = new_record(workflow());
        r.enter_phase(Phase::Verifying, t(1)).unwrap();
        for back in [Phase::Queued, Phase::Fetching, Phase::Verifying] {
            let err = r.enter_phase(back, t(2)).unwrap_err();
            assert_eq!(
                err,
                TransitionError::NotForward {
                    id: r.id.clone(),
                    from: Phase::Verifying,
                    to: back
                }
            );
            assert!(err.to_string().contains("cannot move"));
        }
        assert!(matches!(
            r.enter_phase(Phase::Done, t(2)),
            Err(TransitionError::DonePhase { .. })
        ));
        assert_eq!(r.phase, Phase::Verifying);
        assert_eq!(r.steps.len(), 1);
    }

    #[test]
    fn self_update_goes_through_handed_off_and_can_resume_waiting() {
        let mut r = new_record(workflow());
        r.enter_phase(Phase::Pushing, t(1)).unwrap();
        r.enter_phase(Phase::HandedOff, t(2)).unwrap();
        r.enter_phase(Phase::Waiting, t(3)).unwrap();
        r.finish_converged(t(4)).unwrap();
        assert_eq!(r.state, State::Converged);
        let mut direct = new_record(workflow());
        direct.enter_phase(Phase::HandedOff, t(1)).unwrap();
        direct.enter_phase(Phase::Updating, t(2)).unwrap();
    }

    #[test]
    fn converged_needs_the_update_to_have_started() {
        let mut r = new_record(workflow());
        assert!(matches!(
            r.finish_converged(t(1)),
            Err(TransitionError::BeforeSwarm {
                phase: Phase::Queued,
                ..
            })
        ));
        r.enter_phase(Phase::Pushing, t(1)).unwrap();
        let err = r.finish_converged(t(2)).unwrap_err();
        assert!(err.to_string().contains("before Swarm"));
        assert_eq!(r.state, State::Running);
        r.enter_phase(Phase::HandedOff, t(3)).unwrap();
        r.finish_converged(t(4)).unwrap();
    }

    #[test]
    fn failures_end_in_the_state_of_their_token() {
        let cases = [
            (ErrorToken::SwarmRolledBack, State::RolledBack),
            (ErrorToken::SwarmPaused, State::Paused),
            (ErrorToken::Timeout, State::Failed),
            (ErrorToken::SwarmRefused, State::Failed),
            (ErrorToken::Interrupted, State::Failed),
        ];
        for (token, state) in cases {
            let mut r = new_record(workflow());
            r.enter_phase(Phase::Waiting, t(1)).unwrap();
            r.finish_failed(token, "why", t(2)).unwrap();
            assert_eq!(r.state, state);
            assert_eq!(r.phase, Phase::Done);
            assert_eq!(
                r.error,
                Some(RecordError {
                    token,
                    detail: "why".into()
                })
            );
            assert_eq!(r.ended, Some(t(2)));
            assert_eq!(r.steps[0].ended, Some(t(2)));
        }
    }

    #[test]
    fn early_failures_need_no_steps_and_swarm_outcomes_need_the_update() {
        let mut r = new_record(workflow());
        r.finish_failed(ErrorToken::Interrupted, "restart", t(1))
            .unwrap();
        assert_eq!(r.state, State::Failed);
        assert!(r.steps.is_empty());

        for token in [
            ErrorToken::SwarmRolledBack,
            ErrorToken::SwarmPaused,
            ErrorToken::Timeout,
        ] {
            let mut r = new_record(workflow());
            r.enter_phase(Phase::Pushing, t(1)).unwrap();
            assert!(matches!(
                r.finish_failed(token, "x", t(2)),
                Err(TransitionError::BeforeSwarm { .. })
            ));
            assert_eq!(r.state, State::Running);
        }
        let mut r = new_record(workflow());
        r.enter_phase(Phase::Fetching, t(1)).unwrap();
        r.finish_failed(ErrorToken::FetchFailed, "404", t(2))
            .unwrap();
    }

    #[test]
    fn a_finished_record_changes_no_more() {
        let mut r = new_record(workflow());
        r.finish_failed(ErrorToken::FetchFailed, "x", t(1)).unwrap();
        let before = r.clone();
        assert!(matches!(
            r.enter_phase(Phase::Fetching, t(2)),
            Err(TransitionError::Finished {
                state: State::Failed,
                ..
            })
        ));
        assert!(matches!(
            r.annotate("n"),
            Err(TransitionError::Finished { .. })
        ));
        assert!(matches!(
            r.set_signed_time(t(2)),
            Err(TransitionError::Finished { .. })
        ));
        assert!(matches!(
            r.finish_converged(t(2)),
            Err(TransitionError::Finished { .. })
        ));
        let err = r
            .finish_failed(ErrorToken::Interrupted, "y", t(2))
            .unwrap_err();
        assert!(err.to_string().contains("already ended"));
        assert_eq!(r, before);
    }

    #[test]
    fn annotate_needs_a_step() {
        let mut r = new_record(workflow());
        let err = r.annotate("n").unwrap_err();
        assert!(matches!(err, TransitionError::NoStep { .. }));
        assert!(err.to_string().contains("no step"));
    }

    #[test]
    fn json_has_the_documented_shape() {
        let mut r = new_record(workflow());
        r.enter_phase(Phase::Fetching, t(1)).unwrap();
        r.annotate("n").unwrap();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["id"], "d-abcdefghijklmnopqrstuvwxyz");
        assert_eq!(json["service"], "app");
        assert_eq!(json["swarm_service"], "app_server");
        assert_eq!(json["state"], "running");
        assert_eq!(json["phase"], "fetching");
        assert_eq!(json["caller"]["ref"], "refs/heads/main");
        assert_eq!(json["caller"]["run_id"], "77");
        assert_eq!(json["steps"][0]["phase"], "fetching");
        assert_eq!(json["steps"][0]["note"], "n");
        assert!(json["steps"][0].get("ended").is_none());
        assert_eq!(json["started"], t(0).to_string());
        for absent in ["signed_time", "error", "ended", "allow_older"] {
            assert!(json.get(absent).is_none(), "{absent}");
        }
        assert_eq!(serde_json::from_value::<Record>(json).unwrap(), r);
    }

    #[test]
    fn a_failed_record_round_trips_with_error_and_operator_caller() {
        let mut r = Record::start(NewRecord {
            allow_older: true,
            ..new_record_input(CallerRecord::Operator)
        });
        r.enter_phase(Phase::Verifying, t(1)).unwrap();
        r.set_signed_time(t(-5)).unwrap();
        r.finish_failed(ErrorToken::BundleSigner, "workflow differs", t(2))
            .unwrap();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["caller"], "operator (uid 0)");
        assert_eq!(json["allow_older"], true);
        assert_eq!(json["error"]["token"], "bundle_signer");
        assert_eq!(json["error"]["detail"], "workflow differs");
        assert_eq!(json["state"], "failed");
        assert_eq!(json["phase"], "done");
        assert_eq!(json["signed_time"], t(-5).to_string());
        assert_eq!(serde_json::from_value::<Record>(json).unwrap(), r);
    }

    fn new_record_input(caller: CallerRecord) -> NewRecord {
        NewRecord {
            id: DeployId::parse("d-abcdefghijklmnopqrstuvwxyz").unwrap(),
            service: ServiceName::parse("app").unwrap(),
            swarm_service: "app_server".into(),
            image_digest: Digest::from_sha256([7; 32]),
            version: "1.4.2".into(),
            caller,
            allow_older: false,
            now: t(0),
        }
    }

    #[test]
    fn caller_record_parses_both_forms_and_refuses_other_text() {
        assert_eq!(
            serde_json::from_str::<CallerRecord>(r#""operator (uid 0)""#).unwrap(),
            CallerRecord::Operator
        );
        let err = serde_json::from_str::<CallerRecord>(r#""root""#).unwrap_err();
        assert!(err.to_string().contains("unknown caller"));
        assert!(serde_json::from_str::<CallerRecord>("5").is_err());
        let w = serde_json::to_string(&workflow()).unwrap();
        assert_eq!(
            serde_json::from_str::<CallerRecord>(&w).unwrap(),
            workflow()
        );
    }

    #[test]
    fn caller_record_from_claims_keeps_the_five_fields() {
        let payload = r#"{"repository":"example-org/app","repository_id":"1","job_workflow_ref":"w@1","ref":"refs/heads/main","environment":"production","runner_environment":"github-hosted","run_id":"77","jti":"j","exp":1}"#;
        let header = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        };
        let claims = Claims::from_header(&header).unwrap();
        assert_eq!(
            CallerRecord::from_claims(&claims),
            CallerRecord::Workflow(WorkflowCaller {
                repository: "example-org/app".into(),
                job_workflow_ref: "w@1".into(),
                git_ref: "refs/heads/main".into(),
                environment: "production".into(),
                run_id: "77".into(),
            })
        );
    }

    const ALL_TOKENS: [ErrorToken; 17] = [
        ErrorToken::FetchFailed,
        ErrorToken::UrlNotAllowed,
        ErrorToken::TooLarge,
        ErrorToken::TarInvalid,
        ErrorToken::DigestMismatch,
        ErrorToken::BundleInvalid,
        ErrorToken::BundleSubject,
        ErrorToken::BundleSigner,
        ErrorToken::BundleChain,
        ErrorToken::OlderThanRunning,
        ErrorToken::PlatformMismatch,
        ErrorToken::RegistryFailed,
        ErrorToken::SwarmRefused,
        ErrorToken::SwarmRolledBack,
        ErrorToken::SwarmPaused,
        ErrorToken::Timeout,
        ErrorToken::Interrupted,
    ];

    #[test]
    fn token_text_is_the_serde_name_and_the_design_list() {
        let design = [
            "fetch_failed",
            "url_not_allowed",
            "too_large",
            "tar_invalid",
            "digest_mismatch",
            "bundle_invalid",
            "bundle_subject",
            "bundle_signer",
            "bundle_chain",
            "older_than_running",
            "platform_mismatch",
            "registry_failed",
            "swarm_refused",
            "swarm_rolled_back",
            "swarm_paused",
            "timeout",
            "interrupted",
        ];
        for (token, name) in ALL_TOKENS.into_iter().zip(design) {
            assert_eq!(token.as_str(), name);
            assert_eq!(
                serde_json::to_string(&token).unwrap(),
                format!("\"{name}\"")
            );
            assert_eq!(
                serde_json::from_str::<ErrorToken>(&format!("\"{name}\"")).unwrap(),
                token
            );
        }
    }

    #[test]
    fn failed_list_rule() {
        let bound_only = [
            ErrorToken::BundleInvalid,
            ErrorToken::BundleSubject,
            ErrorToken::BundleSigner,
            ErrorToken::BundleChain,
            ErrorToken::TarInvalid,
            ErrorToken::PlatformMismatch,
        ];
        let never = [
            ErrorToken::FetchFailed,
            ErrorToken::UrlNotAllowed,
            ErrorToken::TooLarge,
            ErrorToken::DigestMismatch,
            ErrorToken::OlderThanRunning,
            ErrorToken::RegistryFailed,
            ErrorToken::SwarmRefused,
            ErrorToken::SwarmPaused,
            ErrorToken::Timeout,
            ErrorToken::Interrupted,
        ];
        for token in bound_only {
            assert!(enters_failed_list(token, true), "{token:?}");
            assert!(!enters_failed_list(token, false), "{token:?}");
        }
        for token in never {
            assert!(!enters_failed_list(token, true), "{token:?}");
            assert!(!enters_failed_list(token, false), "{token:?}");
        }
        assert!(enters_failed_list(ErrorToken::SwarmRolledBack, true));
        assert!(enters_failed_list(ErrorToken::SwarmRolledBack, false));
        assert_eq!(bound_only.len() + never.len() + 1, ALL_TOKENS.len());
    }

    #[test]
    fn states_and_phases_serialize_in_snake_case() {
        assert_eq!(
            serde_json::to_string(&State::RolledBack).unwrap(),
            r#""rolled_back""#
        );
        assert_eq!(
            serde_json::to_string(&Phase::HandedOff).unwrap(),
            r#""handed_off""#
        );
        let order = [
            Phase::Queued,
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::HandedOff,
            Phase::Updating,
            Phase::Waiting,
            Phase::Done,
        ];
        assert!(order.is_sorted());
    }
}
