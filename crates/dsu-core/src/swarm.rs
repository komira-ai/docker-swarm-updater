//! The Swarm `UpdateStatus` rule (docs/design.md section 3.5 step 3) and the restart rule
//! built on it (section 3.6), as pure functions of what was read from the Docker API.

use jiff::Timestamp;

use crate::ids::DeployId;
use crate::record::Phase;
use crate::state::Pending;

/// What was read from Swarm just before the update was asked for (section 3.5 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The service's `Version.Index`.
    pub version_index: u64,
    /// When the service was read.
    pub read_at: Timestamp,
}

/// The service's `UpdateStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStatus {
    /// `State`: `updating`, `completed`, `paused`, `rollback_started`, `rollback_completed`,
    /// `rollback_paused`.
    pub state: String,
    /// `StartedAt`, if Swarm set it.
    pub started_at: Option<Timestamp>,
}

/// The service as read from Swarm while waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    /// `Version.Index`.
    pub version_index: u64,
    /// `UpdateStatus`, if the service has one.
    pub update_status: Option<UpdateStatus>,
    /// `Spec.TaskTemplate.ContainerSpec.Image`.
    pub image: String,
    /// The service label `org.docker-swarm-updater.deploy`, if set.
    pub deploy_label: Option<String>,
}

/// What the rule says about a deploy waiting on Swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Keep polling.
    Waiting,
    /// The update completed and every running task runs the new image.
    Converged,
    /// Swarm rolled the update back.
    RolledBack,
    /// Swarm paused the update (or its rollback): a person must look.
    Paused,
    /// The service's spec is not explained by this deploy: nothing says its update ran, and
    /// the service is not carrying its label (or another image replaced the new one).
    Interrupted,
}

/// Applies the rule of section 3.5 step 3.
///
/// An `UpdateStatus` counts only once it belongs to this update: the service's
/// `Version.Index` is past the snapshot's and `StartedAt` is later than the snapshot's read
/// time; a terminal state left by an earlier update is ignored. Then `completed` with every
/// running task on `expected_image` is `Converged`, `rollback_completed` is `RolledBack`,
/// `paused` and `rollback_paused` are `Paused`, and any other state keeps `Waiting`. Without
/// a status of this update the verdict is `Waiting` while the service carries `deploy`'s
/// label and `Interrupted` otherwise.
pub fn judge(
    snapshot: &Snapshot,
    view: &ServiceView,
    running_task_images: &[String],
    expected_image: &str,
    deploy: &DeployId,
) -> Verdict {
    let belongs = |status: &&UpdateStatus| {
        view.version_index > snapshot.version_index
            && status.started_at.is_some_and(|at| at > snapshot.read_at)
    };
    let Some(status) = view.update_status.as_ref().filter(belongs) else {
        return if view.deploy_label.as_deref() == Some(deploy.as_str()) {
            Verdict::Waiting
        } else {
            Verdict::Interrupted
        };
    };
    match status.state.as_str() {
        "completed" if view.image != expected_image => Verdict::Interrupted,
        "completed"
            if running_task_images
                .iter()
                .all(|image| image == expected_image) =>
        {
            Verdict::Converged
        }
        "rollback_completed" => Verdict::RolledBack,
        "paused" | "rollback_paused" => Verdict::Paused,
        _ => Verdict::Waiting,
    }
}

/// What a restarted updater does with a record still in state `running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartAction {
    /// End the record `failed` with `interrupted`.
    FailInterrupted,
    /// End the record `converged`.
    Converged,
    /// End the record `rolled_back`.
    RolledBack,
    /// End the record `paused`.
    Paused,
    /// Go on waiting for Swarm.
    ResumeWait,
}

/// The restart rule of section 3.6. In the phases `queued` to `pushing` nothing in Swarm
/// changed: the deploy is interrupted. From `handed_off` on, the kept snapshot (`pending`,
/// which must be this `deploy`'s) lets [`judge`] decide; without it the deploy is interrupted.
pub fn restart_action(
    phase: Phase,
    pending: Option<&Pending>,
    view: &ServiceView,
    running_task_images: &[String],
    expected_image: &str,
    deploy: &DeployId,
) -> RestartAction {
    let Some(pending) = pending.filter(|p| &p.deploy == deploy && phase >= Phase::HandedOff) else {
        return RestartAction::FailInterrupted;
    };
    match judge(
        &pending.snapshot(),
        view,
        running_task_images,
        expected_image,
        deploy,
    ) {
        Verdict::Waiting => RestartAction::ResumeWait,
        Verdict::Converged => RestartAction::Converged,
        Verdict::RolledBack => RestartAction::RolledBack,
        Verdict::Paused => RestartAction::Paused,
        Verdict::Interrupted => RestartAction::FailInterrupted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEW: &str = "127.0.0.1:5000/app@sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OLD: &str = "127.0.0.1:5000/app@sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_790_000_000 + secs).unwrap()
    }

    fn deploy() -> DeployId {
        DeployId::parse("d-abcdefghijklmnopqrstuvwxyz").unwrap()
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            version_index: 10,
            read_at: t(100),
        }
    }

    fn view(
        index: u64,
        state: Option<(&str, Option<i64>)>,
        image: &str,
        label: Option<&str>,
    ) -> ServiceView {
        ServiceView {
            version_index: index,
            update_status: state.map(|(s, at)| UpdateStatus {
                state: s.into(),
                started_at: at.map(t),
            }),
            image: image.into(),
            deploy_label: label.map(Into::into),
        }
    }

    fn judged(v: &ServiceView, tasks: &[&str]) -> Verdict {
        let tasks: Vec<String> = tasks.iter().map(|s| (*s).to_owned()).collect();
        judge(&snapshot(), v, &tasks, NEW, &deploy())
    }

    const OURS: Option<&str> = Some("d-abcdefghijklmnopqrstuvwxyz");

    #[test]
    fn states_of_this_update() {
        let at = Some(101);
        let cases = [
            ("updating", &[OLD, NEW][..], Verdict::Waiting),
            ("rollback_started", &[OLD][..], Verdict::Waiting),
            ("something_new", &[NEW][..], Verdict::Waiting),
            ("completed", &[NEW, NEW][..], Verdict::Converged),
            ("completed", &[][..], Verdict::Converged),
            ("completed", &[NEW, OLD][..], Verdict::Waiting),
            ("completed", &[OLD][..], Verdict::Waiting),
            ("rollback_completed", &[OLD][..], Verdict::RolledBack),
            ("paused", &[OLD][..], Verdict::Paused),
            ("rollback_paused", &[OLD][..], Verdict::Paused),
        ];
        for (state, tasks, want) in cases {
            let v = view(11, Some((state, at)), NEW, OURS);
            assert_eq!(judged(&v, tasks), want, "{state} {tasks:?}");
        }
    }

    #[test]
    fn a_status_of_an_earlier_update_is_ignored() {
        // Index not past the snapshot's.
        let v = view(10, Some(("rollback_completed", Some(101))), OLD, OURS);
        assert_eq!(judged(&v, &[OLD]), Verdict::Waiting);
        // Started at or before the read time.
        for at in [100, 50] {
            let v = view(11, Some(("completed", Some(at))), NEW, OURS);
            assert_eq!(judged(&v, &[NEW]), Verdict::Waiting);
        }
        // No start time.
        let v = view(11, Some(("completed", None)), NEW, OURS);
        assert_eq!(judged(&v, &[NEW]), Verdict::Waiting);
        // Both stale and the service is not carrying our label.
        let v = view(10, Some(("completed", Some(50))), OLD, Some("d-other"));
        assert_eq!(judged(&v, &[OLD]), Verdict::Interrupted);
    }

    #[test]
    fn no_status_waits_only_while_the_service_carries_our_label() {
        assert_eq!(judged(&view(11, None, NEW, OURS), &[OLD]), Verdict::Waiting);
        assert_eq!(
            judged(&view(10, None, OLD, None), &[OLD]),
            Verdict::Interrupted
        );
        assert_eq!(
            judged(&view(12, None, OLD, Some("d-other")), &[OLD]),
            Verdict::Interrupted
        );
    }

    #[test]
    fn a_completed_update_of_another_image_is_not_ours() {
        let v = view(11, Some(("completed", Some(101))), OLD, OURS);
        assert_eq!(judged(&v, &[OLD]), Verdict::Interrupted);
    }

    fn pending() -> Pending {
        Pending {
            deploy: deploy(),
            version_index: 10,
            read_at: t(100),
        }
    }

    fn restart(
        phase: Phase,
        pending: Option<&Pending>,
        v: &ServiceView,
        tasks: &[&str],
    ) -> RestartAction {
        let tasks: Vec<String> = tasks.iter().map(|s| (*s).to_owned()).collect();
        restart_action(phase, pending, v, &tasks, NEW, &deploy())
    }

    #[test]
    fn restart_before_the_update_is_interrupted_whatever_swarm_says() {
        let p = pending();
        let done = view(11, Some(("completed", Some(101))), NEW, OURS);
        for phase in [
            Phase::Queued,
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
        ] {
            assert_eq!(
                restart(phase, Some(&p), &done, &[NEW]),
                RestartAction::FailInterrupted,
                "{phase:?}"
            );
        }
    }

    #[test]
    fn restart_after_the_hand_off_applies_the_rule() {
        let p = pending();
        let cases = [
            (
                view(11, Some(("completed", Some(101))), NEW, OURS),
                &[NEW][..],
                RestartAction::Converged,
            ),
            (
                view(11, Some(("rollback_completed", Some(101))), OLD, None),
                &[OLD][..],
                RestartAction::RolledBack,
            ),
            (
                view(11, Some(("paused", Some(101))), NEW, OURS),
                &[OLD][..],
                RestartAction::Paused,
            ),
            (
                view(11, Some(("updating", Some(101))), NEW, OURS),
                &[OLD][..],
                RestartAction::ResumeWait,
            ),
            (
                view(10, None, OLD, Some("d-other")),
                &[OLD][..],
                RestartAction::FailInterrupted,
            ),
        ];
        for phase in [Phase::HandedOff, Phase::Updating, Phase::Waiting] {
            for (v, tasks, want) in &cases {
                assert_eq!(restart(phase, Some(&p), v, tasks), *want, "{phase:?} {v:?}");
            }
        }
    }

    #[test]
    fn restart_without_this_deploys_snapshot_is_interrupted() {
        let v = view(11, Some(("completed", Some(101))), NEW, OURS);
        assert_eq!(
            restart(Phase::Waiting, None, &v, &[NEW]),
            RestartAction::FailInterrupted
        );
        let other = Pending {
            deploy: DeployId::parse("d-bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            ..pending()
        };
        assert_eq!(
            restart(Phase::Waiting, Some(&other), &v, &[NEW]),
            RestartAction::FailInterrupted
        );
    }
}
