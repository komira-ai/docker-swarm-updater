//! Deploy rows for the downgrade rule, the registry and the Swarm update and its wait.

use crate::harness::*;
use dsu_core::ids::{DeployId, ServiceName};
use dsu_core::record::{ErrorToken, Phase, State};
use dsu_core::swarm::Snapshot;
use dsu_server::clock::Clock as _;
use dsu_testkit::docker::{FakeTask, FakeUpdateStatus, Outcome, UpdateScript};
use dsu_testkit::mint::signed_at;
use dsu_testkit::registry::Mode;
use jiff::SignedDuration;
use serde_json::json;

use super::*;

// downgrade

#[tokio::test]
async fn an_older_release_is_refused_for_a_caller_and_accepted_for_the_operator() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![
            Rel::new(a, "app", "a"),
            Rel::signed(a, "app", "b", SignedDuration::from_secs(-90)),
        ]
    })
    .await;
    let u = w.updater().await;
    assert_eq!(run(&u, &rels[0]).await.state, State::Converged);
    let record = run(&u, &rels[1]).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::OlderThanRunning))
    );
    assert_eq!(
        record.signed_time,
        Some(signed_at() - SignedDuration::from_secs(90))
    );
    let state = service_state(&u, "app").await;
    assert!(state.failed.is_empty(), "the operator's retry must run");
    assert_eq!(state.floor, Some(signed_at()));
    assert_eq!(w.docker().updates().len(), 1);
    assert!(w.registry.manifest("app", &rels[1].digest()).is_none());

    let body = rels[1].body_with(|b| b["allow_older"] = json!(true));
    let reply = u.as_operator("POST", &deploys("app"), &body).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(record.allow_older);
    let note = record.steps[1].note.as_deref().unwrap();
    assert!(note.contains("older than the running release"), "{note}");
    assert!(note.contains("allow_older"), "{note}");
    assert_eq!(
        service_state(&u, "app").await.floor,
        Some(signed_at() - SignedDuration::from_secs(90))
    );
}

// registry

#[tokio::test]
async fn a_registry_that_fails_or_answers_another_digest_leaves_swarm_alone() {
    for mode in [Mode::FailBlobUpload, Mode::AnswerOtherDigest] {
        let (w, mut rels) = World::new(mode, |a| vec![Rel::new(a, "app", "a")]).await;
        let rel = rels.remove(0);
        let u = w.updater().await;
        let record = run(&u, &rel).await;
        assert_eq!(
            outcome(&record),
            (State::Failed, Some(ErrorToken::RegistryFailed)),
            "{mode:?}"
        );
        assert_eq!(record.steps.last().unwrap().phase, Phase::Pushing);
        assert!(w.docker().updates().is_empty());
        let state = service_state(&u, "app").await;
        assert!(state.failed.is_empty() && state.floor.is_none());
        assert!(w.downloads().is_empty());
    }
}

// Swarm

#[tokio::test]
async fn a_rolled_back_update_is_rolled_back_and_its_digest_is_blocked() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::RollsBack);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::RolledBack, Some(ErrorToken::SwarmRolledBack))
    );
    let state = service_state(&u, "app").await;
    assert!(state.is_failed(&rel.digest()));
    assert!(state.floor.is_none() && state.converged.is_empty() && state.pending.is_none());
    let retry = post(&u, &rel).await;
    assert_eq!(
        (retry.status, retry.error().as_str()),
        (409, "previously_failed")
    );
}

#[tokio::test]
async fn a_paused_update_is_paused_and_names_the_failing_task() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::Pauses);
    let mut failing = FakeTask::running("t2", "new");
    failing.state = "failed".into();
    failing.error = Some("task: non-zero exit (1)".into());
    w.docker()
        .set_tasks("app_server", vec![FakeTask::running("t1", "old"), failing]);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Paused, Some(ErrorToken::SwarmPaused))
    );
    let note = record.steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("t2 failed on new (task: non-zero exit (1))"),
        "{note}"
    );
    assert!(note.contains("t1 running on old"), "{note}");
    let state = service_state(&u, "app").await;
    assert!(state.failed.is_empty() && state.pending.is_none());
}

#[tokio::test]
async fn a_timeout_ends_the_deploy_and_asks_swarm_for_nothing_more() {
    let (w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    w.script(Outcome::NeverEnds);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Failed, Some(ErrorToken::Timeout)));
    assert!(record.error.as_ref().unwrap().detail.contains("60 seconds"));
    // Only the update itself was sent: no rollback, no second update.
    assert_eq!(w.docker().updates().len(), 1);
    let state = service_state(&u, "web").await;
    assert!(state.failed.is_empty() && state.pending.is_none());
}

#[tokio::test]
async fn a_docker_that_goes_away_while_waiting_is_retried_until_the_timeout() {
    let (mut w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    w.script(Outcome::NeverEnds);
    let u = w.updater().await;
    let reply = post(&u, &rel).await;
    let id = deploy_id(&reply);
    wait_record(&u.app, &id, |r| r.phase == Phase::Waiting).await;
    w.env.docker = None;
    let record = finished(&u.app, &id).await;
    assert_eq!(outcome(&record), (State::Failed, Some(ErrorToken::Timeout)));
    let note = record.steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("the last read of the service failed"),
        "{note}"
    );
}

#[tokio::test]
async fn without_a_timeout_a_late_completion_still_converges() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let mut script = UpdateScript::new(Outcome::Converges);
    script.updating_reads = 200;
    w.docker().set_script(script);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
}

#[tokio::test]
async fn a_version_conflict_is_retried_once() {
    for (conflicts, want) in [
        (1, (State::Converged, None)),
        (2, (State::Failed, Some(ErrorToken::SwarmRefused))),
    ] {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let mut script = UpdateScript::new(Outcome::Converges);
        script.conflicts = conflicts;
        w.docker().set_script(script);
        let u = w.updater().await;
        let record = run(&u, &rel).await;
        assert_eq!(outcome(&record), want, "{conflicts} conflicts");
        let updates = w.docker().updates();
        assert_eq!(updates.len(), 2);
        // The second attempt quotes the version of a fresh read.
        assert_eq!(updates[1].version, updates[0].version + 1);
        if conflicts == 2 {
            assert!(record.error.unwrap().detail.contains("out of sequence"),);
            assert!(service_state(&u, "app").await.pending.is_none());
        }
    }
}

#[tokio::test]
async fn an_update_swarm_refuses_is_swarm_refused() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    w.script(Outcome::Refuses("the service is locked".into()));
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::SwarmRefused))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .contains("the service is locked")
    );
    assert_eq!(record.steps.last().unwrap().phase, Phase::Updating);
    assert!(!service_state(&u, "app").await.is_failed(&rel.digest()));
}

#[tokio::test]
async fn a_swarm_service_that_does_not_exist_is_swarm_refused() {
    let (w, rel) = World::one(|a| Rel::new(a, "ghost", "a")).await;
    let u = w.updater().await;
    let reply = u
        .as_caller(&caller("ghost"), "POST", &deploys("ghost"), &rel.body())
        .await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::SwarmRefused))
    );
}

#[tokio::test]
async fn a_stale_terminal_state_from_an_earlier_update_is_ignored() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let earlier = w.env.clock.now() - SignedDuration::from_hours(1);
    w.docker().set_update_status(
        "app_server",
        FakeUpdateStatus {
            state: "rollback_completed".into(),
            started_at: earlier,
            message: "an earlier rollback".into(),
        },
    );
    let mut script = UpdateScript::new(Outcome::Converges);
    script.stale_reads = 5;
    script.updating_reads = 2;
    w.docker().set_script(script);
    let u = w.updater().await;
    let record = run(&u, &rel).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert!(service_state(&u, "app").await.failed.is_empty());
}

// Swarm already runs the image

/// Two releases of `web` (`web` waits at most 60 s, so a deploy that never settles ends
/// `timeout` instead of hanging the test), with Swarm's spec and both tasks on the first.
async fn web_running_the_first() -> (World, Vec<Rel>, String) {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "web", "a"), Rel::new(a, "web", "b")]
    })
    .await;
    let image = rels[0].reference(&w.env.registry);
    w.docker().set_image("web_server", &image);
    w.docker().set_tasks(
        "web_server",
        vec![
            FakeTask::running("t1", &image),
            FakeTask::running("t2", &image),
        ],
    );
    (w, rels, image)
}

/// The service is free again: another digest is admitted and converges.
async fn assert_free(u: &Updater, rel: &Rel) {
    let next = post(u, rel).await;
    assert_eq!(next.status, 202, "{}", String::from_utf8_lossy(&next.body));
    let record = finished(&u.app, &deploy_id(&next)).await;
    assert_eq!(outcome(&record), (State::Converged, None));
}

#[tokio::test]
async fn a_deploy_of_the_image_swarm_already_runs_converges_without_an_update() {
    let (w, rels, image) = web_running_the_first().await;
    let u = w.updater().await;
    let record = run(&u, &rels[0]).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::Updating
        ]
    );
    let note = record.steps[3].note.as_deref().unwrap();
    assert_eq!(
        note,
        format!(
            "Swarm already runs {image} on every task; no update asked for; \
             tasks: t1 running on {image}, t2 running on {image}"
        )
    );
    assert!(w.docker().updates().is_empty());
    let state = service_state(&u, "web").await;
    assert_eq!(state.floor, Some(signed_at()));
    assert_eq!(state.converged_digests(), [rels[0].digest()]);
    assert!(state.pending.is_none() && state.failed.is_empty());
    // Converged and running: asked again, the same record answers.
    let again = post(&u, &rels[0]).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.json()["id"], record.id.as_str());
    assert_free(&u, &rels[1]).await;
}

#[tokio::test]
async fn an_update_that_starts_no_rollout_converges_when_an_earlier_one_settles() {
    let (w, rels, image) = web_running_the_first().await;
    // Someone else's update to the image is still rolling out: one task runs the old image,
    // and the status Swarm shows belongs to that update.
    let old = format!("{}/web@{}", w.env.registry, digest(2));
    w.docker().set_tasks(
        "web_server",
        vec![
            FakeTask::running("t1", &image),
            FakeTask::running("t2", &old),
        ],
    );
    let earlier = w.env.clock.now() - SignedDuration::from_hours(1);
    let mut script = UpdateScript::new(Outcome::Converges);
    script.updating_reads = 3;
    w.docker().set_script(script);
    w.docker().begin_update("web_server", earlier);
    let before = w.docker().service("web_server");
    let u = w.updater().await;
    let record = run(&u, &rels[0]).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(phases(&record).last(), Some(&Phase::Waiting));
    // The update changed the labels only, so Swarm started no rollout of its own.
    let updates = w.docker().updates();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].body["TaskTemplate"], before.spec["TaskTemplate"]);
    let after = w.docker().service("web_server");
    assert_eq!(after.update_status.unwrap().started_at, earlier);
    assert_eq!(service_state(&u, "web").await.floor, Some(signed_at()));
    assert_free(&u, &rels[1]).await;
}

#[tokio::test]
async fn a_restart_after_an_update_that_started_no_rollout_converges() {
    let (w, rels, image) = web_running_the_first().await;
    let first = w.updater().await;
    let now = first.app.clock.now();
    let id = DeployId::parse("d-eeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
    first
        .app
        .store
        .put_record(&crafted(
            "web",
            &rels[0].digest(),
            id.as_str(),
            &TO_WAITING,
            now,
        ))
        .await
        .unwrap();
    // What the last process did before it stopped: read, keep the snapshot, ask for the
    // update. Only the labels changed, so Swarm wrote no status.
    let view = w.swarm().inspect_service("web_server").await.unwrap();
    let snapshot = Snapshot {
        version_index: view.version_index,
        read_at: now,
    };
    first
        .app
        .store
        .update_service(&ServiceName::parse("web").unwrap(), |s| {
            s.set_pending(id.clone(), snapshot);
        })
        .await
        .unwrap();
    w.swarm()
        .update_service(&view, &image, &id, &rels[0].digest())
        .await
        .unwrap();
    first.stop().await.unwrap();
    let after = w.swarm().inspect_service("web_server").await.unwrap();
    assert!(after.update_status.is_none());
    assert_eq!(after.deploy_label.as_deref(), Some(id.as_str()));

    let second = w.updater().await;
    let record = second.app.store.record(&id).await.unwrap();
    assert_eq!(outcome(&record), (State::Converged, None));
    let state = service_state(&second, "web").await;
    assert!(state.pending.is_none());
    assert_eq!(state.floor, Some(signed_at()));
    assert_free(&second, &rels[1]).await;
}

#[tokio::test]
async fn an_update_swarm_drops_silently_is_interrupted_and_frees_the_service() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "web", "a"), Rel::new(a, "web", "b")]
    })
    .await;
    w.script(Outcome::Ignores);
    let before = w.docker().service("web_server");
    let u = w.updater().await;
    let record = run(&u, &rels[0]).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert_eq!(w.docker().updates().len(), 1);
    assert_eq!(w.docker().service("web_server"), before);
    let state = service_state(&u, "web").await;
    assert!(state.pending.is_none() && state.failed.is_empty() && state.floor.is_none());
    w.script(Outcome::Converges);
    assert_free(&u, &rels[1]).await;
}
