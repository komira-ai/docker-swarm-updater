//! Deploy rows for a restart at each phase and for the self-update hand-off.

use crate::harness::*;
use dsu_core::ids::{DeployId, ServiceName};
use dsu_core::record::{ErrorToken, Phase, Record, State};
use dsu_core::swarm::Snapshot;
use dsu_server::runner::{RunnerError, recover};
use dsu_testkit::docker::Outcome;
use dsu_testkit::mint::signed_at;

use super::*;

// restart

#[tokio::test]
async fn a_restart_in_the_fetching_phase_fails_the_deploy_and_the_caller_asks_again() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    // The first process never gets an answer from the release server.
    let first = Updater::start(&w.env, Options::default()).await;
    let id = deploy_id(&post(&first, &rel).await);
    wait_record(&first.app, &id, |r| r.phase == Phase::Fetching).await;
    first.stop().await.unwrap();
    let leftover = w.env.state_dir().join("downloads").join("d-left");
    std::fs::create_dir_all(&leftover).unwrap();
    std::fs::write(leftover.join("image.tar"), b"partial").unwrap();

    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(w.docker().updates().is_empty());
    assert!(!service_state(&second, "app").await.is_failed(&rel.digest()));
    assert!(w.downloads().is_empty(), "leftover downloads are removed");
    let again = run(&second, &rel).await;
    assert_eq!(outcome(&again), (State::Converged, None));
}

/// A first process that left a deploy of `rel` waiting on a Swarm update that never ends.
async fn left_waiting(w: &World, rel: &Rel) -> DeployId {
    w.script(Outcome::NeverEnds);
    let first = w.updater().await;
    let id = deploy_id(&post(&first, rel).await);
    wait_record(&first.app, &id, |r| r.phase == Phase::Waiting).await;
    first.stop().await.unwrap();
    id
}

#[tokio::test]
async fn a_restart_while_swarm_still_updates_resumes_the_wait() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let id = left_waiting(&w, &rel).await;
    let second = w.updater().await;
    // Swarm is still updating: the record is running, and its service is locked.
    let record = second.app.store.record(&id).await.unwrap();
    assert_eq!(record.state, State::Running);
    let other = Rel::new(&w.env.authority, "app", "z");
    let busy = post(&second, &other).await;
    assert_eq!((busy.status, busy.error().as_str()), (409, "busy"));
    w.script(Outcome::Converges);
    let record = finished(&second.app, &id).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::Updating,
            Phase::Waiting
        ]
    );
    let state = service_state(&second, "app").await;
    assert_eq!(state.floor, Some(signed_at()));
    assert!(state.pending.is_none());
    assert_eq!(
        w.docker().updates().len(),
        1,
        "the update is not asked for again"
    );
}

#[tokio::test]
async fn a_restart_after_swarm_settled_ends_the_record_at_start() {
    let cases = [
        (Outcome::Converges, (State::Converged, None)),
        (
            Outcome::RollsBack,
            (State::RolledBack, Some(ErrorToken::SwarmRolledBack)),
        ),
        (
            Outcome::Pauses,
            (State::Paused, Some(ErrorToken::SwarmPaused)),
        ),
    ];
    for (settles, want) in cases {
        let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
        let id = left_waiting(&w, &rel).await;
        // Swarm finishes while no updater runs; reading the service lets the fake go on.
        w.script(settles);
        w.swarm().inspect_service("app_server").await.unwrap();
        let second = w.updater().await;
        let record = second.app.store.record(&id).await.unwrap();
        assert_eq!(outcome(&record), want);
        let state = service_state(&second, "app").await;
        assert_eq!(state.is_failed(&rel.digest()), want.0 == State::RolledBack);
        assert!(state.pending.is_none());
        assert_eq!(state.floor.is_some(), want.0 == State::Converged);
    }
}

#[tokio::test]
async fn a_restart_finds_a_spec_no_update_of_the_deploy_explains() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let first = w.updater().await;
    let now = first.app.clock.now();
    let id = "d-aaaaaaaaaaaaaaaaaaaaaaaaaa";
    first
        .app
        .store
        .put_record(&crafted("app", &rel.digest(), id, &TO_WAITING, now))
        .await
        .unwrap();
    // Swarm's spec was changed by hand: no update of this deploy ever ran.
    let snapshot = Snapshot {
        version_index: w.docker().service("app_server").index,
        read_at: now,
    };
    first
        .app
        .store
        .update_service(&ServiceName::parse("app").unwrap(), |s| {
            s.set_pending(DeployId::parse(id).unwrap(), snapshot);
        })
        .await
        .unwrap();
    first.stop().await.unwrap();

    let second = w.updater().await;
    let record = second
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(service_state(&second, "app").await.pending.is_none());
}

#[tokio::test]
async fn a_restart_ends_a_record_whose_service_is_no_longer_configured() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let first = w.updater().await;
    let id = "d-bbbbbbbbbbbbbbbbbbbbbbbbbb";
    first
        .app
        .store
        .put_record(&crafted(
            "removed",
            &rel.digest(),
            id,
            &[Phase::Fetching],
            first.app.clock.now(),
        ))
        .await
        .unwrap();
    first.stop().await.unwrap();
    let second = w.updater().await;
    let record = second
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::Interrupted))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .contains("no longer configured")
    );
}

#[tokio::test]
async fn a_restart_that_cannot_read_swarm_does_not_settle_anything() {
    let (mut w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    let id = "d-cccccccccccccccccccccccccc";
    u.app
        .store
        .put_record(&crafted(
            "app",
            &rel.digest(),
            id,
            &TO_WAITING,
            u.app.clock.now(),
        ))
        .await
        .unwrap();
    w.env.docker = None;
    let error = recover(&u.app).await.unwrap_err();
    assert!(matches!(error, RunnerError::Docker { .. }), "{error}");
    assert!(error.to_string().contains(id));
    let record = u
        .app
        .store
        .record(&DeployId::parse(id).unwrap())
        .await
        .unwrap();
    assert_eq!(record.state, State::Running);
}

// self-update

/// The environment of an updater that runs as the Swarm service of `app`.
fn as_app_server(w: &World) {
    w.docker().add_container(
        "dsu-test-host",
        &[("com.docker.swarm.service.name", "app_server")],
    );
}

#[tokio::test]
async fn a_self_update_hands_off_and_the_next_process_settles_it_converged() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    let id = left_waiting(&w, &rel).await;
    let record = finished_or_running(&w, &id).await;
    // The self-update goes from pushing to handed_off, never through updating.
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::HandedOff,
            Phase::Waiting
        ]
    );
    w.script(Outcome::Converges);
    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(w.docker().updates().len(), 1);
    assert_eq!(service_state(&second, "app").await.floor, Some(signed_at()));
}

/// The record `id` as the files hold it, read by a short-lived store.
async fn finished_or_running(w: &World, id: &DeployId) -> Record {
    let bytes =
        std::fs::read(w.env.state_dir().join("deploys").join(format!("{id}.json"))).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a_self_update_that_swarm_rolls_back_is_settled_rolled_back_by_the_old_image() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    let id = left_waiting(&w, &rel).await;
    w.script(Outcome::RollsBack);
    w.swarm().inspect_service("app_server").await.unwrap();
    let second = w.updater().await;
    let record = finished(&second.app, &id).await;
    assert_eq!(
        outcome(&record),
        (State::RolledBack, Some(ErrorToken::SwarmRolledBack))
    );
    assert!(service_state(&second, "app").await.is_failed(&rel.digest()));
}

#[tokio::test]
async fn a_record_handed_off_before_swarm_answered_is_waited_for_from_handed_off() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    as_app_server(&w);
    w.script(Outcome::NeverEnds);
    let first = w.updater().await;
    let now = first.app.clock.now();
    let id = DeployId::parse("d-dddddddddddddddddddddddddd").unwrap();
    first
        .app
        .store
        .put_record(&crafted(
            "app",
            &rel.digest(),
            id.as_str(),
            &[
                Phase::Fetching,
                Phase::Verifying,
                Phase::Pushing,
                Phase::HandedOff,
            ],
            now,
        ))
        .await
        .unwrap();
    // The update was accepted by Swarm, then the process went away before it waited.
    let client = w.swarm();
    let view = client.inspect_service("app_server").await.unwrap();
    let snapshot = Snapshot {
        version_index: view.version_index,
        read_at: now,
    };
    first
        .app
        .store
        .update_service(&ServiceName::parse("app").unwrap(), |s| {
            s.set_pending(id.clone(), snapshot);
        })
        .await
        .unwrap();
    let image = rel.reference(&w.env.registry);
    client
        .update_service(&view, &image, &id, &rel.digest())
        .await
        .unwrap();
    first.stop().await.unwrap();

    let second = w.updater().await;
    // While it resumes, no other deploy runs next to a self-update.
    let other = Rel::new(&w.env.authority, "web", "a");
    let busy = post(&second, &other).await;
    assert_eq!(
        (busy.status, busy.error().as_str()),
        (409, "self_update_busy")
    );
    w.script(Outcome::Converges);
    let record = finished(&second.app, &id).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(
        phases(&record),
        [
            Phase::Fetching,
            Phase::Verifying,
            Phase::Pushing,
            Phase::HandedOff,
            Phase::Waiting
        ]
    );
}
