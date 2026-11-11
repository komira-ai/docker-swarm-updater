//! Deploy rows for retention, the operator and the state and downloads directories.

use crate::harness::*;
use crate::support::HookDisk;
use dsu_core::record::{CallerRecord, ErrorToken, Record, State};
use dsu_server::runner::recover;
use dsu_testkit::mint::Authority;
use dsu_testkit::registry::{Event, Mode};

use super::*;

// retention

/// Deploys `rels` one after the other, each converging.
async fn converge_all(u: &Updater, rels: &[Rel]) -> Vec<Record> {
    let mut records = Vec::new();
    for rel in rels {
        let record = run(u, rel).await;
        assert_eq!(outcome(&record), (State::Converged, None), "{}", rel.file);
        records.push(record);
    }
    records
}

fn six() -> impl FnOnce(&Authority) -> Vec<Rel> {
    |a| {
        ["a", "b", "c", "d", "e", "f"]
            .into_iter()
            .map(|label| Rel::new(a, "app", label))
            .collect()
    }
}

#[tokio::test]
async fn retention_keeps_the_running_the_previous_and_the_last_three_and_deletes_the_rest() {
    let (w, rels) = World::new(Mode::Normal, six()).await;
    let u = w.updater().await;
    let records = converge_all(&u, &rels).await;
    // Running f, previous e, the last three b..d besides them: only `a` goes.
    let deleted: Vec<Event> = w
        .registry
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::ManifestDeleted { .. }))
        .collect();
    assert_eq!(
        deleted,
        [Event::ManifestDeleted {
            repository: "app".into(),
            digest: rels[0].digest()
        }]
    );
    assert!(w.registry.manifest("app", &rels[0].digest()).is_none());
    for rel in &rels[1..] {
        assert!(w.registry.manifest("app", &rel.digest()).is_some());
    }
    let state = service_state(&u, "app").await;
    assert!(!state.pushed.contains(&rels[0].digest()));
    assert_eq!(state.pushed.len(), 5);
    let note = records[5].steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("retention: deleted 1 manifests, 0 could not be deleted"),
        "{note}"
    );
    // Earlier converges deleted nothing.
    assert!(
        !records[4]
            .steps
            .last()
            .unwrap()
            .note
            .clone()
            .unwrap()
            .contains("retention")
    );
}

#[tokio::test]
async fn a_manifest_the_registry_will_not_delete_is_kept_and_noted_not_failed() {
    let (w, rels) = World::new(Mode::FailDelete, six()).await;
    let u = w.updater().await;
    let records = converge_all(&u, &rels).await;
    let note = records[5].steps.last().unwrap().note.clone().unwrap();
    assert!(
        note.contains("deleted 0 manifests, 1 could not be deleted"),
        "{note}"
    );
    assert!(w.registry.manifest("app", &rels[0].digest()).is_some());
    // It stays in the pushed set, so the next converge tries again.
    assert!(
        service_state(&u, "app")
            .await
            .pushed
            .contains(&rels[0].digest())
    );
}

// the operator

#[tokio::test]
async fn the_operator_deploys_a_release_end_to_end() {
    let (w, rel) = World::one(|a| Rel::new(a, "web", "a")).await;
    let u = w.updater().await;
    let reply = u.as_operator("POST", &deploys("web"), &rel.body()).await;
    assert_eq!(reply.status, 202);
    let record = finished(&u.app, &deploy_id(&reply)).await;
    assert_eq!(outcome(&record), (State::Converged, None));
    assert_eq!(record.caller, CallerRecord::Operator);
}

// the state directory and the downloads

#[tokio::test]
async fn a_state_directory_that_stops_working_keeps_the_service_locked_until_the_next_start() {
    let (w, rels) = World::new(Mode::Normal, |a| {
        vec![Rel::new(a, "app", "a"), Rel::new(a, "app", "b")]
    })
    .await;
    let deploys_dir = w.env.state_dir().join("deploys");
    let saved = w.env.dir.path().join("deploys-saved");
    // The image's first chunk is written: the record can no longer be written.
    let hook_dir = (deploys_dir.clone(), saved.clone());
    let disk = HookDisk::new(move |chunk| {
        if chunk == 2 {
            std::fs::rename(&hook_dir.0, &hook_dir.1).unwrap();
        }
    });
    let u = Updater::start(
        &w.env,
        Options {
            disk: std::sync::Arc::new(disk),
            ..w.options()
        },
    )
    .await;
    let reply = post(&u, &rels[0]).await;
    assert_eq!(reply.status, 202);
    u.app.wait_deploys().await;
    // Nothing more was asked of Swarm or the registry. The record could not be ended, so
    // it stays running and its service stays locked until the next start settles it.
    assert!(w.docker().updates().is_empty() && w.registry.events().is_empty());
    assert!(service_state(&u, "app").await.pending.is_none());
    assert!(w.downloads().is_empty());
    std::fs::rename(&saved, &deploys_dir).unwrap();
    let busy = post(&u, &rels[1]).await;
    assert_eq!((busy.status, busy.error().as_str()), (409, "busy"));
    recover(&u.app).await.unwrap();
    let next = post(&u, &rels[1]).await;
    assert_eq!(next.status, 202);
    assert_eq!(
        finished(&u.app, &deploy_id(&next)).await.state,
        State::Converged
    );
}

#[tokio::test]
async fn a_downloads_directory_that_cannot_be_created_is_fetch_failed() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let u = w.updater().await;
    std::fs::write(w.env.state_dir().join("downloads"), b"not a directory").unwrap();
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(record.error.unwrap().detail.starts_with("cannot create "));
}

#[tokio::test]
async fn a_bundle_that_vanishes_after_the_download_is_fetch_failed() {
    let (w, rel) = World::one(|a| Rel::new(a, "app", "a")).await;
    let downloads = w.env.state_dir().join("downloads");
    let disk = HookDisk::new(move |chunk| {
        if chunk == 1 {
            for dir in std::fs::read_dir(&downloads).unwrap() {
                let _ = std::fs::remove_file(dir.unwrap().path().join("bundle.sigstore.json"));
            }
        }
    });
    let u = Updater::start(
        &w.env,
        Options {
            disk: std::sync::Arc::new(disk),
            ..w.options()
        },
    )
    .await;
    let record = run(&u, &rel).await;
    assert_eq!(
        outcome(&record),
        (State::Failed, Some(ErrorToken::FetchFailed))
    );
    assert!(
        record
            .error
            .unwrap()
            .detail
            .starts_with("cannot read the downloaded bundle")
    );
}
