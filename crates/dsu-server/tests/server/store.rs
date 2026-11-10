//! The state directory: what is written, what is loaded back, and what is refused.

use dsu_core::ids::{DeployId, ServiceName};
use dsu_core::record::{CallerRecord, NewRecord, Phase, Record, State};
use dsu_server::store::{Store, StoreError};
use jiff::Timestamp;

fn t(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn now() -> Timestamp {
    t("2026-10-01T00:00:00Z")
}

fn service(name: &str) -> ServiceName {
    ServiceName::parse(name).unwrap()
}

fn record(id: &str, name: &str, n: u8, started: &str) -> Record {
    Record::start(NewRecord {
        id: DeployId::parse(id).unwrap(),
        service: service(name),
        swarm_service: format!("{name}_server"),
        image_digest: crate::harness::digest(n),
        version: "1".into(),
        caller: CallerRecord::Operator,
        allow_older: false,
        now: t(started),
    })
}

const A: &str = "d-aaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "d-bbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "d-cccccccccccccccccccccccccc";

fn names(dir: &std::path::Path, sub: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir.join(sub))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn open_creates_the_three_directories_and_an_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("a").join("state");
    let store = Store::open(&state, now()).await.unwrap();
    assert_eq!(store.dir(), state);
    for sub in ["deploys", "services", "jti"] {
        assert!(state.join(sub).is_dir(), "{sub}");
    }
    assert!(store.running_records().await.is_empty());
    assert!(store.record(&DeployId::parse(A).unwrap()).await.is_none());
    assert_eq!(
        store.service_state(&service("app")).await,
        Default::default()
    );
    store.check_writable().await.unwrap();
    assert!(names(&state, ".").iter().all(|n| n != "health"));
}

#[tokio::test]
async fn records_and_service_state_are_written_and_loaded_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), now()).await.unwrap();
    let mut first = record(A, "app", 1, "2026-10-01T00:00:00Z");
    store.put_record(&first).await.unwrap();
    first.enter_phase(Phase::Fetching, now()).unwrap();
    store.put_record(&first).await.unwrap();
    store
        .put_record(&record(B, "app", 1, "2026-10-01T00:00:05Z"))
        .await
        .unwrap();
    let mut done = record(C, "web", 2, "2026-10-01T00:00:09Z");
    done.finish_failed(dsu_core::record::ErrorToken::FetchFailed, "x", now())
        .unwrap();
    store.put_record(&done).await.unwrap();
    store
        .update_service(&service("app"), |s| s.add_failed(crate::harness::digest(3)))
        .await
        .unwrap();
    assert_eq!(
        names(dir.path(), "deploys"),
        [
            format!("{A}.json"),
            format!("{B}.json"),
            format!("{C}.json")
        ]
    );
    assert_eq!(names(dir.path(), "services"), ["app.json"]);

    // The newest record of a digest, of a service; the running ones, oldest first.
    let digest1 = crate::harness::digest(1);
    let newest = store
        .latest_for_digest(&service("app"), &digest1)
        .await
        .unwrap();
    assert_eq!(newest.id.as_str(), B);
    assert!(
        store
            .latest_for_digest(&service("web"), &digest1)
            .await
            .is_none()
    );
    assert_eq!(
        store
            .last_record(&service("web"))
            .await
            .unwrap()
            .id
            .as_str(),
        C
    );
    assert!(store.last_record(&service("ghost")).await.is_none());
    let running: Vec<String> = store
        .running_records()
        .await
        .iter()
        .map(|r| r.id.to_string())
        .collect();
    assert_eq!(running, [A, B]);

    // A new process sees the same.
    drop(store);
    let again = Store::open(dir.path(), now()).await.unwrap();
    let first = again.record(&DeployId::parse(A).unwrap()).await.unwrap();
    assert_eq!(
        (first.state, first.phase),
        (State::Running, Phase::Fetching)
    );
    assert_eq!(
        again.record(&DeployId::parse(C).unwrap()).await.unwrap(),
        done
    );
    assert!(
        again
            .service_state(&service("app"))
            .await
            .is_failed(&crate::harness::digest(3))
    );
}

#[tokio::test]
async fn a_token_id_is_accepted_once_and_forgotten_after_exp() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), now()).await.unwrap();
    let exp = t("2026-10-01T00:05:00Z");
    assert!(store.spend_jti("one", exp, now()).await.unwrap());
    assert!(!store.spend_jti("one", exp, now()).await.unwrap());
    assert!(store.spend_jti("two", exp, now()).await.unwrap());
    let files = names(dir.path(), "jti");
    assert_eq!(files.len(), 2);
    assert!(
        files
            .iter()
            .all(|f| f.len() == 64 && f.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("jti").join(&files[0])).unwrap(),
        "2026-10-01T00:05:00Z"
    );
    // Reopened before exp: still spent. Reopened at exp: forgotten, files removed.
    drop(store);
    let store = Store::open(dir.path(), t("2026-10-01T00:04:59Z"))
        .await
        .unwrap();
    assert!(!store.spend_jti("one", exp, now()).await.unwrap());
    drop(store);
    let store = Store::open(dir.path(), exp).await.unwrap();
    assert!(names(dir.path(), "jti").is_empty());
    assert!(store.spend_jti("one", exp, exp).await.unwrap());
}

#[tokio::test]
async fn leftover_temporary_files_are_removed_at_open() {
    let dir = tempfile::tempdir().unwrap();
    drop(Store::open(dir.path(), now()).await.unwrap());
    for sub in ["deploys", "services", "jti"] {
        std::fs::write(dir.path().join(sub).join("x.tmp"), b"half").unwrap();
    }
    Store::open(dir.path(), now()).await.unwrap();
    for sub in ["deploys", "services", "jti"] {
        assert!(names(dir.path(), sub).is_empty(), "{sub}");
    }
}

async fn refused(dir: &std::path::Path, sub: &str, name: &str, content: &str) -> String {
    drop(Store::open(dir, now()).await.unwrap());
    std::fs::write(dir.join(sub).join(name), content).unwrap();
    let error = Store::open(dir, now()).await.err().unwrap();
    assert!(matches!(error, StoreError::Corrupt { .. }), "{error:?}");
    let message = error.to_string();
    assert!(message.contains(name), "{message}");
    std::fs::remove_file(dir.join(sub).join(name)).unwrap();
    message
}

#[tokio::test]
async fn files_that_are_not_what_their_names_say_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    let good = serde_json::to_string(&record(A, "app", 1, "2026-10-01T00:00:00Z")).unwrap();
    refused(p, "deploys", "notes.txt", "x").await;
    refused(p, "deploys", &format!("{A}.json"), "not json").await;
    refused(p, "deploys", &format!("{B}.json"), &good).await;
    refused(p, "services", "App.json", "{}").await;
    refused(p, "services", "app.json", "[1]").await;
    refused(p, "jti", "short", "2026-10-01T00:00:00Z").await;
    let long = "g".repeat(64);
    refused(p, "jti", &long, "2026-10-01T00:00:00Z").await;
    let hex = "a".repeat(64);
    refused(p, "jti", &hex, "tomorrow").await;
}

#[tokio::test]
async fn a_directory_that_cannot_be_used_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    let error = Store::open(&file.join("state"), now()).await.err().unwrap();
    assert!(matches!(error, StoreError::Io { .. }));
    assert!(error.to_string().contains("file/state"));
}

#[tokio::test]
async fn a_failed_write_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let store = Store::open(&state, now()).await.unwrap();
    store
        .update_service(&service("app"), |s| s.add_failed(crate::harness::digest(1)))
        .await
        .unwrap();
    std::fs::remove_dir_all(&state).unwrap();
    let id = DeployId::parse(A).unwrap();
    assert!(
        store
            .put_record(&record(A, "app", 1, "2026-10-01T00:00:00Z"))
            .await
            .is_err()
    );
    assert!(store.record(&id).await.is_none());
    let changed = store
        .update_service(&service("app"), |s| s.add_failed(crate::harness::digest(2)))
        .await;
    assert!(changed.is_err());
    let state_now = store.service_state(&service("app")).await;
    assert!(
        state_now.is_failed(&crate::harness::digest(1))
            && !state_now.is_failed(&crate::harness::digest(2))
    );
    assert!(
        store
            .spend_jti("j", t("2026-10-01T00:05:00Z"), now())
            .await
            .is_err()
    );
    assert!(store.check_writable().await.is_err());
}

#[tokio::test]
async fn pruning_goes_on_when_a_file_is_already_gone() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), now()).await.unwrap();
    store
        .spend_jti("one", t("2026-10-01T00:05:00Z"), now())
        .await
        .unwrap();
    for file in names(dir.path(), "jti") {
        std::fs::remove_file(dir.path().join("jti").join(file)).unwrap();
    }
    let later = t("2026-10-01T02:00:00Z");
    assert!(
        store
            .spend_jti("two", t("2026-10-01T03:00:00Z"), later)
            .await
            .unwrap()
    );
    assert!(
        store
            .spend_jti("one", t("2026-10-01T03:00:00Z"), later)
            .await
            .unwrap(),
        "forgotten"
    );
}
