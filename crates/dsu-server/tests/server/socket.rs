//! The socket and its directory, the peer credentials, `serve` end to end and the stop
//! signals.

use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream as StdStream;

use dsu_server::cli::{ServeArgs, serve};
use dsu_server::peer::{Credentials, PeerCred, SystemPeerCred};
use dsu_server::server::{Shutdown, bind_socket};
use dsu_server::startup::StartError;
use tokio::sync::oneshot;

use crate::harness::{Env, REGISTRY, config_text, current_gid, http, raw, write_trusted_root};

static SIGNALS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().mode() & 0o7777
}

#[tokio::test]
async fn the_socket_is_created_in_a_directory_of_mode_0750_with_mode_0660_and_the_group() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run").join("dsu.sock");
    let _listener = bind_socket(&socket, current_gid()).unwrap();
    let run = socket.parent().unwrap();
    assert_eq!(mode(run), 0o750);
    assert_eq!(mode(&socket), 0o660);
    for path in [run, &socket] {
        assert_eq!(std::fs::metadata(path).unwrap().gid(), current_gid());
    }
    assert!(
        std::fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
}

#[tokio::test]
async fn a_stale_socket_is_replaced_and_another_file_is_not() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("dsu.sock");
    drop(bind_socket(&socket, current_gid()).unwrap());
    assert!(socket.exists(), "the closed listener left its file");
    let _listener = bind_socket(&socket, current_gid()).unwrap();
    assert!(StdStream::connect(&socket).is_ok());
    let taken = dir.path().join("taken");
    std::fs::write(&taken, b"x").unwrap();
    let error = bind_socket(&taken, current_gid()).err().unwrap();
    assert!(matches!(error, StartError::SocketPathTaken { .. }));
    assert!(error.to_string().contains("--socket"));
}

#[tokio::test]
async fn an_existing_directory_open_to_other_users_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    for open in [0o755, 0o701] {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(open)).unwrap();
        let error = bind_socket(&dir.path().join("dsu.sock"), current_gid())
            .err()
            .unwrap();
        assert!(
            matches!(error, StartError::SocketDirOpen { .. }),
            "{open:o}"
        );
        assert!(error.to_string().contains("--socket"));
        assert_eq!(mode(dir.path()), open, "never changed");
    }
    // A closed directory is used as it is.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let _listener = bind_socket(&dir.path().join("dsu.sock"), current_gid()).unwrap();
    assert_eq!(mode(dir.path()), 0o700);
}

#[tokio::test]
async fn socket_failures_name_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    // The parent is a file: the path cannot be inspected.
    let file = dir.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let error = bind_socket(&file.join("dsu.sock"), current_gid())
        .err()
        .unwrap();
    assert!(matches!(error, StartError::Socket { .. }));
    assert!(error.to_string().contains("--socket"));
    // The directory cannot be created below a file.
    let error = bind_socket(&file.join("a").join("dsu.sock"), current_gid())
        .err()
        .unwrap();
    assert!(error.to_string().contains("--socket"));
    // A path too long for a socket address.
    let long = dir.path().join("x".repeat(200));
    std::fs::create_dir(&long).unwrap();
    std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = bind_socket(&long.join("dsu.sock"), current_gid())
        .err()
        .unwrap();
    assert!(error.to_string().contains("bind"), "{error}");
}

/// The real read, from both ends of a connection in this process. The kernel's other answer, pid 0
/// for a peer outside the updater's pid namespace, needs a second pid namespace, which takes
/// privileges a hermetic test does not have; the API tests in `api::peer` feed the server those
/// credentials (and an unreadable read, which is what the earlier rustix-based read gave for
/// pid 0) through the fake peer.
#[tokio::test]
async fn the_peer_credentials_are_the_kernels() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("s")).unwrap();
    let client = tokio::net::UnixStream::connect(dir.path().join("s"))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let mine = Credentials {
        pid: rustix::process::getpid().as_raw_nonzero().get(),
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
    };
    assert_eq!(SystemPeerCred.credentials(&server).unwrap(), mine);
    assert_eq!(SystemPeerCred.credentials(&client).unwrap(), mine);
}

#[tokio::test]
async fn stop_signals_resolve_the_shutdown() {
    let _one_at_a_time = SIGNALS.lock().await;
    for signal in [rustix::process::Signal::TERM, rustix::process::Signal::INT] {
        let shutdown = Shutdown::install().unwrap();
        rustix::process::kill_process(rustix::process::getpid(), signal).unwrap();
        shutdown.wait().await;
    }
}

fn args(env: &Env) -> ServeArgs {
    write_trusted_root(
        &env.dir.path().join("root2.json"),
        &env.authority.trusted_root_json(),
    );
    let config = env.dir.path().join("serve.toml");
    std::fs::write(
        &config,
        config_text(&env.dir.path().join("root2.json"), REGISTRY),
    )
    .unwrap();
    ServeArgs {
        config,
        socket: env.socket(),
        socket_group: current_gid(),
        proxy_uid: 1234,
        state_dir: env.state_dir(),
        docker: env.docker().socket().to_owned(),
        allow_local_operator: false,
        ca_file: None,
    }
}

#[tokio::test]
async fn serve_answers_until_a_stop_signal() {
    let _one_at_a_time = SIGNALS.lock().await;
    let env = Env::new().await;
    let (ready_tx, ready_rx) = oneshot::channel();
    let serving = tokio::spawn(serve(args(&env), move || {
        let _ = ready_tx.send(());
    }));
    ready_rx.await.unwrap();
    let r = raw(&env.socket(), &http("GET", "/v1/health", &[], b"")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), serde_json::json!({"ok": true}));
    // The real peer credentials: this process is neither the proxy nor root.
    let r = raw(&env.socket(), &http("GET", "/v1/services", &[], b"")).await;
    assert_eq!((r.status, r.error().as_str()), (401, "bad_peer"));
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .unwrap();
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_starts_with_a_ca_file_and_stops_on_a_signal() {
    let _one_at_a_time = SIGNALS.lock().await;
    let env = Env::new().await;
    let mut serve_args = args(&env);
    let ca = dsu_testkit::release::ReleaseServer::start(vec![]).await;
    std::fs::write(env.dir.path().join("ca.pem"), ca.ca_pem()).unwrap();
    serve_args.ca_file = Some(env.dir.path().join("ca.pem"));
    let (ready_tx, ready_rx) = oneshot::channel();
    let serving = tokio::spawn(serve(serve_args, move || {
        let _ = ready_tx.send(());
    }));
    ready_rx.await.unwrap();
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT).unwrap();
    serving.await.unwrap().unwrap();
}
