//! The command line: `import` (bundles good and refused), `probe`, usage errors and the
//! exit codes.

use std::ffi::OsString;
use std::time::Duration;

use clap::Parser as _;
use dsu_server::cli::{
    Cli, CliError, Command, ImportArgs, ProbeArgs, import, probe, run, run_with_clock,
};
use dsu_server::pipeline::PipelineError;
use dsu_testkit::mint::Authority;
use dsu_testkit::oci::OciImage;
use dsu_testkit::registry::{Event, FakeRegistry, Mode};

use crate::harness::{Env, Options, Updater, config_text, write_trusted_root};
use crate::pipeline::Release;
use crate::support::FakeClock;

fn parse(args: &[&str]) -> Command {
    let all = std::iter::once("docker-swarm-updater").chain(args.iter().copied());
    Cli::try_parse_from(all).unwrap().command
}

struct Import {
    dir: tempfile::TempDir,
    registry: FakeRegistry,
    release: Release,
    image_digest: dsu_core::ids::Digest,
}

impl Import {
    async fn new(mode: Mode) -> Import {
        let dir = tempfile::tempdir().unwrap();
        let registry = FakeRegistry::start(mode).await;
        let authority = Authority::public_good();
        let image = OciImage::new("a").layers(2).build();
        let release = Release::of(&authority, &image);
        write_trusted_root(
            &dir.path().join("root.json"),
            &authority.trusted_root_json(),
        );
        std::fs::write(
            dir.path().join("config.toml"),
            config_text(&dir.path().join("root.json"), &registry.addr()),
        )
        .unwrap();
        std::fs::write(dir.path().join("bundle.json"), &release.bundle).unwrap();
        Import {
            dir,
            registry,
            release,
            image_digest: image.manifest_digest,
        }
    }

    fn args(&self) -> ImportArgs {
        let path = |name: &str| self.dir.path().join(name).display().to_string();
        let tar = self.release.tar.display().to_string();
        let digest = self.image_digest.to_string();
        let Command::Import(args) = parse(&[
            "import",
            "--config",
            &path("config.toml"),
            "--service",
            "app",
            "--tar",
            &tar,
            "--bundle",
            &path("bundle.json"),
            "--digest",
            &digest,
        ]) else {
            unreachable!("the verb is import")
        };
        args
    }
}

#[tokio::test]
async fn import_verifies_pushes_and_prints_the_reference() {
    let i = Import::new(Mode::Normal).await;
    let mut out = Vec::new();
    let code = run(Command::Import(i.args()), &mut out).await.unwrap();
    assert_eq!(code, 0);
    let reference = format!("{}/app@{}\n", i.registry.addr(), i.image_digest);
    assert_eq!(String::from_utf8(out).unwrap(), reference);
    assert!(i.registry.manifest("app", &i.image_digest).is_some());
}

#[tokio::test]
async fn import_of_a_refused_bundle_pushes_nothing() {
    let i = Import::new(Mode::Normal).await;
    // A bundle made by another signing chain.
    let other = Release::of(
        &Authority::public_good(),
        &OciImage::new("a").layers(2).build(),
    );
    std::fs::write(i.dir.path().join("bundle.json"), &other.bundle).unwrap();
    let mut out = Vec::new();
    let error = import(&i.args(), &mut out).await.unwrap_err();
    assert!(out.is_empty());
    assert!(
        matches!(error, CliError::Pipeline(PipelineError::Verify(_))),
        "{error}"
    );
    assert!(i.registry.events().is_empty());
    // Not a bundle at all.
    std::fs::write(i.dir.path().join("bundle.json"), "nope").unwrap();
    let error = import(&i.args(), &mut out).await.unwrap_err();
    assert!(
        error.to_string().contains("not a Sigstore bundle"),
        "{error}"
    );
}

#[tokio::test]
async fn import_failures_are_named() {
    let i = Import::new(Mode::Normal).await;
    let mut out = Vec::new();
    // A service the config does not list.
    let mut args = i.args();
    args.service = dsu_core::ids::ServiceName::parse("nope").unwrap();
    let error = import(&args, &mut out).await.unwrap_err();
    assert!(matches!(error, CliError::UnknownService(_)));
    assert!(error.to_string().contains("nope"));
    // A bundle that cannot be read, a tar that cannot be read, a config that is refused.
    let mut args = i.args();
    args.bundle = i.dir.path().join("missing");
    assert!(matches!(
        import(&args, &mut out).await.unwrap_err(),
        CliError::ReadBundle { .. }
    ));
    let mut args = i.args();
    args.tar = i.dir.path().join("missing.tar");
    assert!(matches!(
        import(&args, &mut out).await.unwrap_err(),
        CliError::Pipeline(PipelineError::Read { .. })
    ));
    let mut args = i.args();
    args.config = i.dir.path().join("missing.toml");
    assert!(matches!(
        import(&args, &mut out).await.unwrap_err(),
        CliError::Start(_)
    ));
    assert!(out.is_empty());
}

#[tokio::test]
async fn import_with_a_failing_registry_or_output() {
    let i = Import::new(Mode::FailBlobUpload).await;
    let mut out = Vec::new();
    let error = import(&i.args(), &mut out).await.unwrap_err();
    assert!(
        matches!(error, CliError::Pipeline(PipelineError::Registry(_))),
        "{error}"
    );
    assert!(out.is_empty());

    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let i = Import::new(Mode::Normal).await;
    let error = import(&i.args(), &mut Broken).await.unwrap_err();
    assert!(matches!(error, CliError::Output(_)));
    assert!(
        i.registry
            .events()
            .iter()
            .any(|e| matches!(e, Event::ManifestPushed { .. })),
        "the image was pushed before the output failed"
    );
}

fn probe_args(extra: &[&str], target: &str) -> ProbeArgs {
    let mut all = vec!["probe"];
    all.extend_from_slice(extra);
    all.push(target);
    let Command::Probe(args) = parse(&all) else {
        unreachable!()
    };
    args
}

#[test]
fn timeouts_are_a_number_and_a_unit() {
    let timeout = |text: &str| probe_args(&["--timeout", text], "/x").timeout;
    assert_eq!(timeout("500ms"), Duration::from_millis(500));
    assert_eq!(timeout("2s"), Duration::from_secs(2));
    assert_eq!(timeout("3m"), Duration::from_secs(180));
    assert_eq!(probe_args(&[], "/x").timeout, Duration::from_secs(2));
    assert_eq!(
        timeout("18446744073709551615m"),
        Duration::from_secs(u64::MAX)
    );
    for bad in ["", "s", "2", "2h", "-1s", "1.5s", "99999999999999999999s"] {
        let all = ["docker-swarm-updater", "probe", "--timeout", bad, "/x"];
        assert!(Cli::try_parse_from(all).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn probe_exit_codes_against_the_updaters_own_health_route() {
    let env = Env::new().await;
    let u = Updater::start(&env, Options::default()).await;
    let socket = env.socket().display().to_string();
    u.set_peer(1);
    // The clock never moves: an answer is expected, so the deadline must not fire.
    let clock = FakeClock::new();
    let healthy = probe_args(&["--unix", &socket], "/v1/health");
    assert_eq!(probe(&healthy, &clock).await.unwrap(), 0);
    env.docker().set_ping_status(500);
    assert_eq!(probe(&healthy, &clock).await.unwrap(), 1);
    let mut out = Vec::new();
    let code = run_with_clock(Command::Probe(healthy), &mut out, &clock)
        .await
        .unwrap();
    assert_eq!(code, 1);
    assert!(out.is_empty(), "nothing on stdout");
    // A target the rules refuse is an error, not an exit code.
    let error = probe(&probe_args(&[], "http://example.com/x"), &clock)
        .await
        .unwrap_err();
    assert!(matches!(error, CliError::Target(_)));
    let error = probe(&probe_args(&["--unix", &socket], "v1/health"), &clock)
        .await
        .unwrap_err();
    assert!(matches!(error, CliError::Target(_)));
}

fn main_code(args: &[&str]) -> std::process::ExitCode {
    let all: Vec<OsString> = std::iter::once("docker-swarm-updater")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    dsu_server::cli::main(all)
}

#[test]
fn main_returns_the_exit_codes() {
    use std::process::ExitCode;
    assert_eq!(main_code(&["--help"]), ExitCode::SUCCESS);
    assert_eq!(main_code(&["--version"]), ExitCode::SUCCESS);
    assert_eq!(main_code(&["serve", "--nope"]), ExitCode::from(2));
    assert_eq!(main_code(&[]), ExitCode::from(2));
    // A refused probe target: 2. A probe of a closed port: 1.
    assert_eq!(
        main_code(&["probe", "http://example.com/x"]),
        ExitCode::from(2)
    );
    let closed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        });
    assert_eq!(
        main_code(&["probe", &format!("http://127.0.0.1:{closed}/x")]),
        ExitCode::from(1)
    );
    // `serve --proxy-uid 0` is refused before anything starts.
    assert_eq!(
        main_code(&[
            "serve",
            "--config",
            "c",
            "--socket",
            "s",
            "--socket-group",
            "0",
            "--proxy-uid",
            "0",
            "--state-dir",
            "d",
            "--docker",
            "k",
        ]),
        ExitCode::from(2)
    );
}
