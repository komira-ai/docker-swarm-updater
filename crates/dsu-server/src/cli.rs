//! The command line (docs/design.md sections 2.4 and 4): `serve`, `import` and `probe`. No
//! setting is read from the environment.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use dsu_core::ids::{Digest, ServiceName};

use crate::app::{App, Params, image_reference};
use crate::clock::{Clock, SystemClock};
use crate::fetch::{FetchError, SystemDisk, default_roots, roots_from_pem};
use crate::log::Log;
use crate::net::SystemNetwork;
use crate::peer::SystemPeerCred;
use crate::pipeline::{self, PipelineError, VerifyJob};
use crate::probe::{ProbeOutcome, ProbeTarget, TargetError};
use crate::runner::{self, RunnerError};
use crate::server::{ServeError, Shutdown, bind_socket, serve as serve_connections};
use crate::startup::{StartError, load_config};

/// The command line of the binary.
#[derive(Debug, Parser)]
#[command(
    name = "docker-swarm-updater",
    version,
    about = "Deploys a pinned, signature-checked image to a Docker Swarm service when a CI job asks"
)]
pub struct Cli {
    /// What to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The verbs.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve the API on a Unix socket.
    Serve(ServeArgs),
    /// Verify a release's image tar and bundle from local files and push the image.
    Import(ImportArgs),
    /// GET a loopback URL or a Unix socket path; exit 0 on a 2xx answer, 1 otherwise.
    Probe(ProbeArgs),
}

/// The flags of `serve`.
#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    /// The config file (TOML).
    #[arg(long)]
    pub config: PathBuf,
    /// The Unix socket to listen on.
    #[arg(long)]
    pub socket: PathBuf,
    /// The group id that may open the socket.
    #[arg(long)]
    pub socket_group: u32,
    /// The uid of the fronting proxy's process; never 0.
    #[arg(long)]
    pub proxy_uid: u32,
    /// The directory of records, service state and spent token ids.
    #[arg(long)]
    pub state_dir: PathBuf,
    /// The Docker Engine API's Unix socket.
    #[arg(long)]
    pub docker: PathBuf,
    /// Accept requests without claims from uid 0 as the local operator.
    #[arg(long)]
    pub allow_local_operator: bool,
    /// PEM certificates that replace the built-in roots for downloads.
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
}

/// The flags of `import`.
#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    /// The config file (TOML).
    #[arg(long)]
    pub config: PathBuf,
    /// The configured service the image is for.
    #[arg(long, value_parser = ServiceName::parse)]
    pub service: ServiceName,
    /// The image tar (an OCI image layout).
    #[arg(long)]
    pub tar: PathBuf,
    /// The tar's Sigstore bundle.
    #[arg(long)]
    pub bundle: PathBuf,
    /// The manifest digest expected, `sha256:<64 hex>`.
    #[arg(long, value_parser = Digest::parse)]
    pub digest: Digest,
}

/// The arguments of `probe`.
#[derive(Debug, Clone, Args)]
pub struct ProbeArgs {
    /// Probe this Unix socket; the target is then a request path.
    #[arg(long, value_name = "SOCKET")]
    pub unix: Option<PathBuf>,
    /// How long the whole exchange may take: a number and `ms`, `s` or `m`.
    #[arg(long, default_value = "2s", value_parser = parse_timeout)]
    pub timeout: Duration,
    /// `http://<loopback address>[:port]/<path>`, or with `--unix` the request path.
    pub target: String,
}

/// A duration written as a number followed by `ms`, `s` or `m`.
fn parse_timeout(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    let wrong = || format!("{text:?} is not a duration such as 2s, 500ms or 1m");
    let n: u64 = digits.parse().map_err(|_| wrong())?;
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n.saturating_mul(60))),
        _ => Err(wrong()),
    }
}

/// A command that failed or was refused.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// `serve` was refused or could not start.
    #[error("{0}")]
    Start(#[from] StartError),
    /// `serve` could not settle the deploys a previous run left unfinished.
    #[error("{0}")]
    Recover(#[from] RunnerError),
    /// `serve` stopped on an error.
    #[error("{0}")]
    Serve(#[from] ServeError),
    /// `import` did not verify or push the image.
    #[error("{0}")]
    Pipeline(#[from] PipelineError),
    /// `probe` was given a target it refuses.
    #[error("{0}")]
    Target(#[from] TargetError),
    /// `import` names a service the config does not list.
    #[error("service {0} is not in the config")]
    UnknownService(ServiceName),
    /// `import`'s bundle cannot be read.
    #[error("cannot read the bundle {path}: {source}")]
    ReadBundle {
        /// The file.
        path: PathBuf,
        /// The operating system error.
        source: std::io::Error,
    },
    /// Writing the answer failed.
    #[error("cannot write the output: {0}")]
    Output(#[source] std::io::Error),
    /// The async runtime could not start.
    #[error("cannot start the runtime: {0}")]
    Runtime(#[source] std::io::Error),
}

/// Runs the command line `args` and returns the process exit code: 0 on success, `probe`'s 1
/// for an unhealthy answer, 2 for a usage error, a refusal or a failure.
pub fn main<I: IntoIterator<Item = OsString>>(args: I) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2));
        }
    };
    ExitCode::from(match run_blocking(cli.command) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    })
}

fn run_blocking(command: Command) -> Result<u8, CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    runtime.block_on(run(command, &mut std::io::stdout()))
}

/// Runs one command; `import` writes the image reference to `out`. Returns the exit code.
pub async fn run(command: Command, out: &mut dyn Write) -> Result<u8, CliError> {
    run_with_clock(command, out, &SystemClock).await
}

/// [`run`] with the clock `probe` measures its deadline on.
pub async fn run_with_clock(
    command: Command,
    out: &mut dyn Write,
    clock: &dyn Clock,
) -> Result<u8, CliError> {
    match command {
        Command::Serve(args) => serve(args, || {}).await?,
        Command::Import(args) => import(&args, out).await?,
        Command::Probe(args) => return probe(&args, clock).await,
    }
    Ok(0)
}

/// `serve`: checks the flags and the config, opens the state, binds the socket and serves
/// until `SIGTERM` or `SIGINT`. `ready` runs once the socket accepts connections.
pub async fn serve(args: ServeArgs, ready: impl FnOnce()) -> Result<(), CliError> {
    if args.proxy_uid == 0 {
        return Err(StartError::ProxyUidZero.into());
    }
    let loaded = load_config(&args.config)?;
    let tls_roots = match &args.ca_file {
        Some(path) => ca_roots(path).map_err(|source| StartError::CaFile {
            path: path.clone(),
            source,
        })?,
        None => default_roots(),
    };
    let app = App::start(Params {
        config: loaded.config,
        roots: loaded.roots,
        state_dir: args.state_dir,
        docker_socket: args.docker,
        proxy_uid: args.proxy_uid,
        allow_local_operator: args.allow_local_operator,
        hostname: rustix::system::uname()
            .nodename()
            .to_string_lossy()
            .into_owned(),
        clock: Arc::new(SystemClock),
        peer_cred: Arc::new(SystemPeerCred),
        log: Log::stderr(),
        network: Arc::new(SystemNetwork),
        disk: Arc::new(SystemDisk),
        tls_roots,
    })
    .await?;
    let listener = bind_socket(&args.socket, args.socket_group)?;
    let shutdown = Shutdown::install()?;
    runner::recover(&app).await?;
    ready();
    serve_connections(app, listener, shutdown.wait()).await?;
    Ok(())
}

/// The trust `serve --ca-file` gives downloads: exactly the certificates of the PEM file at
/// `path`, in place of the built-in roots.
pub fn ca_roots(path: &std::path::Path) -> Result<rustls::RootCertStore, FetchError> {
    let pem = std::fs::read(path).map_err(|e| FetchError::CaFile(e.to_string()))?;
    roots_from_pem(&pem)
}

/// `import`: sections 3.3 steps 1 to 4 and 3.4 on local files, then the image reference
/// `<registry>/<repository>@<digest>` is written to `out`. The signed-time floor (step 5)
/// needs a state directory and is not checked.
pub async fn import(args: &ImportArgs, out: &mut dyn Write) -> Result<(), CliError> {
    let loaded = load_config(&args.config)?;
    let service = loaded
        .config
        .service(&args.service)
        .ok_or_else(|| CliError::UnknownService(args.service.clone()))?;
    let bundle = std::fs::read(&args.bundle).map_err(|source| CliError::ReadBundle {
        path: args.bundle.clone(),
        source,
    })?;
    let verified = pipeline::verify_tar(&VerifyJob {
        tar: args.tar.clone(),
        tar_digest: pipeline::hash_file(&args.tar)?,
        bundle,
        image_digest: args.digest.clone(),
        service: service.clone(),
        roots: Arc::new(loaded.roots),
    })?;
    let registry = dsu_registry::Registry::new(loaded.config.registry.clone());
    pipeline::push_tar(&registry, &service.repository, &verified).await?;
    let reference = image_reference(&loaded.config.registry, &service.repository, &args.digest);
    writeln!(out, "{reference}").map_err(CliError::Output)?;
    Ok(())
}

/// `probe`: the exit code, 0 for a 2xx answer and 1 otherwise, with the reason on stderr.
pub async fn probe(args: &ProbeArgs, clock: &dyn Clock) -> Result<u8, CliError> {
    let target = match &args.unix {
        Some(socket) => ProbeTarget::unix(socket, &args.target)?,
        None => ProbeTarget::from_url(&args.target)?,
    };
    let outcome = crate::probe::probe(&target, args.timeout, clock).await;
    if let ProbeOutcome::Unhealthy(failure) = &outcome {
        eprintln!("unhealthy: {failure}");
    }
    Ok(outcome.exit_code())
}
