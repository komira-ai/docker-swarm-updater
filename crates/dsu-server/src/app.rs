//! The running updater's shared context: the config, the collaborators every request and
//! every deploy uses, and the state.

use std::path::PathBuf;
use std::sync::Arc;

use dsu_core::config::{Config, ServiceConfig};
use dsu_core::ids::{Digest, ServiceName};
use dsu_docker::{DockerClient, DockerError, ServiceView, TaskView};
use dsu_registry::Registry;
use dsu_verify::TrustedRoots;
use rustls::RootCertStore;

use crate::clock::Clock;
use crate::deployer::Deployer;
use crate::fetch::{Disk, Fetcher};
use crate::net::Network;
use crate::peer::PeerCred;
use crate::startup::StartError;
use crate::store::Store;

/// Everything [`App::start`] is made from.
pub struct Params {
    /// The checked config.
    pub config: Config,
    /// The trusted roots named by the config.
    pub roots: TrustedRoots,
    /// `--state-dir`.
    pub state_dir: PathBuf,
    /// `--docker`: the Docker socket.
    pub docker_socket: PathBuf,
    /// `--proxy-uid`, never 0.
    pub proxy_uid: u32,
    /// `--allow-local-operator`.
    pub allow_local_operator: bool,
    /// The host name the updater's own container is looked up by (its task's hostname).
    pub hostname: String,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// How the uid of a connection's peer is read.
    pub peer_cred: Arc<dyn PeerCred>,
    /// Name resolution and TCP connections of downloads.
    pub network: Arc<dyn Network>,
    /// The disk downloads are written to.
    pub disk: Arc<dyn Disk>,
    /// The roots TLS connections of downloads trust.
    pub tls_roots: RootCertStore,
}

/// The shared context of the HTTP server and the deploy runner.
pub struct App {
    /// The checked config.
    pub config: Config,
    /// The trusted roots.
    pub roots: Arc<TrustedRoots>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// How the uid of a connection's peer is read.
    pub peer_cred: Arc<dyn PeerCred>,
    /// The Docker Engine API.
    pub docker: DockerClient,
    /// The registry the updater pushes to.
    pub registry: Registry,
    /// The state directory.
    pub store: Store,
    /// The downloader of release files.
    pub fetcher: Fetcher,
    /// The in-memory lock of one deploy per service.
    pub deployer: Deployer,
    /// `--proxy-uid`.
    pub proxy_uid: u32,
    /// `--allow-local-operator`.
    pub allow_local_operator: bool,
}

impl App {
    /// Opens the state directory, builds the downloader and reads the updater's own Swarm
    /// service name from its container (section 3.6, self-update).
    pub async fn start(params: Params) -> Result<Arc<App>, StartError> {
        let now = params.clock.now();
        let store = Store::open(&params.state_dir, now).await?;
        let fetcher = Fetcher::new(
            params.network,
            Arc::clone(&params.clock),
            params.disk,
            params.tls_roots,
            params.config.redirect_hosts.clone(),
        )
        .map_err(StartError::Downloader)?;
        let docker = DockerClient::new(params.docker_socket);
        let own_service = docker.own_service_name(&params.hostname).await?;
        let registry = Registry::new(params.config.registry.clone());
        Ok(Arc::new(App {
            config: params.config,
            roots: Arc::new(params.roots),
            clock: params.clock,
            peer_cred: params.peer_cred,
            docker,
            registry,
            store,
            fetcher,
            deployer: Deployer::new(own_service),
            proxy_uid: params.proxy_uid,
            allow_local_operator: params.allow_local_operator,
        }))
    }

    /// The configured service called `name`.
    pub fn service(&self, name: &ServiceName) -> Option<&ServiceConfig> {
        self.config.service(name)
    }

    /// The Swarm service `swarm_service` and its tasks that should be running; `None` when
    /// Swarm has no such service.
    pub async fn swarm_tasks(
        &self,
        swarm_service: &str,
    ) -> Result<Option<(ServiceView, Vec<TaskView>)>, DockerError> {
        let view = match self.docker.inspect_service(swarm_service).await {
            Ok(view) => view,
            Err(DockerError::ServiceNotFound { .. }) => return Ok(None),
            Err(other) => return Err(other),
        };
        let tasks = self.docker.running_tasks(&view.id).await?;
        Ok(Some((view, tasks)))
    }
}

/// The reference a service's image is deployed under: `<registry>/<repository>@<digest>`.
pub fn image_reference(registry: &str, repository: &str, digest: &Digest) -> String {
    format!("{registry}/{repository}@{digest}")
}
