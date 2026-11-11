//! What must hold before the updater serves or imports anything: the config file and its
//! checks (docs/design.md section 2.3), the trusted-root file, the CA file, and the refusals
//! of the flags. A refusal names the key or flag.

use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use dsu_core::config::{Config, ConfigError};
use dsu_docker::DockerError;
use dsu_verify::{RootError, TrustedRoots};

use crate::fetch::FetchError;
use crate::store::StoreError;

/// A start that is refused, or that fails.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// `--proxy-uid 0`: root is the operator, never the proxy.
    #[error(
        "flag `--proxy-uid` is refused: 0 is root, which is the local operator and never the proxy"
    )]
    ProxyUidZero,
    /// The config file cannot be read.
    #[error("flag `--config`: cannot read {path}: {source}")]
    ConfigRead {
        /// The path given.
        path: PathBuf,
        /// The operating system error.
        source: std::io::Error,
    },
    /// The config breaks a rule of section 2.3.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// `trusted_root` is not a file the updater may trust.
    #[error("config key `trusted_root` ({path}) is refused: {reason}")]
    TrustedRootFile {
        /// The configured path.
        path: PathBuf,
        /// The rule it breaks.
        reason: String,
    },
    /// `trusted_root` is a file the verifier cannot use.
    #[error("config key `trusted_root` ({path}) is refused: {source}")]
    TrustedRootContent {
        /// The configured path.
        path: PathBuf,
        /// What the verifier said.
        source: RootError,
    },
    /// `--ca-file` holds no usable certificate.
    #[error("flag `--ca-file` ({path}): {source}")]
    CaFile {
        /// The path given.
        path: PathBuf,
        /// What is wrong with it.
        source: FetchError,
    },
    /// The downloader cannot be set up.
    #[error("cannot set up the downloader: {0}")]
    Downloader(#[source] FetchError),
    /// The state directory cannot be used.
    #[error("flag `--state-dir`: {0}")]
    State(#[from] StoreError),
    /// The Docker API did not answer at start.
    #[error("flag `--docker`: {0}")]
    Docker(#[from] DockerError),
    /// The directory the socket lives in is open to every user.
    #[error(
        "flag `--socket` ({path}): the directory is accessible to other users (mode {mode:04o})"
    )]
    SocketDirOpen {
        /// The directory.
        path: PathBuf,
        /// Its mode.
        mode: u32,
    },
    /// The path of the socket is taken by something that is not a socket.
    #[error("flag `--socket` ({path}): the path exists and is not a socket")]
    SocketPathTaken {
        /// The path.
        path: PathBuf,
    },
    /// A file system call for the socket failed.
    #[error("flag `{flag}` ({path}): cannot {action}: {source}")]
    Socket {
        /// The flag the path or group came from.
        flag: &'static str,
        /// What was being done.
        action: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The operating system error.
        source: std::io::Error,
    },
    /// The signal handlers for a clean stop could not be installed.
    #[error("cannot install the signal handlers: {0}")]
    Signals(#[source] std::io::Error),
}

/// The config and the trusted roots, loaded and checked.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed config.
    pub config: Config,
    /// The trusted roots of `trusted_root`.
    pub roots: TrustedRoots,
}

/// The rule the trusted-root file breaks, if it breaks one: it must be a regular file, owned
/// by uid 0 or by `effective_uid`, and writable by neither group nor other.
pub fn trusted_root_problem(
    is_file: bool,
    owner: u32,
    mode: u32,
    effective_uid: u32,
) -> Option<&'static str> {
    if !is_file {
        Some("it is not a regular file")
    } else if owner != 0 && owner != effective_uid {
        Some("it is owned by neither root nor the updater's user")
    } else if mode & 0o022 != 0 {
        Some("it is writable by group or other")
    } else {
        None
    }
}

/// The bytes of the trusted-root file `path`. The file is opened once: what is checked is
/// what is read.
fn read_trusted_root(path: &Path, effective_uid: u32) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if let Some(reason) =
        trusted_root_problem(meta.is_file(), meta.uid(), meta.mode(), effective_uid)
    {
        return Err(std::io::Error::other(reason));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads `path` as the config file, runs the checks of section 2.3 and loads the trusted
/// roots it names.
pub fn load_config(path: &Path) -> Result<Loaded, StartError> {
    let text = std::fs::read_to_string(path).map_err(|source| StartError::ConfigRead {
        path: path.to_owned(),
        source,
    })?;
    let config = Config::parse(&text)?;
    let root_path = &config.trusted_root;
    let effective_uid = rustix::process::geteuid().as_raw();
    let bytes =
        read_trusted_root(root_path, effective_uid).map_err(|e| StartError::TrustedRootFile {
            path: root_path.clone(),
            reason: e.to_string(),
        })?;
    let roots = TrustedRoots::parse(&bytes).map_err(|source| StartError::TrustedRootContent {
        path: root_path.clone(),
        source,
    })?;
    Ok(Loaded { config, roots })
}
