//! The errors of the registry client. The server reports every one of them as the token
//! `registry_failed`; the variants say what failed.

use std::io;
use std::path::PathBuf;

use dsu_core::ids::Digest;
use http::{Method, StatusCode};

/// An error and its causes, joined with `: `.
fn describe(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(inner) = cause {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        cause = inner.source();
    }
    text
}

/// A failed registry operation.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The repository name does not follow the distribution name grammar.
    #[error("repository name {name:?} is not valid")]
    InvalidRepository {
        /// The refused name.
        name: String,
    },
    /// The TCP connection to the registry failed.
    #[error("cannot connect to registry {addr}: {source}")]
    Connect {
        /// The configured `host:port`.
        addr: String,
        /// The socket error.
        source: io::Error,
    },
    /// The request could not be formed (a header value or the target is not valid HTTP).
    #[error("cannot form the request {method} {path}: {source}")]
    Request {
        /// The request method.
        method: Method,
        /// The request target.
        path: String,
        /// The HTTP error.
        source: http::Error,
    },
    /// The HTTP exchange failed after the connection was made (the registry hung up, or a
    /// blob's file ended before its range did).
    #[error("{method} {path} on registry {addr} failed: {}", describe(.source))]
    Transport {
        /// The configured `host:port`.
        addr: String,
        /// The request method.
        method: Method,
        /// The request target.
        path: String,
        /// The HTTP error.
        source: hyper::Error,
    },
    /// The registry answered a status the operation does not accept.
    #[error("{method} {path} answered {status}")]
    Status {
        /// The request method.
        method: Method,
        /// The request target.
        path: String,
        /// The answered status.
        status: StatusCode,
    },
    /// The registry's upload `Location` is missing or is not a path on the registry.
    #[error("the registry's upload location {location:?} is not usable")]
    BadLocation {
        /// The header value, empty when the header is missing or not text.
        location: String,
    },
    /// A blob's file could not be opened or positioned at the start of its range.
    #[error("cannot read blob {digest} from {path}: {source}")]
    BlobRead {
        /// The blob's digest.
        digest: Digest,
        /// The file the blob is read from.
        path: PathBuf,
        /// The file error.
        source: io::Error,
    },
    /// After the manifest was written, the registry did not answer the pushed digest.
    #[error("registry answered {answered:?} for manifest {expected}")]
    ManifestDigest {
        /// The digest that was pushed.
        expected: Digest,
        /// What `Docker-Content-Digest` said, `None` when it was missing or not text.
        answered: Option<String>,
    },
}
