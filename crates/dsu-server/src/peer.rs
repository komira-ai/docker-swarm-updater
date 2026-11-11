//! The uid of the process at the other end of a connection (docs/design.md section 1).

use std::io;

use tokio::net::UnixStream;

/// Reads the peer's uid from an accepted connection. The real implementation asks the kernel;
/// tests substitute the uid they want a request to come from.
pub trait PeerCred: Send + Sync {
    /// The effective uid the peer had when it connected.
    fn uid(&self, stream: &UnixStream) -> io::Result<u32>;
}

/// The kernel's answer, from `SO_PEERCRED`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPeerCred;

impl PeerCred for SystemPeerCred {
    fn uid(&self, stream: &UnixStream) -> io::Result<u32> {
        let credentials = rustix::net::sockopt::socket_peercred(stream)?;
        Ok(credentials.uid.as_raw())
    }
}
