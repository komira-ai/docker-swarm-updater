//! Who is at the other end of a connection (docs/design.md section 1).

use std::fmt;
use std::io;

use tokio::net::UnixStream;

/// What the kernel reports for a connection's peer (`SO_PEERCRED`), as seen from the updater's
/// own namespaces. Only `uid` decides anything (the peer rule); `pid` and `gid` are logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credentials {
    /// The peer's pid in the updater's pid namespace: 0 when the peer runs outside it, as a
    /// client on the host of a containerised updater does.
    pub pid: i32,
    /// The peer's effective uid, mapped into the updater's user namespace.
    pub uid: u32,
    /// The peer's effective gid, mapped into the updater's user namespace.
    pub gid: u32,
}

impl fmt::Display for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uid {} gid {} pid {}", self.uid, self.gid, self.pid)
    }
}

/// Reads the credentials of the peer of an accepted connection. The real implementation asks
/// the kernel; tests substitute the credentials they want a request to come from.
pub trait PeerCred: Send + Sync {
    /// The credentials the peer had when it connected.
    fn credentials(&self, stream: &UnixStream) -> io::Result<Credentials>;
}

/// The kernel's answer, from `SO_PEERCRED`.
///
/// Read through tokio, whose credentials hold any pid. rustix's `UCred` (1.1) holds the pid as a
/// non-zero integer, so the kernel's pid 0 for a peer outside the pid namespace is not a value of
/// that type: it came back as an error ("Success"), and a host-side client was dropped.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPeerCred;

impl PeerCred for SystemPeerCred {
    fn credentials(&self, stream: &UnixStream) -> io::Result<Credentials> {
        let credentials = stream.peer_cred()?;
        Ok(Credentials {
            pid: credentials.pid().unwrap_or(0),
            uid: credentials.uid(),
            gid: credentials.gid(),
        })
    }
}
