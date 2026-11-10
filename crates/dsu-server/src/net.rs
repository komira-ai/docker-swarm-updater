//! Name resolution and TCP connection, behind a trait so tests decide what a host name
//! resolves to and where a connection to a resolved address really goes.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;

use crate::clock::BoxFuture;

/// Resolves host names and opens TCP connections.
pub trait Network: Send + Sync {
    /// Every address `host` resolves to.
    fn resolve(&self, host: &str) -> BoxFuture<'_, io::Result<Vec<IpAddr>>>;

    /// A TCP connection to `addr`.
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>>;
}

/// The real network: the system resolver and plain TCP.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNetwork;

impl Network for SystemNetwork {
    fn resolve(&self, host: &str) -> BoxFuture<'_, io::Result<Vec<IpAddr>>> {
        let host = host.to_owned();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }

    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        Box::pin(TcpStream::connect(addr))
    }
}
