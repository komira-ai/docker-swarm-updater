//! Fakes shared by the integration tests: a clock that moves only when told, a network that
//! maps host names to chosen addresses and dials the fake release server, and a disk that
//! reports a chosen amount of free space or fails at a chosen chunk.
#![allow(
    dead_code,
    reason = "each integration test crate uses a subset of the fakes"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test support: a failed unwrap is a failed test"
)]

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dsu_server::clock::{BoxFuture, Clock};
use dsu_server::fetch::{Disk, SystemDisk};
use dsu_server::net::Network;
use tokio::fs::File;
use tokio::net::TcpStream;
use tokio::sync::watch;

/// The documentation address the fake resolver gives to the allowed host names.
pub const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

struct ClockState {
    start: jiff::Timestamp,
    elapsed: watch::Sender<Duration>,
    pending: watch::Sender<usize>,
}

/// Counts a deadline as pending from its creation until the future is dropped.
struct PendingGuard(Arc<ClockState>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.pending.send_modify(|n| *n -= 1);
    }
}

/// A clock with virtual time. `sleep` advances time and returns at once; a `deadline` resolves
/// only when virtual time reaches it, by a `sleep` or by [`FakeClock::advance`].
#[derive(Clone)]
pub struct FakeClock(Arc<ClockState>);

impl FakeClock {
    pub fn new() -> Self {
        let start: jiff::Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
        Self(Arc::new(ClockState {
            start,
            elapsed: watch::channel(Duration::ZERO).0,
            pending: watch::channel(0).0,
        }))
    }

    /// Moves virtual time forward.
    pub fn advance(&self, d: Duration) {
        self.0.elapsed.send_modify(|e| *e += d);
    }

    /// Resolves once at least one deadline is pending.
    pub async fn wait_pending(&self) {
        self.0
            .pending
            .subscribe()
            .wait_for(|n| *n > 0)
            .await
            .unwrap();
    }

    /// Drives `work`, advancing time by `step` each time a deadline is pending, until `work`
    /// finishes. Time moves only in answer to a pending deadline, never by the real clock.
    pub async fn pump<T>(&self, step: Duration, work: impl Future<Output = T>) -> T {
        let mut work = pin!(work);
        loop {
            tokio::select! {
                out = &mut work => return out,
                () = self.wait_pending() => {
                    self.advance(step);
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> jiff::Timestamp {
        let elapsed = *self.0.elapsed.borrow();
        self.0
            .start
            .checked_add(jiff::SignedDuration::try_from(elapsed).unwrap())
            .unwrap()
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()> {
        self.advance(d);
        Box::pin(std::future::ready(()))
    }

    fn deadline(&self, d: Duration) -> BoxFuture<'_, ()> {
        let target = *self.0.elapsed.borrow() + d;
        self.0.pending.send_modify(|n| *n += 1);
        let guard = PendingGuard(self.0.clone());
        let mut elapsed = self.0.elapsed.subscribe();
        Box::pin(async move {
            let _guard = guard;
            elapsed.wait_for(|e| *e >= target).await.unwrap();
        })
    }
}

/// What the fake network does when asked to connect.
#[derive(Clone, Copy)]
pub enum ConnectMode {
    /// `SERVER_IP:443` reaches the fake server; any other address is refused.
    Normal,
    /// Every connect waits forever.
    Hang,
}

/// A network with chosen DNS answers whose only reachable address is `SERVER_IP:443`, which
/// leads to the fake release server's loopback port.
pub struct FakeNetwork {
    hosts: Mutex<BTreeMap<String, Vec<IpAddr>>>,
    server_port: u16,
    mode: ConnectMode,
    resolved: Mutex<Vec<String>>,
    connects: Mutex<Vec<SocketAddr>>,
}

impl FakeNetwork {
    pub fn new(server_port: u16) -> Self {
        Self {
            hosts: Mutex::new(BTreeMap::new()),
            server_port,
            mode: ConnectMode::Normal,
            resolved: Mutex::new(Vec::new()),
            connects: Mutex::new(Vec::new()),
        }
    }

    /// Sets how connects behave.
    pub fn mode(mut self, mode: ConnectMode) -> Self {
        self.mode = mode;
        self
    }

    /// Makes `host` resolve to `addrs`.
    pub fn host(self, host: &str, addrs: &[&str]) -> Self {
        let addrs = addrs.iter().map(|a| a.parse().unwrap()).collect();
        self.hosts.lock().unwrap().insert(host.to_owned(), addrs);
        self
    }

    /// The default answers: the allowed host names resolve to `SERVER_IP`.
    pub fn allowed(self) -> Self {
        self.host("github.com", &["203.0.113.10"])
            .host("objects.githubusercontent.com", &["203.0.113.10"])
            .host("release-assets.githubusercontent.com", &["203.0.113.10"])
    }

    /// Every host looked up, in order.
    pub fn resolved(&self) -> Vec<String> {
        self.resolved.lock().unwrap().clone()
    }

    /// Every address a connection was attempted to, in order.
    pub fn connects(&self) -> Vec<SocketAddr> {
        self.connects.lock().unwrap().clone()
    }
}

impl Network for FakeNetwork {
    fn resolve(&self, host: &str) -> BoxFuture<'_, io::Result<Vec<IpAddr>>> {
        self.resolved.lock().unwrap().push(host.to_owned());
        let answer = self
            .hosts
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"));
        Box::pin(std::future::ready(answer))
    }

    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<TcpStream>> {
        self.connects.lock().unwrap().push(addr);
        let mode = self.mode;
        let port = self.server_port;
        Box::pin(async move {
            if matches!(mode, ConnectMode::Hang) {
                std::future::pending::<()>().await;
            }
            if addr == SocketAddr::new(SERVER_IP, 443) {
                TcpStream::connect(("127.0.0.1", port)).await
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "unreachable address",
                ))
            }
        })
    }
}

/// A disk that reports `free` bytes (less what was written through it) and fails the
/// `fail_at`-th chunk written (counting from 1) when set. Writes go to the real file.
pub struct FakeDisk {
    free: Mutex<u64>,
    fail_at: Option<usize>,
    chunks: Mutex<usize>,
}

impl FakeDisk {
    pub fn new(free: u64) -> Self {
        Self {
            free: Mutex::new(free),
            fail_at: None,
            chunks: Mutex::new(0),
        }
    }

    pub fn failing_at(mut self, chunk: usize) -> Self {
        self.fail_at = Some(chunk);
        self
    }

    /// Chunks written so far.
    pub fn chunks(&self) -> usize {
        *self.chunks.lock().unwrap()
    }
}

impl Disk for FakeDisk {
    fn free_bytes(&self, _dir: &Path) -> io::Result<u64> {
        Ok(*self.free.lock().unwrap())
    }

    fn write<'a>(&'a self, file: &'a mut File, chunk: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        let number = {
            let mut chunks = self.chunks.lock().unwrap();
            *chunks += 1;
            *chunks
        };
        if Some(number) == self.fail_at {
            return Box::pin(std::future::ready(Err(io::Error::other("the disk failed"))));
        }
        let len = chunk.len() as u64;
        {
            let mut free = self.free.lock().unwrap();
            *free = free.saturating_sub(len);
        }
        SystemDisk.write(file, chunk)
    }
}
