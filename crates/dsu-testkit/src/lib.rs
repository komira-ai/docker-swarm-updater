//! Test support for docker-swarm-updater: a test Sigstore signing chain, OCI tars, and fake
//! Docker, registry and release servers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test support: a failed unwrap is a failed test"
)]

pub mod docker;
pub mod mint;
pub mod oci;
pub mod registry;
pub mod release;
