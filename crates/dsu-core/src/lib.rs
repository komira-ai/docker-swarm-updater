//! The pure core of docker-swarm-updater (docs/design.md section 5): the config and its
//! checks, the claim and peer rules, the request-target and URL rules, the deploy record
//! and its state machine, OCI image-layout reading, the Swarm `UpdateStatus` rule and
//! retention. No I/O, no clock, `BTreeMap` only: every input, time included, is an argument.
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

pub mod api;
pub mod claims;
pub mod config;
pub mod ids;
pub mod oci;
pub mod peer;
pub mod record;
pub mod retention;
pub mod route;
pub mod state;
pub mod swarm;
pub mod url;
