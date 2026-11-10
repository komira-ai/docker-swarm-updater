//! Every integration test of dsu-server, in one binary (so coverage is measured over one
//! run): the fetcher, the probe, the HTTP API and its auth, the state store, the pipeline,
//! the command line and the start checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: a failed unwrap is a failed test"
)]

mod api;
mod cli;
mod config;
mod deploys;
mod fetch;
mod harness;
mod pipeline;
mod probe;
mod socket;
mod store;
mod support;
