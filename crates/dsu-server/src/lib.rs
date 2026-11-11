//! docker-swarm-updater's HTTP API, state files, deploy runner, fetcher and verbs.

pub mod app;
pub mod auth;
pub mod cli;
pub mod clock;
pub mod deployer;
pub mod fetch;
pub mod handlers;
pub mod net;
pub mod peer;
pub mod pipeline;
pub mod probe;
pub mod runner;
pub mod server;
pub mod startup;
pub mod store;
