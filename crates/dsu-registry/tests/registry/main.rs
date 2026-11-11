//! `dsu-registry` against the fake registry of `dsu-testkit` and against scripted registries.
//! One test binary, so the coverage of every function adds up in one place.
#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed unwrap is a failed test"
)]

mod fake;
mod scripted;
