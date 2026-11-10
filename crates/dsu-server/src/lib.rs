//! docker-swarm-updater's HTTP API, state files, deploy runner, fetcher and verbs.

pub mod cli {
    //! The command line: `serve`, `import`, `probe`.

    /// Runs the command line `args` and returns the process exit code.
    pub fn main<I: IntoIterator<Item = std::ffi::OsString>>(args: I) -> std::process::ExitCode {
        let _ = args.into_iter();
        std::process::ExitCode::FAILURE
    }
}
