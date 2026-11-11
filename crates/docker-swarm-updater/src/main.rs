//! The docker-swarm-updater binary: forwards to [`dsu_server::cli::main`].

fn main() -> std::process::ExitCode {
    dsu_server::cli::main(std::env::args_os())
}
