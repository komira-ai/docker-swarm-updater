//! The dsu-deploy binary: forwards to [`dsu_deploy::main`].

fn main() -> std::process::ExitCode {
    dsu_deploy::main(std::env::args_os())
}
