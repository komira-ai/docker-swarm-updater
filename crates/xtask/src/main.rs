//! The xtask binary: forwards to [`xtask::main`].

fn main() -> std::process::ExitCode {
    xtask::main(std::env::args().skip(1))
}
