//! `cargo xtask release check-output --expect <line> -- <program> [<arg>...]`: runs the
//! program with its arguments and passes when it exits 0 and its standard output is exactly
//! `<line>` and a line break (one line, nothing else). The release workflow checks with it
//! that the built binary, and the image's entrypoint, print the release version.

use std::process::Command;

use super::{USAGE, flags, required};
use crate::Report;

pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    let Some(split) = args.iter().position(|a| a == "--") else {
        return Err(format!("check-output needs `-- <program>`; {USAGE}"));
    };
    let flags = flags(&args[..split], &["--expect"])?;
    let expect = required(&flags, "--expect")?;
    let Some((program, program_args)) = args[split + 1..].split_first() else {
        return Err(format!("check-output needs a program after `--`; {USAGE}"));
    };
    let output = Command::new(program)
        .args(program_args)
        .output()
        .map_err(|e| format!("running {program}: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let wanted = format!("{expect}\n");
    let passed = output.status.success() && stdout == wanted;
    let text = if passed {
        format!("check-output: {program} printed {expect:?}\n")
    } else {
        format!(
            "check-output: {program} exited with {} and printed {stdout:?}, not {wanted:?}\n",
            output.status
        )
    };
    Ok(Report { text, passed })
}
