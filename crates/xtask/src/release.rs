//! `cargo xtask release <verb>`: the steps of `.github/workflows/artifacts.yml` that are more
//! than one command, so the workflow runs one named command per step and the logic has tests.
//!
//! - `version --commit-count <n> [--root <dir>]` prints `version=<major>.<minor>.<n>`, the
//!   workspace version's major and minor with the number of commits on `main` as the patch: a
//!   commit always gets the same version, and a later commit a higher one.
//! - `stamp --version <x.y.z> [--root <dir>]` writes that version into `Cargo.toml`
//!   (`[workspace.package]`) and into `Cargo.lock` for every workspace crate, so the binaries
//!   print it and `--locked` still holds.
//! - `check-static --binary <file>` refuses a binary that needs a program interpreter (a
//!   dynamic loader): the released binaries run on any Linux of their architecture.
//! - `image ...` writes the container image tar, see [`image`].
//! - `sums --dir <dir> --version <v>` refuses a directory whose files are not exactly the
//!   release's [`assets`], writes `SHA256SUMS` over them and prints `sha256=<its SHA-256>`.

pub mod image;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::Report;

const USAGE: &str = "usage: xtask release version --commit-count <n> [--root <dir>] | stamp --version <x.y.z> [--root <dir>] | check-static --binary <file> | image --binary <file> --version <v> --commit <40 hex> --created <unix seconds> --platform linux/amd64|linux/arm64 --out <file> | sums --dir <dir> --version <v>";

/// The program and image name every asset starts with.
pub const NAME: &str = "docker-swarm-updater";

/// The release platforms and their OCI platform: `linux-x86_64` is `linux/amd64`,
/// `linux-arm64` is `linux/arm64`.
pub const PLATFORMS: [(&str, &str); 2] = [("linux-x86_64", "amd64"), ("linux-arm64", "arm64")];

/// The files of release `version`, sorted: for each platform the static binary
/// `docker-swarm-updater-<version>-<platform>` and its image `<that>.image.tar`.
pub fn assets(version: &str) -> Vec<String> {
    let mut names: Vec<String> = PLATFORMS
        .iter()
        .flat_map(|(platform, _)| {
            let binary = format!("{NAME}-{version}-{platform}");
            [format!("{binary}.image.tar"), binary]
        })
        .collect();
    names.sort();
    names
}

/// Runs `release` with `args` (after the word `release`).
pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(USAGE.into());
    };
    match verb.as_str() {
        "version" => {
            let flags = flags(rest, &["--commit-count", "--root"])?;
            let count = required(&flags, "--commit-count")?;
            let root = root(&flags);
            Ok(passed(format!(
                "version={}\n",
                version(&read(&root.join("Cargo.toml"))?, count)?
            )))
        }
        "stamp" => {
            let flags = flags(rest, &["--version", "--root"])?;
            let version = required(&flags, "--version")?;
            stamp(&root(&flags), version)?;
            Ok(passed(format!("stamp: {version}\n")))
        }
        "check-static" => {
            let flags = flags(rest, &["--binary"])?;
            let binary = PathBuf::from(required(&flags, "--binary")?);
            let bytes =
                std::fs::read(&binary).map_err(|e| format!("reading {}: {e}", binary.display()))?;
            Ok(match needs_interpreter(&bytes)? {
                false => passed(format!("check-static: {} is static\n", binary.display())),
                true => Report {
                    text: format!(
                        "check-static: {} needs a program interpreter\n",
                        binary.display()
                    ),
                    passed: false,
                },
            })
        }
        "image" => image::run(rest),
        "sums" => {
            let flags = flags(rest, &["--dir", "--version"])?;
            let dir = PathBuf::from(required(&flags, "--dir")?);
            sums(&dir, required(&flags, "--version")?)
        }
        _ => Err(USAGE.into()),
    }
}

fn passed(text: String) -> Report {
    Report { text, passed: true }
}

/// `--flag value` pairs, each flag one of `known` and given once.
pub(crate) fn flags<'a>(
    args: &'a [String],
    known: &[&str],
) -> Result<BTreeMap<&'a str, &'a str>, String> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if !known.contains(&flag.as_str()) {
            return Err(format!("unknown flag {flag}; {USAGE}"));
        }
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if out.insert(flag.as_str(), value.as_str()).is_some() {
            return Err(format!("{flag} is given twice"));
        }
    }
    Ok(out)
}

pub(crate) fn required<'a>(flags: &BTreeMap<&str, &'a str>, flag: &str) -> Result<&'a str, String> {
    flags
        .get(flag)
        .copied()
        .ok_or_else(|| format!("{flag} is required"))
}

fn root(flags: &BTreeMap<&str, &str>) -> PathBuf {
    PathBuf::from(flags.get("--root").copied().unwrap_or("."))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

#[derive(serde::Deserialize)]
struct RootManifest {
    workspace: Workspace,
}

#[derive(serde::Deserialize)]
struct Workspace {
    package: WorkspacePackage,
}

#[derive(serde::Deserialize)]
struct WorkspacePackage {
    version: String,
}

/// The version `X.Y.Z` of the workspace manifest `cargo_toml`.
fn workspace_version(cargo_toml: &str) -> Result<String, String> {
    let manifest: RootManifest =
        toml::from_str(cargo_toml).map_err(|e| format!("Cargo.toml: {e}"))?;
    let version = manifest.workspace.package.version;
    check_version(&version)?;
    Ok(version)
}

/// `X.Y.Z`, each a decimal number.
fn check_version(version: &str) -> Result<(), String> {
    let parts: Vec<&str> = version.split('.').collect();
    let numeric = |p: &&str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if parts.len() == 3 && parts.iter().all(numeric) {
        Ok(())
    } else {
        Err(format!("version {version:?} is not X.Y.Z"))
    }
}

/// The release version: the workspace's major and minor, `commit_count` as the patch.
fn version(cargo_toml: &str, commit_count: &str) -> Result<String, String> {
    let count: u64 = commit_count
        .parse()
        .map_err(|_| format!("--commit-count {commit_count:?} is not a number"))?;
    let current = workspace_version(cargo_toml)?;
    let (major_minor, _) = current.rsplit_once('.').unwrap_or_default();
    Ok(format!("{major_minor}.{count}"))
}

/// Writes `version` into `root/Cargo.toml` and `root/Cargo.lock`.
fn stamp(root: &Path, version: &str) -> Result<(), String> {
    check_version(version)?;
    let toml_path = root.join("Cargo.toml");
    let lock_path = root.join("Cargo.lock");
    let cargo_toml = read(&toml_path)?;
    let lock = read(&lock_path)?;
    let old = workspace_version(&cargo_toml)?;
    let new_toml = stamp_manifest(&cargo_toml, &old, version)?;
    let new_lock = stamp_lock(&lock, &old, version)?;
    std::fs::write(&toml_path, new_toml)
        .map_err(|e| format!("writing {}: {e}", toml_path.display()))?;
    std::fs::write(&lock_path, new_lock)
        .map_err(|e| format!("writing {}: {e}", lock_path.display()))
}

/// `cargo_toml` with the `version` line of `[workspace.package]` set to `new`.
fn stamp_manifest(cargo_toml: &str, old: &str, new: &str) -> Result<String, String> {
    let wanted = format!("version = \"{old}\"");
    let mut in_section = false;
    let mut done = false;
    let mut out = String::with_capacity(cargo_toml.len());
    for line in cargo_toml.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == "[workspace.package]";
        }
        if in_section && !done && trimmed == wanted {
            out.push_str(&line.replacen(&wanted, &format!("version = \"{new}\""), 1));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    if done {
        Ok(out)
    } else {
        Err(format!(
            "Cargo.toml: no `{wanted}` line in [workspace.package]"
        ))
    }
}

/// `lock` with every workspace package's version (a `[[package]]` with no `source`, at `old`)
/// set to `new`. A lock with no such package is refused.
fn stamp_lock(lock: &str, old: &str, new: &str) -> Result<String, String> {
    let wanted = format!("version = \"{old}\"");
    let mut out = String::with_capacity(lock.len());
    let mut stamped = 0;
    let mut blocks = lock.split("\n[[package]]\n");
    // The text before the first package (the header) is kept as it is.
    out.push_str(blocks.next().unwrap_or_default());
    for block in blocks {
        out.push_str("\n[[package]]\n");
        let member = !block
            .lines()
            .take_while(|l| !l.is_empty())
            .any(|l| l.starts_with("source = "));
        let at_old = block.lines().any(|l| l == wanted);
        if member && at_old {
            out.push_str(&block.replacen(&wanted, &format!("version = \"{new}\""), 1));
            stamped += 1;
        } else {
            out.push_str(block);
        }
    }
    if stamped == 0 {
        return Err(format!("Cargo.lock: no workspace package at {old}"));
    }
    Ok(out)
}

/// Whether the ELF executable `bytes` has a `PT_INTERP` program header, that is, needs a
/// dynamic loader to start. A file that is not a little-endian 64-bit ELF is an error.
fn needs_interpreter(bytes: &[u8]) -> Result<bool, String> {
    const PT_INTERP: u32 = 3;
    if bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err("not an ELF file".into());
    }
    if bytes.get(4..6) != Some([2u8, 1].as_slice()) {
        return Err("not a little-endian 64-bit ELF file".into());
    }
    let truncated = || "the ELF header or a program header is truncated".to_owned();
    // e_phoff, e_phentsize and e_phnum of the ELF64 header.
    let phoff = le::<8>(bytes, 0x20)
        .map(u64::from_le_bytes)
        .ok_or_else(truncated)?;
    let sizes = le::<4>(bytes, 0x36).ok_or_else(truncated)?;
    let phentsize = usize::from(u16::from_le_bytes([sizes[0], sizes[1]]));
    let phnum = usize::from(u16::from_le_bytes([sizes[2], sizes[3]]));
    // An offset past the address space is past the file too.
    let phoff = usize::try_from(phoff).unwrap_or(usize::MAX);
    for i in 0..phnum {
        // At most 65535 * 65535 past `phoff`: no overflow before the saturation.
        let at = phoff.saturating_add(i * phentsize);
        let p_type = le::<4>(bytes, at)
            .map(u32::from_le_bytes)
            .ok_or_else(truncated)?;
        if p_type == PT_INTERP {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The `N` bytes of `bytes` at `at`, if the file has them.
fn le<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes
        .get(at..)
        .and_then(|rest| rest.get(..N))
        .and_then(|b| b.try_into().ok())
}

/// Checks that `dir` holds exactly the [`assets`] of `version`, writes `SHA256SUMS` in
/// `sha256sum` format, and reports `sha256=<SHA-256 of SHA256SUMS>`.
fn sums(dir: &Path, version: &str) -> Result<Report, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    // An entry that cannot be read is left out: the set then differs from the release's and
    // the check fails.
    let mut found: Vec<String> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    let expected = assets(version);
    if found != expected {
        return Ok(Report {
            text: format!(
                "sums: {} holds {found:?}, the release is {expected:?}\n",
                dir.display()
            ),
            passed: false,
        });
    }
    let mut text = String::new();
    for name in &expected {
        let path = dir.join(name);
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let _ = writeln!(text, "{}  {name}", hex::encode(Sha256::digest(&bytes)));
    }
    let path = dir.join("SHA256SUMS");
    std::fs::write(&path, &text).map_err(|e| format!("writing {}: {e}", path.display()))?;
    Ok(passed(format!(
        "sha256={}\n",
        hex::encode(Sha256::digest(text.as_bytes()))
    )))
}

#[cfg(test)]
mod tests;
