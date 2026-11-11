//! Repository checks. `cargo xtask coverage --lcov <file> [--root <dir>] [--summary <file>]`
//! reads an lcov report made with branch coverage and holds every workspace crate to the
//! floors in its own `Cargo.toml` (`[package.metadata.coverage]`, `lines` and `branches`,
//! percent). A floor below 99, a crate without floors, a crate with nothing measured, or a
//! crate under its floors fails the check.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The lowest floor a crate may declare.
const MIN_FLOOR: f64 = 99.0;

/// Runs the command line `args` (without the program name) and returns the exit code: 0 when
/// every crate meets its floors, 1 when one does not, 2 when the command line or an input is wrong.
pub fn main(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    match run(&args) {
        Ok(report) => {
            print!("{}", report.text);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::from(2)
        }
    }
}

/// The outcome of one check: the table it printed and whether every crate passed.
#[derive(Debug)]
struct Report {
    text: String,
    passed: bool,
}

/// Parsed command-line options of `coverage`.
#[derive(Debug, PartialEq)]
struct Options {
    lcov: PathBuf,
    root: PathBuf,
    summary: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    if it.next().map(String::as_str) != Some("coverage") {
        return Err("usage: xtask coverage --lcov <file> [--root <dir>] [--summary <file>]".into());
    }
    let (mut lcov, mut root, mut summary) = (None, PathBuf::from("."), None);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--lcov" => lcov = Some(PathBuf::from(value)),
            "--root" => root = PathBuf::from(value),
            "--summary" => summary = Some(PathBuf::from(value)),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    let lcov = lcov.ok_or("--lcov is required")?;
    Ok(Options {
        lcov,
        root,
        summary,
    })
}

fn run(args: &[String]) -> Result<Report, String> {
    let opts = parse_args(args)?;
    let lcov = std::fs::read_to_string(&opts.lcov)
        .map_err(|e| format!("reading {}: {e}", opts.lcov.display()))?;
    let measured = parse_lcov(&lcov, &opts.root)?;
    let floors = read_floors(&opts.root)?;
    let report = check(&floors, &measured);
    if let Some(path) = &opts.summary {
        let mut body = std::fs::read_to_string(path).unwrap_or_default();
        body.push_str(&report.text);
        std::fs::write(path, body).map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(report)
}

/// Lines and branches of one crate: (hit, total) each.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct Counts {
    lines: (u64, u64),
    branches: (u64, u64),
}

/// A crate's declared floors, in percent.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Floors {
    lines: f64,
    branches: f64,
}

/// Sums an lcov report per crate: a source file belongs to crate `<name>` when its path,
/// relative to `root`, starts with `crates/<name>/`. Files outside `crates/` are refused, so
/// a report from another tree cannot pass.
fn parse_lcov(text: &str, root: &Path) -> Result<BTreeMap<String, Counts>, String> {
    let mut out: BTreeMap<String, Counts> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("SF:") {
            let rel = Path::new(path)
                .strip_prefix(root)
                .unwrap_or(Path::new(path));
            let mut parts = rel.components().map(|c| c.as_os_str().to_string_lossy());
            match (parts.next().as_deref(), parts.next()) {
                (Some("crates"), Some(name)) => current = Some(name.into_owned()),
                _ => return Err(format!("source file outside crates/: {path}")),
            }
            continue;
        }
        let Some(name) = &current else { continue };
        let counts = out.entry(name.clone()).or_default();
        if let Some(rest) = line.strip_prefix("DA:") {
            let hits = rest
                .split(',')
                .nth(1)
                .ok_or_else(|| format!("bad line: {line}"))?;
            counts.lines.1 += 1;
            counts.lines.0 += u64::from(hits.trim() != "0");
        } else if let Some(rest) = line.strip_prefix("BRDA:") {
            let taken = rest
                .split(',')
                .nth(3)
                .ok_or_else(|| format!("bad line: {line}"))?;
            counts.branches.1 += 1;
            counts.branches.0 += u64::from(!matches!(taken.trim(), "-" | "0"));
        } else if line == "end_of_record" {
            current = None;
        }
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
struct Manifest {
    package: Package,
}

#[derive(serde::Deserialize)]
struct Package {
    metadata: Option<Metadata>,
}

#[derive(serde::Deserialize)]
struct Metadata {
    coverage: Option<CoverageFloors>,
}

#[derive(serde::Deserialize)]
struct CoverageFloors {
    lines: f64,
    branches: f64,
}

/// Reads the floors of every crate under `root/crates`. A crate without floors, or with a
/// floor below [`MIN_FLOOR`], is an error.
fn read_floors(root: &Path) -> Result<BTreeMap<String, Floors>, String> {
    let dir = root.join("crates");
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    let mut out = BTreeMap::new();
    // An entry that cannot be read is skipped: its crate then has no floors, and a crate
    // measured without floors fails the check.
    for entry in entries.flatten() {
        let path = entry.path();
        let manifest = path.join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parsed: Manifest =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", manifest.display()))?;
        let floors = parsed
            .package
            .metadata
            .and_then(|m| m.coverage)
            .ok_or_else(|| format!("{name}: no [package.metadata.coverage] floors"))?;
        if floors.lines < MIN_FLOOR || floors.branches < MIN_FLOOR {
            return Err(format!("{name}: a coverage floor is below {MIN_FLOOR}"));
        }
        out.insert(
            name,
            Floors {
                lines: floors.lines,
                branches: floors.branches,
            },
        );
    }
    Ok(out)
}

fn percent((hit, total): (u64, u64)) -> f64 {
    if total == 0 {
        100.0
    } else {
        hit as f64 * 100.0 / total as f64
    }
}

/// Compares measured coverage with each crate's floors and renders a Markdown table.
fn check(floors: &BTreeMap<String, Floors>, measured: &BTreeMap<String, Counts>) -> Report {
    let mut text =
        String::from("| crate | lines | branches | floors | result |\n|---|---|---|---|---|\n");
    let mut passed = true;
    for (name, floor) in floors {
        let (cells, ok) = match measured.get(name) {
            None => ("nothing measured | - ".to_owned(), false),
            Some(c) => {
                let (l, b) = (percent(c.lines), percent(c.branches));
                let cells = format!(
                    "{l:.2}% ({}/{}) | {b:.2}% ({}/{})",
                    c.lines.0, c.lines.1, c.branches.0, c.branches.1
                );
                (cells, l >= floor.lines && b >= floor.branches)
            }
        };
        passed &= ok;
        let verdict = if ok { "ok" } else { "BELOW FLOOR" };
        let _ = writeln!(
            text,
            "| {name} | {cells} | {:.0}% / {:.0}% | {verdict} |",
            floor.lines, floor.branches
        );
    }
    for name in measured.keys().filter(|n| !floors.contains_key(*n)) {
        passed = false;
        let _ = writeln!(
            text,
            "| {name} | measured but not a crate with floors | | | BELOW FLOOR |"
        );
    }
    Report { text, passed }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn write_crate(root: &Path, name: &str, floors: Option<(f64, f64)>) {
        let dir = root.join("crates").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let meta = floors
            .map(|(l, b)| format!("[package.metadata.coverage]\nlines = {l}\nbranches = {b}\n"))
            .unwrap_or_default();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\n{meta}"),
        )
        .unwrap();
    }

    const LCOV: &str = "SF:/r/crates/a/src/lib.rs\nDA:1,3\nDA:2,0\nBRDA:1,0,0,1\nBRDA:1,0,1,-\nBRDA:2,0,0,0\nBRDA:2,0,1,2\nLF:2\nend_of_record\nTN:\nSF:/r/crates/b/src/lib.rs\nDA:1,1\nend_of_record\n";

    #[test]
    fn parse_args_reads_every_flag_and_refuses_the_rest() {
        let o = parse_args(&s(&[
            "coverage",
            "--lcov",
            "l",
            "--root",
            "r",
            "--summary",
            "m",
        ]))
        .unwrap();
        assert_eq!(
            o,
            Options {
                lcov: "l".into(),
                root: "r".into(),
                summary: Some("m".into())
            }
        );
        assert_eq!(
            parse_args(&s(&["coverage", "--lcov", "l"])).unwrap().root,
            PathBuf::from(".")
        );
        assert!(parse_args(&s(&[])).unwrap_err().starts_with("usage"));
        assert!(parse_args(&s(&["other"])).unwrap_err().starts_with("usage"));
        assert_eq!(
            parse_args(&s(&["coverage", "--lcov"])).unwrap_err(),
            "--lcov needs a value"
        );
        assert_eq!(
            parse_args(&s(&["coverage", "--x", "1"])).unwrap_err(),
            "unknown flag --x"
        );
        assert_eq!(
            parse_args(&s(&["coverage"])).unwrap_err(),
            "--lcov is required"
        );
    }

    #[test]
    fn lcov_is_summed_per_crate_counting_unhit_lines_and_branches() {
        let m = parse_lcov(LCOV, Path::new("/r")).unwrap();
        assert_eq!(
            m["a"],
            Counts {
                lines: (1, 2),
                branches: (2, 4)
            }
        );
        assert_eq!(
            m["b"],
            Counts {
                lines: (1, 1),
                branches: (0, 0)
            }
        );
        let rel = parse_lcov(
            "SF:crates/c/src/x.rs\nDA:1,0\nBRDA:1,0,0,0\n",
            Path::new("/r"),
        );
        assert_eq!(
            rel.unwrap()["c"],
            Counts {
                lines: (0, 1),
                branches: (0, 1)
            }
        );
    }

    #[test]
    fn lcov_outside_crates_or_malformed_is_refused() {
        assert_eq!(
            parse_lcov("SF:/elsewhere/x.rs\n", Path::new("/r")).unwrap_err(),
            "source file outside crates/: /elsewhere/x.rs"
        );
        assert_eq!(
            parse_lcov("SF:/r/crates\n", Path::new("/r")).unwrap_err(),
            "source file outside crates/: /r/crates"
        );
        let root = Path::new("/r");
        assert_eq!(
            parse_lcov("SF:/r/crates/a/x.rs\nDA:1\n", root).unwrap_err(),
            "bad line: DA:1"
        );
        assert_eq!(
            parse_lcov("SF:/r/crates/a/x.rs\nBRDA:1,0\n", root).unwrap_err(),
            "bad line: BRDA:1,0"
        );
        // Records before any SF line are ignored.
        assert!(parse_lcov("TN:\nDA:1,1\n", root).unwrap().is_empty());
    }

    #[test]
    fn floors_are_read_from_each_crate_and_never_below_99() {
        let dir = tempfile::tempdir().unwrap();
        write_crate(dir.path(), "a", Some((99.0, 99.5)));
        std::fs::create_dir_all(dir.path().join("crates/not-a-crate")).unwrap();
        let f = read_floors(dir.path()).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(
            f["a"],
            Floors {
                lines: 99.0,
                branches: 99.5
            }
        );

        write_crate(dir.path(), "low", Some((99.0, 98.0)));
        assert_eq!(
            read_floors(dir.path()).unwrap_err(),
            "low: a coverage floor is below 99"
        );
        write_crate(dir.path(), "low", Some((90.0, 99.0)));
        assert_eq!(
            read_floors(dir.path()).unwrap_err(),
            "low: a coverage floor is below 99"
        );
        write_crate(dir.path(), "low", None);
        assert_eq!(
            read_floors(dir.path()).unwrap_err(),
            "low: no [package.metadata.coverage] floors"
        );
        std::fs::write(dir.path().join("crates/low/Cargo.toml"), "not toml [").unwrap();
        assert!(
            read_floors(dir.path())
                .unwrap_err()
                .contains("crates/low/Cargo.toml")
        );
        assert!(
            read_floors(&dir.path().join("missing"))
                .unwrap_err()
                .starts_with("reading")
        );
    }

    #[test]
    fn check_passes_at_the_floor_and_fails_below_or_unmeasured() {
        let floors = BTreeMap::from([
            (
                "a".to_owned(),
                Floors {
                    lines: 99.0,
                    branches: 99.0,
                },
            ),
            (
                "b".to_owned(),
                Floors {
                    lines: 99.0,
                    branches: 99.0,
                },
            ),
        ]);
        let full = Counts {
            lines: (99, 100),
            branches: (0, 0),
        };
        let measured = BTreeMap::from([("a".to_owned(), full), ("b".to_owned(), full)]);
        let r = check(&floors, &measured);
        assert!(r.passed, "{}", r.text);
        assert!(
            r.text
                .contains("| a | 99.00% (99/100) | 100.00% (0/0) | 99% / 99% | ok |")
        );

        let low = Counts {
            lines: (100, 100),
            branches: (98, 100),
        };
        let measured = BTreeMap::from([("a".to_owned(), full), ("b".to_owned(), low)]);
        let r = check(&floors, &measured);
        assert!(!r.passed);
        assert!(
            r.text
                .contains("| b | 100.00% (100/100) | 98.00% (98/100) | 99% / 99% | BELOW FLOOR |")
        );

        let r = check(&floors, &BTreeMap::from([("a".to_owned(), full)]));
        assert!(!r.passed);
        assert!(
            r.text
                .contains("| b | nothing measured | -  | 99% / 99% | BELOW FLOOR |")
        );

        let extra = BTreeMap::from([
            ("a".to_owned(), full),
            ("b".to_owned(), full),
            ("z".to_owned(), full),
        ]);
        let r = check(&floors, &extra);
        assert!(!r.passed);
        assert!(
            r.text
                .contains("| z | measured but not a crate with floors |")
        );
    }

    #[test]
    fn run_reads_the_report_and_appends_the_summary() {
        let dir = tempfile::tempdir().unwrap();
        write_crate(dir.path(), "a", Some((99.0, 99.0)));
        write_crate(dir.path(), "b", Some((99.0, 99.0)));
        let lcov = dir.path().join("lcov.info");
        std::fs::write(&lcov, LCOV.replace("/r", &dir.path().to_string_lossy())).unwrap();
        let summary = dir.path().join("summary.md");
        std::fs::write(&summary, "before\n").unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        let args = |extra: &[&str]| {
            let mut v = s(&[
                "coverage",
                "--lcov",
                &lcov.to_string_lossy(),
                "--root",
                &root,
            ]);
            v.extend(s(extra));
            v
        };
        let r = run(&args(&["--summary", &summary.to_string_lossy()])).unwrap();
        assert!(!r.passed);
        let written = std::fs::read_to_string(&summary).unwrap();
        assert!(written.starts_with("before\n| crate |"));
        assert_eq!(&written["before\n".len()..], r.text);

        // Without --summary nothing else is written.
        assert!(!run(&args(&[])).unwrap().passed);
        let no_dir = dir.path().join("none/summary.md");
        assert!(
            run(&args(&["--summary", &no_dir.to_string_lossy()]))
                .unwrap_err()
                .starts_with("writing")
        );
        let gone = dir.path().join("gone.info").to_string_lossy().into_owned();
        assert!(
            run(&s(&["coverage", "--lcov", &gone]))
                .unwrap_err()
                .starts_with("reading ")
        );
        assert!(run(&s(&["bad"])).is_err());
        let bad_root = s(&[
            "coverage",
            "--lcov",
            &lcov.to_string_lossy(),
            "--root",
            "/r",
        ]);
        assert!(
            run(&bad_root)
                .unwrap_err()
                .starts_with("source file outside crates/")
        );
    }
}
