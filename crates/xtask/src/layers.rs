//! `cargo xtask layers [--root <dir>]`: holds the workspace to `layers.toml`. Every crate
//! under `crates/` is in exactly one layer, a crate depends (`[dependencies]` and
//! `[build-dependencies]`) only on workspace crates of its own layer or a lower one, and a
//! `pure` layer's crates deny the two disallowed-items lints in their lib root and depend on
//! none of the runtime, network and randomness crates in [`BANNED`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::Report;

/// What every crate of a `pure` layer must carry, on one line, in `src/lib.rs`.
const DENY_LINE: &str = "#![deny(clippy::disallowed_methods, clippy::disallowed_types)]";

/// Crates a `pure` crate may not depend on.
const BANNED: [&str; 11] = [
    "tokio",
    "hyper",
    "hyper-util",
    "rustls",
    "tokio-rustls",
    "getrandom",
    "rand",
    "mio",
    "socket2",
    "reqwest",
    "ureq",
];

#[derive(serde::Deserialize)]
struct Layers {
    #[serde(default)]
    layer: Vec<Layer>,
}

#[derive(serde::Deserialize)]
struct Layer {
    name: String,
    #[serde(default)]
    pure: bool,
    crates: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Manifest {
    package: Package,
    #[serde(default)]
    dependencies: BTreeMap<String, Dep>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, Dep>,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
}

/// A dependency entry: `name = "1"` or a table, which may rename the package.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Dep {
    Version(#[allow(dead_code, reason = "only its shape matters")] String),
    Table { package: Option<String> },
}

/// One workspace crate: its directory, package name and normal plus build dependencies.
struct Krate {
    dir: PathBuf,
    name: String,
    deps: BTreeSet<String>,
}

/// Runs `layers [--root <dir>]` (`args` without the command word).
pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    let root = match args {
        [] => PathBuf::from("."),
        [flag, dir] if flag == "--root" => PathBuf::from(dir),
        _ => return Err("usage: xtask layers [--root <dir>]".into()),
    };
    let problems = check(&root)?;
    let text = if problems.is_empty() {
        "layers: ok\n".to_owned()
    } else {
        problems.iter().map(|p| format!("layers: {p}\n")).collect()
    };
    Ok(Report {
        text,
        passed: problems.is_empty(),
    })
}

fn read_krates(root: &Path) -> Result<Vec<Krate>, String> {
    let dir = root.join("crates");
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    // A directory without a Cargo.toml is not a crate.
    for entry in entries.flatten() {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let parsed: Manifest =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", manifest.display()))?;
        let deps = parsed
            .dependencies
            .into_iter()
            .chain(parsed.build_dependencies)
            .map(|(key, dep)| match dep {
                Dep::Table { package: Some(p) } => p,
                Dep::Table { package: None } | Dep::Version(_) => key,
            })
            .collect();
        out.push(Krate {
            dir: entry.path(),
            name: parsed.package.name,
            deps,
        });
    }
    Ok(out)
}

/// Checks the repository at `root` and returns every defect found, sorted; an empty list is
/// a pass. An unreadable or unparsable `layers.toml` or manifest is an error.
pub fn check(root: &Path) -> Result<Vec<String>, String> {
    let file = root.join("layers.toml");
    let text =
        std::fs::read_to_string(&file).map_err(|e| format!("reading {}: {e}", file.display()))?;
    let layers: Layers = toml::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let krates = read_krates(root)?;
    let exists: BTreeSet<&str> = krates.iter().map(|k| k.name.as_str()).collect();

    let mut problems = Vec::new();
    let mut names = BTreeSet::new();
    // crate name -> (layer index, whether that layer is pure)
    let mut placed: BTreeMap<&str, (usize, bool)> = BTreeMap::new();
    for (index, layer) in layers.layer.iter().enumerate() {
        if !names.insert(layer.name.as_str()) {
            problems.push(format!("layer {} is declared twice", layer.name));
        }
        for name in &layer.crates {
            if !exists.contains(name.as_str()) {
                problems.push(format!(
                    "layer {} names {name}, which is not a crate",
                    layer.name
                ));
            } else if placed.insert(name, (index, layer.pure)).is_some() {
                problems.push(format!("crate {name} is in more than one layer"));
            }
        }
    }
    for krate in &krates {
        let Some(&(own, pure)) = placed.get(krate.name.as_str()) else {
            problems.push(format!("crate {} is in no layer", krate.name));
            continue;
        };
        for dep in &krate.deps {
            if placed
                .get(dep.as_str())
                .is_some_and(|&(layer, _)| layer > own)
            {
                problems.push(format!(
                    "crate {} depends on {dep}, which is in a higher layer",
                    krate.name
                ));
            }
        }
        if pure {
            problems.extend(check_pure(krate));
        }
    }
    problems.sort();
    Ok(problems)
}

/// The extra rules of a crate in a `pure` layer.
fn check_pure(krate: &Krate) -> Vec<String> {
    let mut problems = Vec::new();
    let lib = std::fs::read_to_string(krate.dir.join("src/lib.rs")).unwrap_or_default();
    if !lib.lines().any(|l| l.trim() == DENY_LINE) {
        problems.push(format!(
            "pure crate {} lacks {DENY_LINE} in src/lib.rs",
            krate.name
        ));
    }
    for dep in krate.deps.iter().filter(|d| BANNED.contains(&d.as_str())) {
        problems.push(format!("pure crate {} depends on {dep}", krate.name));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny workspace: (crate, dependencies, lib.rs text), plus the layers.toml text.
    fn workspace(layers: &str, krates: &[(&str, &str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("layers.toml"), layers).unwrap();
        for (name, deps, lib) in krates {
            let src = dir.path().join("crates").join(name).join("src");
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(src.join("lib.rs"), lib).unwrap();
            std::fs::write(
                src.join("../Cargo.toml"),
                format!("[package]\nname = \"{name}\"\n{deps}"),
            )
            .unwrap();
        }
        dir
    }

    const GOOD_LAYERS: &str = "[[layer]]\nname = \"pure\"\npure = true\ncrates = [\"core\"]\n\
        [[layer]]\nname = \"lib\"\ncrates = [\"lib\"]\n[[layer]]\nname = \"app\"\ncrates = [\"app\"]\n";
    const DENY: &str = "//! x\n#![deny(clippy::disallowed_methods, clippy::disallowed_types)]\n";

    fn good_krates() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("core", "[dependencies]\nserde = \"1\"\n", DENY),
            ("lib", "[dependencies]\ncore = { path = \"../core\" }\n", ""),
            (
                "app",
                "[dependencies]\nlib.workspace = true\n[build-dependencies]\ncore = \"1\"\n\
                 [dev-dependencies]\nzzz = \"1\"\n",
                "",
            ),
        ]
    }

    fn problems(layers: &str, krates: &[(&str, &str, &str)]) -> Vec<String> {
        let dir = workspace(layers, krates);
        check(dir.path()).unwrap()
    }

    #[test]
    fn a_well_layered_workspace_passes() {
        assert_eq!(problems(GOOD_LAYERS, &good_krates()), Vec::<String>::new());
    }

    #[test]
    fn a_crate_in_no_layer_is_refused() {
        let mut k = good_krates();
        k.push(("extra", "", ""));
        assert_eq!(problems(GOOD_LAYERS, &k), ["crate extra is in no layer"]);
    }

    #[test]
    fn a_crate_in_two_layers_is_refused() {
        let layers = GOOD_LAYERS.replace("crates = [\"app\"]", "crates = [\"app\", \"lib\"]");
        assert_eq!(
            problems(&layers, &good_krates()),
            ["crate lib is in more than one layer"]
        );
    }

    #[test]
    fn a_layer_naming_a_missing_crate_is_refused() {
        let layers = format!("{GOOD_LAYERS}[[layer]]\nname = \"top\"\ncrates = [\"ghost\"]\n");
        assert_eq!(
            problems(&layers, &good_krates()),
            ["layer top names ghost, which is not a crate"]
        );
    }

    #[test]
    fn a_duplicate_layer_name_is_refused() {
        let layers = format!("{GOOD_LAYERS}[[layer]]\nname = \"app\"\ncrates = []\n");
        assert_eq!(
            problems(&layers, &good_krates()),
            ["layer app is declared twice"]
        );
    }

    #[test]
    fn a_dependency_on_a_higher_layer_is_refused() {
        let mut k = good_krates();
        k[1].1 = "[dependencies]\napp = { path = \"../app\" }\n";
        assert_eq!(
            problems(GOOD_LAYERS, &k),
            ["crate lib depends on app, which is in a higher layer"]
        );
        // A rename is followed to the package, and a build-dependency counts too.
        k[1].1 = "[build-dependencies]\nother = { package = \"app\", path = \"../app\" }\n";
        assert_eq!(problems(GOOD_LAYERS, &k).len(), 1);
        // A dev-dependency on a higher layer is allowed.
        k[1].1 = "[dev-dependencies]\napp = { path = \"../app\" }\n";
        assert!(problems(GOOD_LAYERS, &k).is_empty());
    }

    #[test]
    fn a_pure_crate_without_the_deny_line_is_refused() {
        for lib in [
            "",
            "#![deny(clippy::disallowed_methods)]\n#![deny(clippy::disallowed_types)]\n",
        ] {
            let mut k = good_krates();
            k[0].2 = lib;
            assert_eq!(
                problems(GOOD_LAYERS, &k),
                [format!("pure crate core lacks {DENY_LINE} in src/lib.rs")]
            );
        }
        // No lib root at all.
        let dir = workspace(GOOD_LAYERS, &good_krates());
        std::fs::remove_file(dir.path().join("crates/core/src/lib.rs")).unwrap();
        assert_eq!(check(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn a_pure_crate_depending_on_a_banned_crate_is_refused() {
        for banned in BANNED {
            let deps =
                format!("[dependencies]\nx = {{ package = \"{banned}\", version = \"1\" }}\n");
            let mut k = good_krates();
            k[0].1 = &deps;
            assert_eq!(
                problems(GOOD_LAYERS, &k),
                [format!("pure crate core depends on {banned}")]
            );
        }
        // Not pure: the same crate in a plain layer may depend on tokio.
        let mut k = good_krates();
        k[1].1 = "[dependencies]\ntokio = \"1\"\n";
        assert!(problems(GOOD_LAYERS, &k).is_empty());
    }

    #[test]
    fn unreadable_inputs_are_errors() {
        let dir = workspace(GOOD_LAYERS, &good_krates());
        assert!(
            check(&dir.path().join("none"))
                .unwrap_err()
                .starts_with("reading")
        );
        std::fs::write(dir.path().join("layers.toml"), "[[layer]\n").unwrap();
        assert!(check(dir.path()).unwrap_err().contains("layers.toml"));
        std::fs::write(dir.path().join("layers.toml"), GOOD_LAYERS).unwrap();
        std::fs::write(dir.path().join("crates/lib/Cargo.toml"), "[package\n").unwrap();
        assert!(
            check(dir.path())
                .unwrap_err()
                .contains("crates/lib/Cargo.toml")
        );
        std::fs::remove_dir_all(dir.path().join("crates")).unwrap();
        assert!(check(dir.path()).unwrap_err().starts_with("reading"));
    }

    #[test]
    fn a_directory_without_a_manifest_is_not_a_crate() {
        let dir = workspace(GOOD_LAYERS, &good_krates());
        std::fs::create_dir_all(dir.path().join("crates/notes")).unwrap();
        assert!(check(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn run_reports_and_parses_its_flags() {
        let dir = workspace(GOOD_LAYERS, &good_krates());
        let root = dir.path().to_string_lossy().into_owned();
        let r = run(&["--root".to_owned(), root.clone()]).unwrap();
        assert!(r.passed);
        assert_eq!(r.text, "layers: ok\n");
        std::fs::remove_dir_all(dir.path().join("crates/app")).unwrap();
        let r = run(&["--root".to_owned(), root]).unwrap();
        assert!(!r.passed);
        assert!(r.text.starts_with("layers: layer app names app"));
        assert!(run(&["--bad".to_owned()]).unwrap_err().starts_with("usage"));
        assert!(
            run(&["--bad".to_owned(), "x".to_owned()])
                .unwrap_err()
                .starts_with("usage")
        );
        assert!(run(&[]).is_err()); // "." has no layers.toml in the xtask crate directory
    }
}
