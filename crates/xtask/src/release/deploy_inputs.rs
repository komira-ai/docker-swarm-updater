//! `cargo xtask release deploy-inputs --dir <dir> --repo <owner>/<name> --version <v>
//! [--github-output <file>]`: what the `deploy` job of `.github/workflows/artifacts.yml` sends
//! for release `v<version>`, read from the linux-x86_64 image tar of that release in `<dir>`
//! (`docker-swarm-updater-<version>-linux-x86_64.image.tar`, as downloaded from the release):
//!
//! - `digest=sha256:<64 hex>`: the image's manifest digest, the one entry of the tar's
//!   `index.json` (the `image_digest` of a deploy);
//! - `image-url=https://github.com/<repo>/releases/download/v<version>/<that file>`;
//! - `bundle-url=<image-url>.sigstore.json`.
//!
//! A tar whose `index.json` is missing, given twice, larger than [`MAX_INDEX`], not JSON, or
//! not listing exactly one manifest with a `sha256:` digest is refused, naming the file.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::{NAME, check_version, flags, output, passed, required};
use crate::Report;

/// The platform whose image the control plane runs.
pub(crate) const PLATFORM: &str = "linux-x86_64";

/// The largest `index.json` read; the release's own is a few hundred bytes.
pub(crate) const MAX_INDEX: u64 = 64 * 1024;

pub(crate) fn run(args: &[String]) -> Result<Report, String> {
    let flags = flags(args, &["--dir", "--repo", "--version", "--github-output"])?;
    let dir = PathBuf::from(required(&flags, "--dir")?);
    let repo = required(&flags, "--repo")?;
    let version = required(&flags, "--version")?;
    check_repo(repo)?;
    check_version(version)?;
    let name = format!("{NAME}-{version}-{PLATFORM}.image.tar");
    let digest = manifest_digest(&dir.join(&name))?;
    let image_url = format!("https://github.com/{repo}/releases/download/v{version}/{name}");
    let text =
        format!("digest={digest}\nimage-url={image_url}\nbundle-url={image_url}.sigstore.json\n");
    output(&flags, &text)?;
    Ok(passed(text))
}

/// `<owner>/<name>`, each non-empty and of the characters GitHub allows in them.
fn check_repo(repo: &str) -> Result<(), String> {
    let part = |p: &str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    match repo.split_once('/') {
        Some((owner, name)) if part(owner) && part(name) => Ok(()),
        _ => Err(format!("--repo {repo:?} is not <owner>/<name>")),
    }
}

#[derive(serde::Deserialize)]
struct Index {
    manifests: Vec<Descriptor>,
}

#[derive(serde::Deserialize)]
struct Descriptor {
    digest: String,
}

/// The one manifest digest the `index.json` of the image tar at `path` lists.
fn manifest_digest(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    index_digest(file).map_err(|e| format!("{}: {e}", path.display()))
}

/// A failure reading the tar itself, not one of its entries.
fn tar_error(e: std::io::Error) -> String {
    format!("reading the tar: {e}")
}

/// The one manifest digest the `index.json` of the tar read from `tar` lists.
fn index_digest(tar: impl std::io::Read) -> Result<String, String> {
    let mut archive = tar::Archive::new(tar);
    let mut index: Option<Vec<u8>> = None;
    for entry in archive.entries().map_err(tar_error)? {
        let entry = entry.map_err(tar_error)?;
        if entry.path_bytes().as_ref() != b"index.json" {
            continue;
        }
        if index.is_some() {
            return Err("index.json is in the tar twice".into());
        }
        let mut bytes = Vec::new();
        entry
            .take(MAX_INDEX + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("reading index.json: {e}"))?;
        if bytes.len() as u64 > MAX_INDEX {
            return Err(format!("index.json is larger than {MAX_INDEX} bytes"));
        }
        index = Some(bytes);
    }
    let index = index.ok_or("the tar has no index.json")?;
    let Index { manifests } =
        serde_json::from_slice(&index).map_err(|e| format!("index.json: {e}"))?;
    let [Descriptor { digest }] = <[Descriptor; 1]>::try_from(manifests)
        .map_err(|m| format!("index.json lists {} manifests, not exactly one", m.len()))?;
    let hex = digest.strip_prefix("sha256:").unwrap_or_default();
    if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!(
            "index.json names the manifest {digest:?}, not sha256:<64 lower-case hex>"
        ));
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::super::image::{Inputs, build};
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    /// A tar of `entries`, each a path and its bytes.
    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o444);
            header.set_size(bytes.len() as u64);
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn index(digests: &[&str]) -> Vec<u8> {
        let manifests: Vec<_> = digests
            .iter()
            .map(|d| serde_json::json!({"mediaType": "m", "digest": d, "size": 1}))
            .collect();
        serde_json::json!({"schemaVersion": 2, "manifests": manifests})
            .to_string()
            .into_bytes()
    }

    fn image(version: &str) -> (Vec<u8>, String) {
        let image = build(&Inputs {
            binary: b"\x7fELF binary".to_vec(),
            version: version.to_owned(),
            commit: "a".repeat(40),
            created: 1_800_000_000,
            architecture: "amd64".to_owned(),
        })
        .unwrap();
        (image.tar, image.manifest_digest)
    }

    #[test]
    fn the_digest_is_the_manifest_the_release_image_was_written_with() {
        let (tar, digest) = image("0.1.9");
        assert_eq!(index_digest(tar.as_slice()).unwrap(), digest);
    }

    #[test]
    fn prints_the_digest_and_the_release_addresses_of_the_image_and_its_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let (tar, digest) = image("0.1.9");
        let name = "docker-swarm-updater-0.1.9-linux-x86_64.image.tar";
        std::fs::write(dir.path().join(name), tar).unwrap();
        let out = dir.path().join("github-output");
        let report = run(&s(&[
            "--dir",
            &dir.path().to_string_lossy(),
            "--repo",
            "komira-ai/docker-swarm-updater",
            "--version",
            "0.1.9",
            "--github-output",
            &out.to_string_lossy(),
        ]))
        .unwrap();
        assert!(report.passed);
        let url = format!(
            "https://github.com/komira-ai/docker-swarm-updater/releases/download/v0.1.9/{name}"
        );
        assert_eq!(
            report.text,
            format!("digest={digest}\nimage-url={url}\nbundle-url={url}.sigstore.json\n")
        );
        assert_eq!(std::fs::read_to_string(&out).unwrap(), report.text);
        // An output file that cannot be written is an error naming it.
        let unwritable = dir.path().join("missing/github-output");
        let err = run(&s(&[
            "--dir",
            &dir.path().to_string_lossy(),
            "--repo",
            "komira-ai/docker-swarm-updater",
            "--version",
            "0.1.9",
            "--github-output",
            &unwritable.to_string_lossy(),
        ]))
        .unwrap_err();
        assert!(
            err.starts_with(&format!("writing {}: ", unwritable.display())),
            "{err}"
        );
    }

    #[test]
    fn only_the_linux_x86_64_image_of_that_version_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let (tar, _) = image("0.1.9");
        // The arm64 image and another version's x86_64 image are not the one asked for.
        std::fs::write(
            dir.path()
                .join("docker-swarm-updater-0.1.9-linux-arm64.image.tar"),
            &tar,
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("docker-swarm-updater-0.1.8-linux-x86_64.image.tar"),
            &tar,
        )
        .unwrap();
        let err = run(&s(&[
            "--dir",
            &dir.path().to_string_lossy(),
            "--repo",
            "o/r",
            "--version",
            "0.1.9",
        ]))
        .unwrap_err();
        let path = dir
            .path()
            .join("docker-swarm-updater-0.1.9-linux-x86_64.image.tar");
        assert!(
            err.starts_with(&format!("reading {}: ", path.display())),
            "{err}"
        );
    }

    #[test]
    fn a_bad_index_is_refused_naming_the_file_and_what_is_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let name = "docker-swarm-updater-0.1.9-linux-x86_64.image.tar";
        let path = dir.path().join(name);
        let big = vec![b' '; usize::try_from(MAX_INDEX).unwrap() + 1];
        let exactly_max = {
            let mut bytes = index(&[D]);
            bytes.resize(usize::try_from(MAX_INDEX).unwrap(), b' ');
            bytes
        };
        let cases: Vec<(Vec<u8>, Result<String, String>)> = vec![
            (tar_of(&[("index.json", &index(&[D]))]), Ok(D.to_owned())),
            // Other entries, before and after, are not read.
            (
                tar_of(&[
                    ("oci-layout", b"{}"),
                    ("index.json", &index(&[D])),
                    ("blobs/x/index.json", b"no"),
                ]),
                Ok(D.to_owned()),
            ),
            // An index of exactly the limit is read; one byte more is not.
            (tar_of(&[("index.json", &exactly_max)]), Ok(D.to_owned())),
            (
                tar_of(&[("index.json", &big)]),
                Err(format!("index.json is larger than {MAX_INDEX} bytes")),
            ),
            (
                tar_of(&[("oci-layout", b"{}")]),
                Err("the tar has no index.json".into()),
            ),
            (
                tar_of(&[("index.json", &index(&[D])), ("index.json", &index(&[D]))]),
                Err("index.json is in the tar twice".into()),
            ),
            (
                tar_of(&[("index.json", &index(&[]))]),
                Err("index.json lists 0 manifests, not exactly one".into()),
            ),
            (
                tar_of(&[("index.json", &index(&[D, D]))]),
                Err("index.json lists 2 manifests, not exactly one".into()),
            ),
            (
                tar_of(&[("index.json", &index(&["sha512:00"]))]),
                Err(
                    "index.json names the manifest \"sha512:00\", not sha256:<64 lower-case hex>"
                        .into(),
                ),
            ),
            (
                tar_of(&[(
                    "index.json",
                    &index(&[&D.to_uppercase().replace("SHA256", "sha256")]),
                )]),
                Err(format!(
                    "index.json names the manifest {:?}, not sha256:<64 lower-case hex>",
                    D.to_uppercase().replace("SHA256", "sha256")
                )),
            ),
            (
                tar_of(&[("index.json", &index(&[&D[..D.len() - 1]]))]),
                Err(format!(
                    "index.json names the manifest {:?}, not sha256:<64 lower-case hex>",
                    &D[..D.len() - 1]
                )),
            ),
        ];
        for (tar, expected) in cases {
            std::fs::write(&path, &tar).unwrap();
            let got = run(&s(&[
                "--dir",
                &dir.path().to_string_lossy(),
                "--repo",
                "o/r",
                "--version",
                "0.1.9",
            ]));
            let expected = expected
                .map(|d| {
                    let url = format!("https://github.com/o/r/releases/download/v0.1.9/{name}");
                    format!("digest={d}\nimage-url={url}\nbundle-url={url}.sigstore.json\n")
                })
                .map_err(|e| format!("{}: {e}", path.display()));
            assert_eq!(got.map(|r| r.text), expected);
        }
    }

    /// Reads `bytes` up to `at`, then fails.
    struct FailsAfter<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl std::io::Read for FailsAfter<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.at == 0 {
                return Err(std::io::Error::other("the disk failed"));
            }
            let n = buf.len().min(self.at).min(self.bytes.len());
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            self.at -= n;
            Ok(n)
        }
    }

    #[test]
    fn a_tar_or_index_that_cannot_be_read_is_an_error() {
        // A read that fails inside index.json's bytes.
        let whole = tar_of(&[("index.json", &index(&[D]))]);
        let failing = FailsAfter {
            bytes: &whole,
            at: 512 + 10,
        };
        assert_eq!(
            index_digest(failing).unwrap_err(),
            "reading index.json: the disk failed"
        );
        // The tar cut short inside index.json's bytes.
        let err = index_digest(&whole[..512 + 10]).unwrap_err();
        assert!(err.starts_with("reading the tar: "), "{err}");
        // A header block that is not a tar header.
        let mut bad = whole.clone();
        bad[148..156].copy_from_slice(b"garbage!");
        assert!(
            index_digest(bad.as_slice())
                .unwrap_err()
                .starts_with("reading the tar: "),
        );
        // index.json that is not JSON.
        assert!(
            index_digest(tar_of(&[("index.json", b"not json")]).as_slice())
                .unwrap_err()
                .starts_with("index.json: "),
        );
    }

    #[test]
    fn a_bad_command_line_is_refused() {
        let cases: [(&[&str], &str); 6] = [
            (
                &["--repo", "o/r", "--version", "0.1.9"],
                "--dir is required",
            ),
            (&["--dir", "d", "--version", "0.1.9"], "--repo is required"),
            (&["--dir", "d", "--repo", "o/r"], "--version is required"),
            (
                &["--dir", "d", "--repo", "o/r", "--version", "v0.1.9"],
                "version \"v0.1.9\" is not X.Y.Z",
            ),
            (
                &["--dir", "d", "--repo", "o/r/x", "--version", "0.1.9"],
                "--repo \"o/r/x\" is not <owner>/<name>",
            ),
            (
                &["--dir", "d", "--repo", "/r", "--version", "0.1.9"],
                "--repo \"/r\" is not <owner>/<name>",
            ),
        ];
        for (args, message) in cases {
            assert_eq!(run(&s(args)).unwrap_err(), message, "{args:?}");
        }
        let err = run(&s(&["--bogus", "x"])).unwrap_err();
        assert!(err.starts_with("unknown flag --bogus; usage: "), "{err}");
        for repo in ["o", "o/", "o/r?x", "o r/x"] {
            assert_eq!(
                check_repo(repo).unwrap_err(),
                format!("--repo {repo:?} is not <owner>/<name>")
            );
        }
        for repo in ["komira-ai/docker-swarm-updater", "A_b.c/x-Y.z_1"] {
            assert_eq!(check_repo(repo), Ok(()));
        }
    }
}
