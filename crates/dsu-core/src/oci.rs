//! Reading the parts of an OCI image layout the deploy checks (docs/design.md section 3.3
//! step 4): `index.json`, the image manifest and the image config. Both the OCI and the
//! Docker v2 manifest media types are accepted.

use std::fmt;

use serde::Deserialize;

use crate::ids::Digest;

/// The manifest media types accepted.
pub const MANIFEST_MEDIA_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// A tar that fails a check of section 3.3 step 4.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OciError {
    /// The manifest named by `index.json` is not the digest the caller asked for.
    #[error("digest_mismatch: index.json names {found}, the request names {expected}")]
    DigestMismatch {
        /// The digest of the request.
        expected: Digest,
        /// The digest of the tar's one manifest.
        found: Digest,
    },
    /// The layout is not what the deploy accepts.
    #[error("tar_invalid: {0}")]
    TarInvalid(String),
    /// The image config names another platform than the service's.
    #[error("platform_mismatch: the image is for {found}, the service wants {expected}")]
    PlatformMismatch {
        /// The configured platform.
        expected: String,
        /// The image config's platform.
        found: String,
    },
    /// The configured platform is not `os/arch[/variant]`.
    #[error("platform {0:?} is not os/architecture[/variant]")]
    BadPlatform(String),
}

fn tar_invalid(what: &str, e: impl fmt::Display) -> OciError {
    OciError::TarInvalid(format!("{what}: {e}"))
}

/// A content descriptor: what a manifest names a blob by.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Descriptor {
    /// The blob's media type.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// The blob's SHA-256 digest (its name in `blobs/sha256/`).
    pub digest: Digest,
    /// The blob's size in bytes.
    pub size: u64,
}

/// The one manifest of `index.json`.
pub type ManifestRef = Descriptor;

#[derive(Deserialize)]
struct Index {
    manifests: Vec<Descriptor>,
}

/// Reads `index.json`: it must list exactly one manifest, of an accepted media type, whose
/// digest is `expected`.
pub fn check_index(bytes: &[u8], expected: &Digest) -> Result<ManifestRef, OciError> {
    let index: Index = serde_json::from_slice(bytes).map_err(|e| tar_invalid("index.json", e))?;
    let mut manifests = index.manifests.into_iter();
    let (Some(manifest), None) = (manifests.next(), manifests.next()) else {
        return Err(OciError::TarInvalid(
            "index.json must list exactly one manifest".into(),
        ));
    };
    if manifest.digest != *expected {
        return Err(OciError::DigestMismatch {
            expected: expected.clone(),
            found: manifest.digest,
        });
    }
    check_media_type("index.json manifest", &manifest.media_type)?;
    Ok(manifest)
}

fn check_media_type(what: &str, media_type: &str) -> Result<(), OciError> {
    if MANIFEST_MEDIA_TYPES.contains(&media_type) {
        Ok(())
    } else {
        Err(OciError::TarInvalid(format!(
            "{what} has unsupported media type {media_type:?}"
        )))
    }
}

/// An image manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Manifest {
    /// The manifest's own media type (`mediaType`, required here).
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// The image config blob.
    pub config: Descriptor,
    /// The layer blobs, in order.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
}

impl Manifest {
    /// Every blob the manifest names: the config first, then the layers.
    pub fn blobs(&self) -> impl Iterator<Item = &Descriptor> {
        std::iter::once(&self.config).chain(self.layers.iter())
    }
}

/// Reads an image manifest. Its media type must be an accepted one.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, OciError> {
    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|e| tar_invalid("manifest", e))?;
    check_media_type("manifest", &manifest.media_type)?;
    Ok(manifest)
}

/// A platform, `os/architecture` or `os/architecture/variant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// The operating system, e.g. `linux`.
    pub os: String,
    /// The CPU architecture, e.g. `amd64`.
    pub architecture: String,
    /// The architecture variant, e.g. `v8`; only compared when configured.
    pub variant: Option<String>,
}

impl Platform {
    /// Parses `os/architecture[/variant]`: two or three segments of `[a-z0-9._-]`.
    pub fn parse(text: &str) -> Result<Platform, OciError> {
        let segments: Vec<&str> = text.split('/').collect();
        let plain = segments.iter().all(|s| {
            !s.is_empty()
                && s.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        });
        match segments.as_slice() {
            [os, arch] if plain => Ok(Platform {
                os: (*os).into(),
                architecture: (*arch).into(),
                variant: None,
            }),
            [os, arch, variant] if plain => Ok(Platform {
                os: (*os).into(),
                architecture: (*arch).into(),
                variant: Some((*variant).into()),
            }),
            _ => Err(OciError::BadPlatform(text.to_owned())),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        match &self.variant {
            Some(v) => write!(f, "/{v}"),
            None => Ok(()),
        }
    }
}

#[derive(Deserialize)]
struct ImageConfig {
    os: String,
    architecture: String,
    #[serde(default)]
    variant: Option<String>,
}

/// Checks the image config's `os` and `architecture` against `platform`
/// (`os/architecture[/variant]`); the config's variant is compared only when `platform` has one.
pub fn check_platform(config_bytes: &[u8], platform: &str) -> Result<(), OciError> {
    let want = Platform::parse(platform)?;
    let config: ImageConfig =
        serde_json::from_slice(config_bytes).map_err(|e| tar_invalid("image config", e))?;
    let found = Platform {
        os: config.os,
        architecture: config.architecture,
        variant: config.variant.filter(|_| want.variant.is_some()),
    };
    if found == want {
        Ok(())
    } else {
        Err(OciError::PlatformMismatch {
            expected: want.to_string(),
            found: found.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const OCI: &str = "application/vnd.oci.image.manifest.v1+json";
    const DOCKER: &str = "application/vnd.docker.distribution.manifest.v2+json";

    fn digest(s: &str) -> Digest {
        Digest::parse(s).unwrap()
    }

    fn index(entries: &[(&str, &str)]) -> String {
        let list: Vec<String> = entries
            .iter()
            .map(|(m, d)| format!(r#"{{"mediaType":"{m}","digest":"{d}","size":7}}"#))
            .collect();
        format!(r#"{{"schemaVersion":2,"manifests":[{}]}}"#, list.join(","))
    }

    #[test]
    fn index_with_the_expected_manifest_is_accepted_in_both_media_types() {
        for media in [OCI, DOCKER] {
            let m = check_index(index(&[(media, D1)]).as_bytes(), &digest(D1)).unwrap();
            assert_eq!(m.digest, digest(D1));
            assert_eq!(m.media_type, media);
            assert_eq!(m.size, 7);
        }
    }

    #[test]
    fn index_with_another_digest_is_a_mismatch() {
        let err = check_index(index(&[(OCI, D2)]).as_bytes(), &digest(D1)).unwrap_err();
        assert_eq!(
            err,
            OciError::DigestMismatch {
                expected: digest(D1),
                found: digest(D2)
            }
        );
        assert!(err.to_string().starts_with("digest_mismatch"));
    }

    #[test]
    fn index_must_list_exactly_one_manifest() {
        for entries in [
            vec![],
            vec![(OCI, D1), (OCI, D1)],
            vec![(OCI, D1), (OCI, D2)],
        ] {
            let err = check_index(index(&entries).as_bytes(), &digest(D1)).unwrap_err();
            assert!(matches!(err, OciError::TarInvalid(_)), "{entries:?}");
        }
    }

    #[test]
    fn index_with_an_unsupported_media_type_or_bad_json_is_tar_invalid() {
        let nested = index(&[("application/vnd.oci.image.index.v1+json", D1)]);
        let err = check_index(nested.as_bytes(), &digest(D1)).unwrap_err();
        assert_eq!(
            err,
            OciError::TarInvalid(
                "index.json manifest has unsupported media type \"application/vnd.oci.image.index.v1+json\"".into()
            )
        );
        for bad in [
            "",
            "{",
            r#"{"manifests":[{"mediaType":"x","digest":"nope","size":1}]}"#,
            r#"{"schemaVersion":2}"#,
        ] {
            let err = check_index(bad.as_bytes(), &digest(D1)).unwrap_err();
            assert!(err.to_string().starts_with("tar_invalid"), "{bad}");
        }
    }

    fn manifest(media: &str, layers: &str) -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{media}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{D1}","size":10}},"layers":[{layers}]}}"#
        )
    }

    #[test]
    fn manifest_lists_the_config_then_the_layers() {
        let layer = format!(
            r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{D2}","size":20}}"#
        );
        let m = parse_manifest(manifest(DOCKER, &format!("{layer},{layer}")).as_bytes()).unwrap();
        assert_eq!(m.media_type, DOCKER);
        assert_eq!(m.config.digest, digest(D1));
        assert_eq!(m.layers.len(), 2);
        let blobs: Vec<&str> = m.blobs().map(|b| b.digest.as_str()).collect();
        assert_eq!(blobs, [D1, D2, D2]);
        let empty = parse_manifest(manifest(OCI, "").as_bytes()).unwrap();
        assert_eq!(empty.blobs().count(), 1);
    }

    #[test]
    fn manifest_without_layers_key_has_no_layers() {
        let json = format!(
            r#"{{"mediaType":"{OCI}","config":{{"mediaType":"c","digest":"{D1}","size":1}}}}"#
        );
        assert!(parse_manifest(json.as_bytes()).unwrap().layers.is_empty());
    }

    #[test]
    fn bad_manifests_are_tar_invalid() {
        let bad_media = manifest("text/plain", "");
        let no_media = format!(r#"{{"config":{{"mediaType":"c","digest":"{D1}","size":1}}}}"#);
        let bad_digest = manifest(OCI, r#"{"mediaType":"l","digest":"sha256:xyz","size":1}"#);
        for bad in [
            "",
            "[]",
            bad_media.as_str(),
            no_media.as_str(),
            bad_digest.as_str(),
        ] {
            let err = parse_manifest(bad.as_bytes()).unwrap_err();
            assert!(matches!(err, OciError::TarInvalid(_)), "{bad}");
        }
    }

    #[test]
    fn platform_parses_two_or_three_segments() {
        let p = Platform::parse("linux/amd64").unwrap();
        assert_eq!(
            (p.os.as_str(), p.architecture.as_str(), p.variant.clone()),
            ("linux", "amd64", None)
        );
        assert_eq!(p.to_string(), "linux/amd64");
        let p = Platform::parse("linux/arm64/v8").unwrap();
        assert_eq!(p.variant.as_deref(), Some("v8"));
        assert_eq!(p.to_string(), "linux/arm64/v8");
        for bad in [
            "",
            "linux",
            "linux/",
            "/amd64",
            "linux//v8",
            "a/b/c/d",
            "Linux/amd64",
            "linux/amd 64",
            "linux/amd64/",
        ] {
            assert_eq!(
                Platform::parse(bad),
                Err(OciError::BadPlatform(bad.to_owned())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn config_platform_is_compared_on_os_and_architecture() {
        let config = r#"{"architecture":"amd64","os":"linux","config":{}}"#;
        assert_eq!(check_platform(config.as_bytes(), "linux/amd64"), Ok(()));
        let err = check_platform(config.as_bytes(), "linux/arm64").unwrap_err();
        assert_eq!(
            err,
            OciError::PlatformMismatch {
                expected: "linux/arm64".into(),
                found: "linux/amd64".into()
            }
        );
        assert!(err.to_string().starts_with("platform_mismatch"));
        assert!(matches!(
            check_platform(config.as_bytes(), "windows/amd64"),
            Err(OciError::PlatformMismatch { .. })
        ));
    }

    #[test]
    fn config_variant_is_ignored_unless_configured() {
        let with_variant = r#"{"architecture":"arm64","os":"linux","variant":"v8"}"#;
        let without = r#"{"architecture":"arm64","os":"linux"}"#;
        assert_eq!(
            check_platform(with_variant.as_bytes(), "linux/arm64"),
            Ok(())
        );
        assert_eq!(check_platform(without.as_bytes(), "linux/arm64"), Ok(()));
        assert_eq!(
            check_platform(with_variant.as_bytes(), "linux/arm64/v8"),
            Ok(())
        );
        let err = check_platform(with_variant.as_bytes(), "linux/arm64/v7").unwrap_err();
        assert_eq!(
            err,
            OciError::PlatformMismatch {
                expected: "linux/arm64/v7".into(),
                found: "linux/arm64/v8".into()
            }
        );
        assert!(matches!(
            check_platform(without.as_bytes(), "linux/arm64/v8"),
            Err(OciError::PlatformMismatch { .. })
        ));
    }

    #[test]
    fn bad_configs_and_bad_platforms_are_refused() {
        for bad in ["", "{}", r#"{"os":"linux"}"#, r#"{"architecture":"amd64"}"#] {
            let err = check_platform(bad.as_bytes(), "linux/amd64").unwrap_err();
            assert!(matches!(err, OciError::TarInvalid(_)), "{bad}");
        }
        let err = check_platform(b"{}", "linux").unwrap_err();
        assert!(matches!(err, OciError::BadPlatform(_)));
        assert!(err.to_string().contains("linux"));
    }
}
