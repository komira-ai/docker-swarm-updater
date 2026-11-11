//! The URL rules of docs/design.md section 3.2: which release URLs a deploy may fetch, which
//! redirect targets a download may follow, and which resolved addresses it may connect to.
//! URLs are parsed with the `url` crate and judged by their parts, never compared as strings.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ::url::{Host, Url};

/// The suffix a bundle's file name has on top of the image file's name.
pub const BUNDLE_SUFFIX: &str = ".sigstore.json";

/// A URL that breaks a rule of section 3.2.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    /// The text is not a URL, or it holds a character or segment refused before parsing.
    #[error("url {url:?} is not acceptable: {reason}")]
    Unparseable {
        /// The refused input.
        url: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The URL parses but breaks a rule.
    #[error("url {url} is not allowed: {rule}")]
    Refused {
        /// The refused URL in its parsed form.
        url: String,
        /// The rule it breaks.
        rule: &'static str,
    },
}

/// Where a service's release assets live and what their file names look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseSpec<'a> {
    /// The GitHub owner.
    pub owner: &'a str,
    /// The GitHub repository.
    pub repo: &'a str,
    /// The `artifact_name` pattern (one `*`) the image file's name must match.
    pub artifact_name: &'a str,
}

/// A release URL that passed the rules, with the parts that were judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseUrl {
    url: Url,
    tag: String,
    file: String,
}

impl ReleaseUrl {
    /// The parsed URL, ready to fetch.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The release tag segment.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The file name segment.
    pub fn file(&self) -> &str {
        &self.file
    }
}

fn refused(url: &Url, rule: &'static str) -> UrlError {
    UrlError::Refused {
        url: url.as_str().to_owned(),
        rule,
    }
}

/// What the raw text holds that the parser would hide: a `%` or `\` anywhere (the parser
/// decodes the first and reads the second as `/`), or a `.` or `..` segment (the parser
/// resolves it away).
fn raw_problem(raw: &str) -> Option<&'static str> {
    if raw.contains('%') || raw.contains('\\') {
        Some("contains a '%' or a '\\'")
    } else if raw.split('/').any(|s| s == "." || s == "..") {
        Some("contains a '.' or '..' segment")
    } else {
        None
    }
}

/// Applies the host and path rules and returns the tag and file segments.
fn judge(raw: &str, spec: &ReleaseSpec<'_>) -> Result<ReleaseUrl, UrlError> {
    if let Some(reason) = raw_problem(raw) {
        return Err(UrlError::Unparseable {
            url: raw.to_owned(),
            reason: reason.to_owned(),
        });
    }
    let url = Url::parse(raw).map_err(|e| UrlError::Unparseable {
        url: raw.to_owned(),
        reason: e.to_string(),
    })?;
    if url.scheme() != "https" {
        return Err(refused(&url, "scheme must be https"));
    }
    if url.host() != Some(Host::Domain("github.com")) {
        return Err(refused(&url, "host must be github.com"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused(&url, "no user info"));
    }
    if url.port().is_some() {
        return Err(refused(&url, "no port"));
    }
    if url.query().is_some() {
        return Err(refused(&url, "no query"));
    }
    if url.fragment().is_some() {
        return Err(refused(&url, "no fragment"));
    }
    let segments: Vec<&str> = url
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(refused(&url, "path segments must not be empty"));
    }
    let [owner, repo, "releases", "download", tag, file] = segments[..] else {
        return Err(refused(
            &url,
            "path must be <owner>/<repo>/releases/download/<tag>/<file>",
        ));
    };
    if owner != spec.owner || repo != spec.repo {
        return Err(refused(
            &url,
            "owner and repository must be the service's configured ones",
        ));
    }
    let (tag, file) = (tag.to_owned(), file.to_owned());
    Ok(ReleaseUrl { url, tag, file })
}

/// Checks the URL of an image tar against the release rule of section 3.2: `https`, host
/// exactly `github.com`, no user info, port, query or fragment, path segments exactly
/// `<owner>/<repo>/releases/download/<tag>/<file>` with owner and repository from `spec`, no
/// empty, `.` or `..` segment, no `%` or `\` anywhere, and a file name matching
/// `spec.artifact_name`.
pub fn check_image_url(raw: &str, spec: &ReleaseSpec<'_>) -> Result<ReleaseUrl, UrlError> {
    let release = judge(raw, spec)?;
    if !crate::config::artifact_name_matches(spec.artifact_name, &release.file) {
        return Err(refused(&release.url, "file name must match artifact_name"));
    }
    Ok(release)
}

/// Checks the URL of a Sigstore bundle: the release rule, with a file name that is the image
/// file's name plus [`BUNDLE_SUFFIX`].
pub fn check_bundle_url(
    raw: &str,
    spec: &ReleaseSpec<'_>,
    image: &ReleaseUrl,
) -> Result<ReleaseUrl, UrlError> {
    let release = judge(raw, spec)?;
    let expected = format!("{}{BUNDLE_SUFFIX}", image.file);
    if release.file != expected {
        return Err(refused(
            &release.url,
            "file name must be the image file's name plus .sigstore.json",
        ));
    }
    Ok(release)
}

/// Checks a redirect target: `https`, a host that is exactly one of `redirect_hosts`, no user
/// info and no port.
pub fn check_redirect_url(url: &Url, redirect_hosts: &[String]) -> Result<(), UrlError> {
    if url.scheme() != "https" {
        return Err(refused(url, "redirects must go to https"));
    }
    let allowed = match url.host() {
        Some(Host::Domain(host)) => redirect_hosts.iter().any(|h| h == host),
        _ => false,
    };
    if !allowed {
        return Err(refused(url, "redirect host is not in redirect_hosts"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refused(url, "no user info"));
    }
    if url.port().is_some() {
        return Err(refused(url, "no port"));
    }
    Ok(())
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let shared = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
    !(ip.is_loopback()
        || ip.is_private()
        || shared
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast())
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let unique_local = (ip.segments()[0] & 0xfe00) == 0xfc00;
    let link_local = (ip.segments()[0] & 0xffc0) == 0xfe80;
    !(ip.is_loopback() || unique_local || link_local || ip.is_unspecified() || ip.is_multicast())
}

/// Whether a download may connect to `ip`: false for loopback, private, shared
/// (100.64.0.0/10), link-local and unique-local addresses, and for unspecified, broadcast and
/// multicast ones. An IPv4-mapped IPv6 address is judged as the IPv4 address it carries.
/// Documentation ranges such as 203.0.113.0/24 are public by this rule.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: ReleaseSpec<'static> = ReleaseSpec {
        owner: "example-org",
        repo: "app",
        artifact_name: "app-*-linux-x86_64.image.tar",
    };
    const GOOD: &str = "https://github.com/example-org/app/releases/download/v1.2.3/app-1.2.3-linux-x86_64.image.tar";
    const GOOD_BUNDLE: &str = "https://github.com/example-org/app/releases/download/v1.2.3/app-1.2.3-linux-x86_64.image.tar.sigstore.json";

    fn image() -> ReleaseUrl {
        check_image_url(GOOD, &SPEC).unwrap()
    }

    #[test]
    fn good_image_url_is_accepted_and_split() {
        let r = image();
        assert_eq!(r.tag(), "v1.2.3");
        assert_eq!(r.file(), "app-1.2.3-linux-x86_64.image.tar");
        assert_eq!(r.url().as_str(), GOOD);
    }

    #[test]
    fn host_is_matched_after_normalisation() {
        let r = check_image_url(&GOOD.replace("github.com", "GitHub.COM"), &SPEC).unwrap();
        assert_eq!(r.url().as_str(), GOOD);
    }

    #[test]
    fn refused_image_urls() {
        let base = "/example-org/app/releases/download/v1/app-1-linux-x86_64.image.tar";
        let release = |owner: &str, repo: &str, mid: &str, file: &str| {
            format!("https://github.com/{owner}/{repo}/{mid}/{file}")
        };
        let cases: Vec<String> = vec![
            format!("http://github.com{base}"),
            format!("ftp://github.com{base}"),
            format!("https://github.com.evil.example{base}"),
            format!("https://api.github.com{base}"),
            format!("https://github.com.{base}"),
            format!("https://127.0.0.1{base}"),
            format!("https://[::1]{base}"),
            format!("https://user@github.com{base}"),
            format!("https://user:pw@github.com{base}"),
            format!("https://:pw@github.com{base}"),
            format!("https://github.com:8443{base}"),
            format!("https://github.com{base}?x=1"),
            format!("https://github.com{base}?"),
            format!("https://github.com{base}#frag"),
            release(
                "other",
                "app",
                "releases/download/v1",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "example-org",
                "other",
                "releases/download/v1",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "Example-Org",
                "app",
                "releases/download/v1",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "example-org",
                "app",
                "release/download/v1",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "example-org",
                "app",
                "releases/downloads/v1",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "example-org",
                "app",
                "releases/download",
                "app-1-linux-x86_64.image.tar",
            ),
            release(
                "example-org",
                "app",
                "releases/download/v1/x",
                "app-1-linux-x86_64.image.tar",
            ),
            "https://github.com/".into(),
            "https://github.com".into(),
            format!("https://github.com{base}/"),
            format!("https://github.com/{base}"),
            release(
                "example-org",
                "app",
                "releases/download/",
                "app-1-linux-x86_64.image.tar",
            ),
            release("example-org", "app", "releases/download/v1", "other.tar"),
            release(
                "example-org",
                "app",
                "releases/download/v1",
                "app-1-linux-x86_64.image.tar.sigstore.json",
            ),
            release(
                "example-org",
                "app",
                "releases/download/v1",
                "app-1-linux-aarch64.image.tar",
            ),
            "data:text/plain,hello".into(),
        ];
        for raw in cases {
            let err = check_image_url(&raw, &SPEC).unwrap_err();
            assert!(
                matches!(err, UrlError::Refused { .. }),
                "{raw} gave {err:?}"
            );
        }
    }

    #[test]
    fn refused_before_parsing() {
        for raw in [
            "https://github.com/example-org/app/releases/download/v1%2e/app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/%2e%2e/app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/v1/app-1-linux-x86_64.image.tar%00",
            "https://github.com\\@evil.example/example-org/app/releases/download/v1/app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/v1\\x/app-1-linux-x86_64.image.tar",
        ] {
            let err = check_image_url(raw, &SPEC).unwrap_err();
            assert!(
                err.to_string().contains("contains a '%' or a '\\'"),
                "{raw}: {err:?}"
            );
        }
        for raw in [
            "https://github.com/example-org/app/releases/download/v1/../app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/./app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/v1/x/../app-1-linux-x86_64.image.tar",
            "https://github.com/../example-org/app/releases/download/v1/app-1-linux-x86_64.image.tar",
            "https://github.com/example-org/app/releases/download/v1/..",
            "https://github.com/example-org/app/releases/download/v1/.",
        ] {
            let err = check_image_url(raw, &SPEC).unwrap_err();
            assert!(
                err.to_string().contains("'.' or '..' segment"),
                "{raw}: {err:?}"
            );
        }
    }

    #[test]
    fn unparseable_text_is_refused() {
        for raw in ["", "github.com/x", "https://", "not a url", "https://[::1"] {
            let err = check_image_url(raw, &SPEC).unwrap_err();
            assert!(
                matches!(err, UrlError::Unparseable { .. }),
                "{raw}: {err:?}"
            );
        }
    }

    #[test]
    fn bundle_url_must_name_the_image_file_plus_suffix() {
        let image = image();
        let ok = check_bundle_url(GOOD_BUNDLE, &SPEC, &image).unwrap();
        assert_eq!(ok.file(), "app-1.2.3-linux-x86_64.image.tar.sigstore.json");

        for raw in [
            // the image's own URL
            GOOD,
            // the bundle of another image of the same release
            "https://github.com/example-org/app/releases/download/v1.2.3/app-9.9.9-linux-x86_64.image.tar.sigstore.json",
            // the suffix alone
            "https://github.com/example-org/app/releases/download/v1.2.3/.sigstore.json",
            // another case of the suffix
            "https://github.com/example-org/app/releases/download/v1.2.3/app-1.2.3-linux-x86_64.image.tar.SIGSTORE.json",
        ] {
            let err = check_bundle_url(raw, &SPEC, &image).unwrap_err();
            assert!(matches!(err, UrlError::Refused { .. }), "{raw}: {err:?}");
        }
    }

    #[test]
    fn bundle_url_gets_the_release_rule_too() {
        let image = image();
        for raw in [
            GOOD_BUNDLE.replace("https", "http"),
            GOOD_BUNDLE.replace("example-org", "other"),
            format!("{GOOD_BUNDLE}?x=1"),
            format!("{GOOD_BUNDLE}%00"),
        ] {
            assert!(check_bundle_url(&raw, &SPEC, &image).is_err(), "{raw}");
        }
    }

    fn hosts() -> Vec<String> {
        vec![
            "objects.githubusercontent.com".into(),
            "release-assets.githubusercontent.com".into(),
        ]
    }

    fn redirect(raw: &str) -> Result<(), UrlError> {
        check_redirect_url(&Url::parse(raw).unwrap(), &hosts())
    }

    #[test]
    fn redirect_to_listed_https_host_is_accepted() {
        redirect("https://objects.githubusercontent.com/blob?sig=abc%2Fdef&x=1").unwrap();
        redirect("https://RELEASE-ASSETS.githubusercontent.com/x").unwrap();
        redirect("https://objects.githubusercontent.com:443/x").unwrap();
    }

    #[test]
    fn redirect_refusals() {
        for raw in [
            "http://objects.githubusercontent.com/x",
            "https://github.com/x",
            "https://evil.objects.githubusercontent.com/x",
            "https://objects.githubusercontent.com.evil.example/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://user@objects.githubusercontent.com/x",
            "https://:pw@objects.githubusercontent.com/x",
            "https://objects.githubusercontent.com:8443/x",
            "data:text/plain,x",
        ] {
            let err = redirect(raw).unwrap_err();
            assert!(matches!(err, UrlError::Refused { .. }), "{raw}: {err:?}");
        }
        assert!(check_redirect_url(&Url::parse("https://x.example/").unwrap(), &[]).is_err());
        let password_only = Url::parse("https://:pw@objects.githubusercontent.com/x").unwrap();
        assert_eq!(
            (password_only.username(), password_only.password()),
            ("", Some("pw"))
        );
        assert!(
            redirect(password_only.as_str())
                .unwrap_err()
                .to_string()
                .contains("user info")
        );
    }

    #[test]
    fn errors_name_the_url_and_the_rule() {
        let refused = redirect("http://objects.githubusercontent.com/x")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("http://objects.githubusercontent.com/x"));
        assert!(refused.contains("redirects must go to https"));
        let parse = check_image_url("", &SPEC).unwrap_err().to_string();
        assert!(parse.contains("not acceptable"));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses() {
        for s in [
            "198.51.100.7",
            "192.0.2.3",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "203.0.113.10",
            "2001:db8:8000::154",
            "2001:db8::1",
            "::ffff:192.0.2.3",
            "fe00::1",
            "fbff::1",
            "fec0::1",
        ] {
            assert!(is_public(ip(s)), "{s}");
        }
    }

    #[test]
    fn refused_addresses() {
        for s in [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
        ] {
            assert!(!is_public(ip(s)), "{s}");
        }
    }
}
