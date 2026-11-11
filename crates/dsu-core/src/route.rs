//! Request-target routing (docs/design.md section 2): the method and the raw request target
//! are matched byte for byte, before any decoding.

use crate::ids::{DeployId, Digest, ServiceName};

/// A request that matched an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `POST /v1/services/{service}/deploys`.
    Deploy {
        /// The `{service}` segment.
        service: ServiceName,
    },
    /// `GET /v1/deploys/{id}`.
    Status {
        /// The `{id}` segment.
        id: DeployId,
    },
    /// `GET /v1/services`.
    List,
    /// `DELETE /v1/services/{service}/failed/{digest}`.
    ClearFailed {
        /// The `{service}` segment.
        service: ServiceName,
        /// The `{digest}` segment.
        digest: Digest,
    },
    /// `GET /v1/health`.
    Health,
}

/// A request that matched no endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RouteRefusal {
    /// No path matches: 404 `not_found`.
    #[error("not_found: no such path")]
    NotFound,
    /// The path exists for other methods: 405 `method_not_allowed`.
    #[error("method_not_allowed: this path answers {allow} only")]
    MethodNotAllowed {
        /// The method the path answers, for the `allow` header.
        allow: &'static str,
    },
}

/// The path of a request, before the method is looked at.
enum Path {
    Health,
    Services,
    Deploys(ServiceName),
    Deploy(DeployId),
    Failed(ServiceName, Digest),
}

fn text(segment: &[u8]) -> Option<&str> {
    std::str::from_utf8(segment).ok()
}

fn service(segment: &[u8]) -> Option<ServiceName> {
    ServiceName::parse(text(segment)?).ok()
}

fn parse_path(target: &[u8]) -> Option<Path> {
    let rest = target.strip_prefix(b"/v1/")?;
    let segments: Vec<&[u8]> = rest.split(|b| *b == b'/').collect();
    match segments.as_slice() {
        [b"health"] => Some(Path::Health),
        [b"services"] => Some(Path::Services),
        [b"services", name, b"deploys"] => service(name).map(Path::Deploys),
        [b"services", name, b"failed", digest] => {
            let digest = Digest::parse(text(digest)?).ok()?;
            Some(Path::Failed(service(name)?, digest))
        }
        [b"deploys", id] => DeployId::parse(text(id)?).ok().map(Path::Deploy),
        _ => None,
    }
}

/// Routes `method` and the raw request `target` (the bytes of the request line, query string
/// included). A `%`, `..`, `//`, a trailing slash, an upper-case letter or a query string
/// never matches (`NotFound`); a known path with another method is `MethodNotAllowed`.
pub fn route(method: &str, target: &[u8]) -> Result<Route, RouteRefusal> {
    let path = parse_path(target).ok_or(RouteRefusal::NotFound)?;
    let (allow, route) = match path {
        Path::Health => ("GET", Route::Health),
        Path::Services => ("GET", Route::List),
        Path::Deploys(service) => ("POST", Route::Deploy { service }),
        Path::Deploy(id) => ("GET", Route::Status { id }),
        Path::Failed(service, digest) => ("DELETE", Route::ClearFailed { service, digest }),
    };
    if method == allow {
        Ok(route)
    } else {
        Err(RouteRefusal::MethodNotAllowed { allow })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "d-abcdefghijklmnopqrstuvwxyz";
    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn svc(name: &str) -> ServiceName {
        ServiceName::parse(name).unwrap()
    }

    #[test]
    fn every_endpoint_routes() {
        assert_eq!(route("GET", b"/v1/health"), Ok(Route::Health));
        assert_eq!(route("GET", b"/v1/services"), Ok(Route::List));
        assert_eq!(
            route("POST", b"/v1/services/app-1/deploys"),
            Ok(Route::Deploy {
                service: svc("app-1")
            })
        );
        assert_eq!(
            route("GET", format!("/v1/deploys/{ID}").as_bytes()),
            Ok(Route::Status {
                id: DeployId::parse(ID).unwrap()
            })
        );
        assert_eq!(
            route(
                "DELETE",
                format!("/v1/services/app/failed/{DIGEST}").as_bytes()
            ),
            Ok(Route::ClearFailed {
                service: svc("app"),
                digest: Digest::parse(DIGEST).unwrap()
            })
        );
    }

    #[test]
    fn a_known_path_with_another_method_is_405_naming_the_method() {
        let cases: [(&str, String, &str); 5] = [
            ("POST", "/v1/health".into(), "GET"),
            ("DELETE", "/v1/services".into(), "GET"),
            ("GET", "/v1/services/app/deploys".into(), "POST"),
            ("POST", format!("/v1/deploys/{ID}"), "GET"),
            ("GET", format!("/v1/services/app/failed/{DIGEST}"), "DELETE"),
        ];
        for (method, target, allow) in cases {
            assert_eq!(
                route(method, target.as_bytes()),
                Err(RouteRefusal::MethodNotAllowed { allow }),
                "{method} {target}"
            );
        }
        assert_eq!(
            route("get", b"/v1/health"),
            Err(RouteRefusal::MethodNotAllowed { allow: "GET" })
        );
        assert_eq!(
            route("HEAD", b"/v1/health"),
            Err(RouteRefusal::MethodNotAllowed { allow: "GET" })
        );
    }

    #[test]
    fn anything_else_is_404() {
        let bad: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"/".to_vec(),
            b"v1/health".to_vec(),
            b"/v2/health".to_vec(),
            b"/v1".to_vec(),
            b"/v1/".to_vec(),
            b"/v1/health/".to_vec(),
            b"/v1/health?x=1".to_vec(),
            b"/v1/services?x=1".to_vec(),
            b"/v1//health".to_vec(),
            b"//v1/health".to_vec(),
            b"/v1/Health".to_vec(),
            b"/v1/%68ealth".to_vec(),
            b"/v1/services/".to_vec(),
            b"/v1/services/app".to_vec(),
            b"/v1/services/app/deploys/".to_vec(),
            b"/v1/services/app/deploys?x".to_vec(),
            b"/v1/services//deploys".to_vec(),
            b"/v1/services/../deploys".to_vec(),
            b"/v1/services/%2e%2e/deploys".to_vec(),
            b"/v1/services/App/deploys".to_vec(),
            b"/v1/services/a_b/deploys".to_vec(),
            format!("/v1/services/{}/deploys", "a".repeat(64)).into_bytes(),
            vec![
                b'/', b'v', b'1', b'/', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', b'/', 0xff,
                b'/', b'd', b'e', b'p', b'l', b'o', b'y', b's',
            ],
            b"/v1/services/app/failed".to_vec(),
            b"/v1/services/app/failed/".to_vec(),
            format!("/v1/services/app/failed/{DIGEST}/").into_bytes(),
            format!("/v1/services/app/failed/{DIGEST}?x").into_bytes(),
            format!("/v1/services/app/failed/{}", DIGEST.to_uppercase()).into_bytes(),
            format!("/v1/services/app/failed/{}", &DIGEST[..DIGEST.len() - 1]).into_bytes(),
            format!(
                "/v1/services/app/failed/{}\u{e9}",
                &DIGEST[..DIGEST.len() - 1]
            )
            .into_bytes(),
            [b"/v1/services/app/failed/".as_slice(), &[0xff]].concat(),
            format!("/v1/services/App/failed/{DIGEST}").into_bytes(),
            b"/v1/deploys".to_vec(),
            format!("/v1/deploys/{ID}/").into_bytes(),
            format!("/v1/deploys/{ID}?x").into_bytes(),
            format!("/v1/deploys/{}", ID.to_uppercase()).into_bytes(),
            format!("/v1/deploys/{ID}%").into_bytes(),
            [b"/v1/deploys/".as_slice(), &[0xff]].concat(),
            b"/v1/other".to_vec(),
        ];
        for target in bad {
            for method in ["GET", "POST", "DELETE"] {
                assert_eq!(
                    route(method, &target),
                    Err(RouteRefusal::NotFound),
                    "{target:?}"
                );
            }
        }
    }

    #[test]
    fn refusals_render_their_token() {
        assert!(RouteRefusal::NotFound.to_string().starts_with("not_found"));
        assert!(
            RouteRefusal::MethodNotAllowed { allow: "POST" }
                .to_string()
                .contains("POST")
        );
    }
}
