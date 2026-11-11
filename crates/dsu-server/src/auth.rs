//! Who a request is from (docs/design.md section 3.1 step 1): the peer rule, the claims
//! header, the token's expiry and its single use.

use dsu_core::api::ApiError;
use dsu_core::claims::Claims;
use dsu_core::config::ServiceConfig;
use dsu_core::peer::{PeerRefusal, Principal, admit};
use http::HeaderMap;
use http::header::HeaderName;

use crate::app::App;

/// The header the proxy sets to the base64url payload of the verified token.
pub const CLAIMS_HEADER: HeaderName = HeaderName::from_static("x-dsu-claims");

/// A request that passed the peer rule and, from the proxy, the claims checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    /// Who the peer is accepted as.
    pub principal: Principal,
    /// The claims; present exactly for [`Principal::Proxy`].
    pub claims: Option<Claims>,
}

impl Authenticated {
    /// Whether the local operator sent the request.
    pub fn is_operator(&self) -> bool {
        self.principal == Principal::Operator
    }

    /// Whether the request may act on `service`: the operator on any, a caller on the
    /// services one of whose callers equals its claims.
    pub fn may_act_on(&self, service: &ServiceConfig) -> bool {
        self.is_operator() || self.claims.as_ref().is_some_and(|c| service.has_caller(c))
    }
}

/// The one claims header of the request, as text.
fn claims_text(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(CLAIMS_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .map_err(|_| ApiError::BadRequest("the claims header is not text".into())),
        _ => Err(ApiError::BadRequest(
            "the request must carry exactly one claims header".into(),
        )),
    }
}

/// The detail of a refusal at the peer rule: which rule the peer broke. uid 0 without claims
/// is refused only when `--allow-local-operator` is not given.
fn peer_refusal(refusal: PeerRefusal, peer_uid: u32, has_claims: bool) -> ApiError {
    match refusal {
        PeerRefusal::NoClaims => refusal.into(),
        PeerRefusal::BadPeer => ApiError::BadPeer(match (has_claims, peer_uid) {
            (true, 0) => "a claims header is never accepted from uid 0".into(),
            (true, uid) => {
                format!("a claims header is accepted only from --proxy-uid, not from uid {uid}")
            }
            (false, 0) => {
                "uid 0 is the local operator only when the updater runs with --allow-local-operator"
                    .into()
            }
            (false, uid) => format!(
                "a request without a claims header is accepted only from uid 0, not from uid {uid}"
            ),
        }),
    }
}

/// Applies the checks of step 1 in order to a request from a peer with uid `peer_uid` (or
/// the reason the peer's uid cannot be read): the peer rule (`bad_peer`, `no_claims`), the
/// claims parse (`bad_request`), `exp` (`expired`) and the `jti` (`replayed`, spent now).
/// `is_health` requests are accepted from any peer, even one whose uid cannot be read, and
/// read no claims.
pub async fn authenticate(
    app: &App,
    peer_uid: Result<u32, &str>,
    is_health: bool,
    headers: &HeaderMap,
) -> Result<Authenticated, ApiError> {
    let has_claims = headers.contains_key(CLAIMS_HEADER);
    let principal = match peer_uid {
        Ok(uid) => admit(
            uid,
            has_claims,
            is_health,
            app.proxy_uid,
            app.allow_local_operator,
        )
        .map_err(|r| peer_refusal(r, uid, has_claims))?,
        Err(_) if is_health => Principal::Anyone,
        Err(reason) => {
            return Err(ApiError::BadPeer(format!(
                "the peer's credentials cannot be read: {reason}"
            )));
        }
    };
    if principal != Principal::Proxy {
        return Ok(Authenticated {
            principal,
            claims: None,
        });
    }
    let claims = Claims::from_header(claims_text(headers)?)
        .map_err(|e| ApiError::BadRequest(e.to_string().replace('\n', " ")))?;
    let now = app.clock.now();
    if claims.is_expired(now) {
        return Err(ApiError::Expired(format!(
            "the token expired at {}",
            claims.exp
        )));
    }
    if !app.store.spend_jti(&claims.jti, claims.exp, now).await? {
        return Err(ApiError::Replayed(
            "the token's jti was already used".into(),
        ));
    }
    Ok(Authenticated {
        principal,
        claims: Some(claims),
    })
}
