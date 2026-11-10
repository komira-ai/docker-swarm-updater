//! Who a request is from (docs/design.md section 3.1 step 1): the peer rule, the claims
//! header, the token's expiry and its single use.

use dsu_core::api::ApiError;
use dsu_core::claims::Claims;
use dsu_core::config::ServiceConfig;
use dsu_core::peer::{Principal, admit};
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

/// Applies the checks of step 1 in order to a request from `peer_uid`: the peer rule
/// (`bad_peer`, `no_claims`), the claims parse (`bad_request`), `exp` (`expired`) and the
/// `jti` (`replayed`, spent now). `is_health` requests are accepted from any peer and read no
/// claims.
pub async fn authenticate(
    app: &App,
    peer_uid: u32,
    is_health: bool,
    headers: &HeaderMap,
) -> Result<Authenticated, ApiError> {
    let has_claims = headers.contains_key(CLAIMS_HEADER);
    let principal = admit(
        peer_uid,
        has_claims,
        is_health,
        app.proxy_uid,
        app.allow_local_operator,
    )?;
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
