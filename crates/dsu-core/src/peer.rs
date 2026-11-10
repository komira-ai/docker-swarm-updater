//! The peer rule of docs/design.md section 1: which connections may do what, from the
//! peer's uid and whether the request carries the claims header.

/// Who a request is accepted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The fronting proxy, speaking for the caller named in the claims header.
    Proxy,
    /// The local operator: uid 0, no claims, `--allow-local-operator` given.
    Operator,
    /// `GET /v1/health` only: any peer that can open the socket.
    Anyone,
}

/// Why a request is refused at the peer rule; both answer 401.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerRefusal {
    /// The uid is not allowed to send this kind of request.
    #[error("bad_peer: this peer may not send this request")]
    BadPeer,
    /// The proxy's uid sent a request without the claims header.
    #[error("no_claims: the request carries no claims header")]
    NoClaims,
}

impl PeerRefusal {
    /// The `error` token of the answer.
    pub fn token(self) -> &'static str {
        match self {
            PeerRefusal::BadPeer => "bad_peer",
            PeerRefusal::NoClaims => "no_claims",
        }
    }
}

/// Decides whether a request from `peer_uid` is accepted, and as whom.
///
/// - `GET /v1/health` (`is_health`) is accepted from any peer, with or without claims.
/// - With claims: only from `proxy_uid`; a claims header from uid 0 is always refused.
/// - Without claims: from `proxy_uid`, `no_claims`; from uid 0 with `allow_local_operator`,
///   the operator; from anyone else, `bad_peer`.
pub fn admit(
    peer_uid: u32,
    has_claims: bool,
    is_health: bool,
    proxy_uid: u32,
    allow_local_operator: bool,
) -> Result<Principal, PeerRefusal> {
    if is_health {
        return Ok(Principal::Anyone);
    }
    let is_proxy = peer_uid == proxy_uid && peer_uid != 0;
    match (has_claims, is_proxy) {
        (true, true) => Ok(Principal::Proxy),
        (true, false) => Err(PeerRefusal::BadPeer),
        (false, true) => Err(PeerRefusal::NoClaims),
        (false, false) if peer_uid == 0 && allow_local_operator => Ok(Principal::Operator),
        (false, false) => Err(PeerRefusal::BadPeer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: u32 = 1234;
    const OTHER: u32 = 4321;

    fn run(uid: u32, claims: bool, operator: bool) -> Result<Principal, PeerRefusal> {
        admit(uid, claims, false, PROXY, operator)
    }

    #[test]
    fn claims_from_the_proxy_uid_are_accepted() {
        assert_eq!(run(PROXY, true, false), Ok(Principal::Proxy));
        assert_eq!(run(PROXY, true, true), Ok(Principal::Proxy));
    }

    #[test]
    fn claims_from_another_uid_or_from_root_are_bad_peer() {
        assert_eq!(run(OTHER, true, true), Err(PeerRefusal::BadPeer));
        assert_eq!(run(0, true, true), Err(PeerRefusal::BadPeer));
        assert_eq!(run(0, true, false), Err(PeerRefusal::BadPeer));
    }

    #[test]
    fn claims_from_root_are_refused_even_if_the_proxy_uid_were_root() {
        assert_eq!(admit(0, true, false, 0, true), Err(PeerRefusal::BadPeer));
    }

    #[test]
    fn no_claims_from_root_needs_the_operator_flag() {
        assert_eq!(run(0, false, true), Ok(Principal::Operator));
        assert_eq!(run(0, false, false), Err(PeerRefusal::BadPeer));
    }

    #[test]
    fn no_claims_from_another_uid_is_bad_peer_and_from_the_proxy_is_no_claims() {
        assert_eq!(run(OTHER, false, true), Err(PeerRefusal::BadPeer));
        assert_eq!(run(PROXY, false, true), Err(PeerRefusal::NoClaims));
        assert_eq!(run(PROXY, false, false), Err(PeerRefusal::NoClaims));
    }

    #[test]
    fn health_is_open_to_any_peer_with_or_without_claims() {
        for uid in [0, PROXY, OTHER] {
            for claims in [false, true] {
                assert_eq!(
                    admit(uid, claims, true, PROXY, false),
                    Ok(Principal::Anyone)
                );
            }
        }
    }

    #[test]
    fn tokens_name_the_refusal() {
        assert_eq!(PeerRefusal::BadPeer.token(), "bad_peer");
        assert_eq!(PeerRefusal::NoClaims.token(), "no_claims");
        assert!(PeerRefusal::BadPeer.to_string().starts_with("bad_peer"));
        assert!(PeerRefusal::NoClaims.to_string().starts_with("no_claims"));
    }
}
