//! [`Http`] over ureq: plain HTTP for the deploy front inside the tailnet, HTTPS with the
//! Mozilla roots for GitHub's token endpoint. Redirects are not followed, any status is an
//! answer, every request has [`REQUEST_TIMEOUT`] from connect to the last byte, and no proxy
//! is used: ureq's default would read `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`
//! from the environment, and this client reads no setting from there.

use std::sync::Arc;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::client::{Http, Method, Request, Response, TransportError};

/// The longest an answer body may be, in bytes.
pub const MAX_ANSWER_BYTES: u64 = 1024 * 1024;

/// How long one request may take, connect to last byte.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The real [`Http`].
#[derive(Debug)]
pub struct UreqHttp {
    agent: ureq::Agent,
}

impl UreqHttp {
    /// An agent trusting the Mozilla roots for HTTPS.
    pub fn new() -> Self {
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::WebPki)
            .unversioned_rustls_crypto_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .proxy(None)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self { agent }
    }
}

impl Default for UreqHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl Http for UreqHttp {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let failed = |message: String| TransportError {
            url: request.url.clone(),
            message,
        };
        let bearer = format!("Bearer {}", request.bearer);
        let sent = match (request.method, &request.body) {
            (Method::Post, body) => self
                .agent
                .post(&request.url)
                .header("authorization", &bearer)
                .header("content-type", "application/json")
                .send(body.as_deref().unwrap_or_default()),
            (Method::Get, _) => self
                .agent
                .get(&request.url)
                .header("authorization", &bearer)
                .call(),
        };
        let response = sent.map_err(|e| failed(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .into_with_config()
            // ureq refuses a body of exactly its limit, so the limit is one more than the most
            // that is accepted.
            .limit(MAX_ANSWER_BYTES + 1)
            .read_to_vec()
            .map_err(|e| failed(format!("reading the answer: {e}")))?;
        Ok(Response { status, body })
    }
}
