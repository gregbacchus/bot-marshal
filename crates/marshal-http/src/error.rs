//! What can go wrong on an outbound call marshal makes for itself.

use crate::guard::GuardError;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("resolving {0}")]
    Resolve(#[source] std::io::Error),
    #[error("connecting: {0}")]
    Connect(#[source] std::io::Error),
    #[error("tls handshake: {0}")]
    Tls(#[source] std::io::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::Error),
    #[error("returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("the response exceeded {limit} bytes without completing")]
    ResponseTooLarge { limit: usize },
    #[error("malformed json in the response: {0}")]
    MalformedJson(#[source] serde_json::Error),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// The upstream guard refused the destination. Distinct from [`HttpError::Connect`] on
    /// purpose: "we would not talk to that address" and "we could not reach it" are different
    /// facts, and an operator debugging a blocked token endpoint needs to see which one.
    #[error(transparent)]
    Blocked(#[from] GuardError),
}
