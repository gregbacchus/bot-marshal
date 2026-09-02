//! The request context every ingress mode converges on.

use crate::evidence::Evidence;
use crate::session::SessionId;
use std::net::SocketAddr;
use std::sync::Arc;

/// How the traffic reached us. Recorded for audit, but **must not** be branched on downstream
/// of ingress: the whole point of the design is that all three modes produce one context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    /// Client set `HTTP_PROXY`/`ALL_PROXY`: HTTP `CONNECT` or SOCKS5.
    Explicit,
    /// nftables/iptables REDIRECT; destination recovered via `SO_ORIGINAL_DST`.
    Transparent,
    /// Client's DNS resolved the hostname to us.
    Dns,
}

/// Which decision point this context represents.
///
/// A `CONNECT` names a destination and nothing else — there is no method, path or body to
/// judge yet. Layers that need a real request are skipped in that phase and evaluate later,
/// once TLS has been terminated and the actual request is visible. Without this distinction a
/// rule written for real traffic would refuse the tunnel before interception could happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Deciding whether to open a tunnel to a destination.
    Connect,
    /// Deciding on a real request.
    Request,
}

/// `host:port` for the upstream, recovered from `CONNECT`, SNI, or the `Host` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Authority {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// A handle to a request or response body.
///
/// Bodies stream by default. A layer that needs bytes calls [`BodyHandle::buffered`] with an
/// explicit cap; exceeding the cap is a configured decision, never a silent truncation.
#[derive(Debug)]
pub enum BodyHandle {
    /// No body, or one not yet read.
    Empty,
    /// Fully buffered because some layer asked for it.
    Buffered(bytes::Bytes),
    /// Streaming; bytes have not been (and may never be) materialised.
    Streaming,
}

impl BodyHandle {
    pub fn as_bytes(&self) -> Option<&bytes::Bytes> {
        match self {
            BodyHandle::Buffered(b) => Some(b),
            _ => None,
        }
    }
}

/// Everything a policy layer or transform can see about one request.
#[derive(Debug)]
pub struct RequestContext {
    pub session: SessionId,
    /// Name of the resolved profile. The profile itself lives in `marshal-config`, which
    /// depends on this crate, so it is referenced by name here to keep the dependency acyclic.
    pub profile: Arc<str>,
    pub ingress: IngressMode,
    pub phase: Phase,
    pub client_addr: SocketAddr,
    pub authority: Authority,
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub body: BodyHandle,
    /// Evidence accumulated so far. Layers receive this read-only and return additions via
    /// [`Verdict::Pass`](crate::verdict::Verdict::Pass); the chain runner merges.
    pub evidence: Evidence,
}

/// The response side, as seen by response-phase policy layers and response transforms.
#[derive(Debug)]
pub struct ResponseParts {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: BodyHandle,
}
