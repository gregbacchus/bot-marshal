//! Identity, derived from the connection rather than asserted by the client.
//!
//! Transparent and DNS ingress give the client no channel to present a credential — it
//! believes it is talking to the origin — so identity has to come from what the kernel knows
//! about the connection.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::request::IngressMode;

/// Which agent or task a connection belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Identity(pub Arc<str>);

impl Identity {
    pub fn new(s: impl AsRef<str>) -> Self {
        Identity(Arc::from(s.as_ref()))
    }

    /// The synthetic identity used when no resolver matched.
    pub fn unidentified() -> Self {
        Identity::new("unidentified")
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Kernel-supplied credentials for the peer.
///
/// `uid` and `gid` are supplied by the kernel and cannot be asserted by the client, so they
/// are safe to trust for policy. `pid`, `cgroup` and `cmdline` require a `/proc` walk that is
/// racy for short-lived processes, so they default to audit annotation only.
#[derive(Debug, Clone, Default)]
pub struct PeerCred {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub pid: Option<u32>,
    pub cgroup: Option<String>,
    pub cmdline: Option<String>,
}

impl PeerCred {
    /// True when only kernel-supplied, non-spoofable fields are populated.
    pub fn is_trusted_for_policy(&self) -> bool {
        self.uid.is_some() || self.gid.is_some()
    }
}

/// What an [`IdentityResolver`] gets to look at.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub ingress: IngressMode,
    pub client_addr: SocketAddr,
    /// Which listener accepted. Carries the identity when nftables steers uid or cgroup to a
    /// dedicated port.
    pub local_addr: SocketAddr,
    /// Explicit mode only.
    pub proxy_auth: Option<Credential>,
    pub peer_cred: Option<PeerCred>,
}

/// A `Proxy-Authorization` credential. Client-asserted, so only as strong as the secret.
#[derive(Clone)]
pub struct Credential {
    pub user: String,
    pub password: String,
}

// Hand-written so a credential can never reach a log line via `{:?}`.
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// The outcome of identity resolution.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub identity: Identity,
    pub profile: Arc<str>,
    /// `false` when no resolver matched. The audit record says so, and the most restrictive
    /// profile applies — an unattributed request never silently inherits a permissive one.
    pub attributed: bool,
    /// Which resolver matched, for audit.
    pub resolver: Option<String>,
}

/// Resolvers are tried in order; first match wins.
#[async_trait::async_trait]
pub trait IdentityResolver: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    /// `None` means "no opinion" — try the next resolver.
    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_debug_redacts_password() {
        let c = Credential { user: "agent-a".into(), password: "hunter2".into() };
        let rendered = format!("{c:?}");
        assert!(rendered.contains("agent-a"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn peer_cred_trust() {
        assert!(PeerCred { uid: Some(1000), ..Default::default() }.is_trusted_for_policy());
        // cgroup alone is enrichment, not a trusted policy input
        assert!(
            !PeerCred { cgroup: Some("/user.slice".into()), ..Default::default() }
                .is_trusted_for_policy()
        );
    }
}
