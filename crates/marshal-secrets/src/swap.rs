//! Boundary secret injection: swapping a placeholder the agent holds for the real credential.
//!
//! # Why a placeholder rather than blind injection
//!
//! The alternative — the proxy simply adding an `Authorization` header to every request to a
//! host — is easier for the agent but strictly weaker: any request the agent can be tricked
//! into making becomes an authenticated one.
//!
//! With a placeholder, the security property is narrower and more useful than "the agent
//! cannot authenticate". A prompt-injected agent *can* still use its placeholder against
//! hosts the chain allows. What it cannot do is exfiltrate anything of value: the placeholder
//! is worthless outside this proxy, and the real credential never exists inside the agent's
//! process, filesystem, or environment. Compromise of the agent stops costing you a
//! credential rotation.

use std::sync::Arc;

use marshal_core::{
    BodyRequirement, Error, RequestContext, RequestTransform, Result, SecretSource, SecretValue,
};
use marshal_policy::HostMatcher;

/// Where a placeholder may appear, and so where it is swapped.
#[derive(Debug, Clone)]
pub struct MatchSites {
    /// Header names scanned. Empty means every header.
    pub headers: Vec<String>,
    pub query: bool,
    pub body: bool,
}

impl Default for MatchSites {
    fn default() -> Self {
        Self { headers: vec!["authorization".into()], query: false, body: false }
    }
}

/// One placeholder-to-secret mapping.
pub struct SecretSwap {
    /// Name for the audit trail. Never the value.
    pub name: String,
    pub source: Arc<dyn SecretSource>,
    /// What the agent sends. Safe to log; useless anywhere but here.
    pub proxy_value: String,
    pub sites: MatchSites,
    /// Refuse a matching request that does not carry the placeholder, rather than forwarding
    /// it unauthenticated and letting the agent see a confusing 401 from the upstream.
    pub require: bool,
    pub hosts: HostMatcher,
}

impl std::fmt::Debug for SecretSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSwap")
            .field("name", &self.name)
            .field("proxy_value", &self.proxy_value)
            .field("require", &self.require)
            .finish_non_exhaustive()
    }
}

/// Applies every configured swap to an allowed request.
#[derive(Debug)]
pub struct SecretInjector {
    swaps: Vec<SecretSwap>,
}

impl SecretInjector {
    pub fn new(swaps: Vec<SecretSwap>) -> Self {
        Self { swaps }
    }

    pub fn is_empty(&self) -> bool {
        self.swaps.is_empty()
    }

    /// Every placeholder configured, so the audit layer can tell them apart from real values.
    pub fn proxy_values(&self) -> Vec<String> {
        self.swaps.iter().map(|s| s.proxy_value.clone()).collect()
    }

    /// Resolve every source once, for seeding the redactor at startup.
    pub async fn resolve_all(&self) -> Vec<(String, SecretValue)> {
        let mut out = Vec::new();
        for swap in &self.swaps {
            match swap.source.resolve().await {
                Ok(v) => out.push((swap.name.clone(), v)),
                Err(e) => {
                    tracing::warn!(secret = %swap.name, error = %e, "could not resolve a secret");
                }
            }
        }
        out
    }
}

#[async_trait::async_trait]
impl RequestTransform for SecretInjector {
    fn name(&self) -> &str {
        "secrets"
    }

    fn body_requirement(&self) -> BodyRequirement {
        // Only if some swap actually scans bodies. Buffering every request because one
        // profile *might* need it would silently stop uploads streaming.
        if self.swaps.iter().any(|s| s.sites.body) {
            BodyRequirement::Buffered { cap: 1024 * 1024 }
        } else {
            BodyRequirement::Streaming
        }
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        for swap in &self.swaps {
            if swap.hosts.matches(&cx.authority.host).is_none() {
                continue;
            }

            let mut swapped_anywhere = false;

            // Resolve lazily: a request that never presents the placeholder should not cause
            // the real credential to be read at all.
            let present = placeholder_present(cx, swap);
            if !present {
                if swap.require {
                    return Err(Error::Config(format!(
                        "requests to `{}` must carry the `{}` placeholder, but this one did \
                         not. Send `{}` where the credential would normally go.",
                        cx.authority.host, swap.name, swap.proxy_value
                    )));
                }
                continue;
            }

            let real = swap.source.resolve().await?;

            for (name, value) in cx.headers.clone().iter() {
                if !swap.sites.headers.is_empty()
                    && !swap.sites.headers.iter().any(|h| h.eq_ignore_ascii_case(name.as_str()))
                {
                    continue;
                }
                let Ok(text) = value.to_str() else { continue };
                if !text.contains(&swap.proxy_value) {
                    continue;
                }
                let replaced = text.replace(&swap.proxy_value, real.expose());
                if let Ok(v) = http::HeaderValue::from_str(&replaced) {
                    cx.headers.insert(name.clone(), v);
                    swapped_anywhere = true;
                }
            }

            if swap.sites.query
                && let Some(q) = cx.uri.query()
                && q.contains(&swap.proxy_value)
            {
                let new_q = q.replace(&swap.proxy_value, real.expose());
                let path = cx.uri.path();
                if let Ok(uri) = format!("{path}?{new_q}").parse::<http::Uri>() {
                    cx.uri = uri;
                    swapped_anywhere = true;
                }
            }

            if swap.sites.body
                && let marshal_core::BodyHandle::Buffered(bytes) = &cx.body
                && let Ok(text) = std::str::from_utf8(bytes)
                && text.contains(&swap.proxy_value)
            {
                let replaced = text.replace(&swap.proxy_value, real.expose());
                cx.body = marshal_core::BodyHandle::Buffered(bytes::Bytes::from(replaced));
                swapped_anywhere = true;
            }

            if swapped_anywhere {
                // The name, never the value.
                cx.evidence.record(format!("secrets.swapped.{}", swap.name), true);
            }
        }
        Ok(())
    }
}

/// Whether the placeholder appears anywhere this swap is configured to look.
fn placeholder_present(cx: &RequestContext, swap: &SecretSwap) -> bool {
    let in_headers = cx.headers.iter().any(|(name, value)| {
        if !swap.sites.headers.is_empty()
            && !swap.sites.headers.iter().any(|h| h.eq_ignore_ascii_case(name.as_str()))
        {
            return false;
        }
        value.to_str().map(|t| t.contains(&swap.proxy_value)).unwrap_or(false)
    });
    if in_headers {
        return true;
    }

    if swap.sites.query && cx.uri.query().map(|q| q.contains(&swap.proxy_value)).unwrap_or(false) {
        return true;
    }

    if swap.sites.body
        && let marshal_core::BodyHandle::Buffered(bytes) = &cx.body
        && let Ok(text) = std::str::from_utf8(bytes)
        && text.contains(&swap.proxy_value)
    {
        return true;
    }

    false
}
