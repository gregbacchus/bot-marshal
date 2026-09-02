//! The swappable part of a running proxy.
//!
//! Everything derived from configuration lives here behind one pointer, so a reload is a
//! single atomic replacement rather than a sequence of updates that a request could be
//! caught halfway through. A connection reads the pointer once and keeps that view for its
//! lifetime, which means a reload never changes the rules under a request already in flight.
//!
//! The invariant that matters more than atomicity: **a reload that fails changes nothing.**
//! The new configuration is built completely — every chain, every transform, every resolver —
//! before the swap happens. A proxy that half-applied a broken config would be enforcing a
//! policy nobody wrote.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use marshal_core::{RequestTransform, ResponseTransform};
use marshal_policy::{Chain, HostMatcher};

use crate::mitm::TlsEngine;
use crate::sessions::SessionRegistry;

/// A complete, self-consistent view of the configuration.
pub struct Runtime {
    /// Every *named* profile — nothing here for the base config's embedded `profile:`, which
    /// has no name and lives in `default_chain`/`default_response_transforms`/
    /// `default_request_transforms` instead.
    pub chains: HashMap<Arc<str>, Arc<Chain>>,
    pub response_transforms: HashMap<Arc<str>, Vec<Arc<dyn ResponseTransform>>>,
    /// Per profile, exactly like `chains` and `response_transforms`: a profile's
    /// `request_transforms.secrets` is only meaningful for sessions resolved into that
    /// profile, and must not leak into another profile's requests.
    pub request_transforms: HashMap<Arc<str>, Vec<Arc<dyn RequestTransform>>>,
    /// The chain for the base config's embedded, unnamed `profile:` — used whenever a
    /// connection is unattributed and `sessions.unidentified.profile` did not name a
    /// different, real profile instead. See [`crate::sessions::SessionRegistry::uses_default_fallback`].
    pub default_chain: Arc<Chain>,
    pub default_response_transforms: Vec<Arc<dyn ResponseTransform>>,
    pub default_request_transforms: Vec<Arc<dyn RequestTransform>>,
    pub sessions: Arc<SessionRegistry>,
    /// Hosts tunnelled without interception, for genuinely certificate-pinned clients. The
    /// only sanctioned exception to interception — see [`Runtime::tls`].
    pub passthrough: HostMatcher,
    /// Mandatory, not optional. A plain byte relay cannot enforce per-request policy, and
    /// worse, it cannot even guarantee the client ends up talking to the host it claimed:
    /// shared-IP hosting (CDNs, load balancers) routes by the TLS SNI inside the tunnel,
    /// which a relay never inspects. A client can `CONNECT good.example.com` — allowed,
    /// correctly resolved and connected — then present `SNI: evil.example.com` and have the
    /// origin serve that content instead, entirely unseen by the proxy. Interception defeats
    /// this structurally: the proxy re-originates its own TLS to upstream keyed on the
    /// CONNECT authority, never on anything the client claims inside the tunnel.
    pub tls: Arc<TlsEngine>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("profiles", &self.chains.keys().map(|k| &**k).collect::<Vec<_>>())
            .field("intercepting", &true)
            .finish()
    }
}

impl Runtime {
    /// Profiles currently in warn mode, so the fact can be surfaced rather than buried.
    pub fn warn_only_profiles(&self) -> Vec<&str> {
        let mut names: Vec<&str> =
            self.chains.iter().filter(|(_, c)| c.is_warn_only()).map(|(name, _)| &**name).collect();
        names.sort_unstable();
        names
    }
}

/// Holds the current [`Runtime`] and swaps it wholesale.
#[derive(Debug)]
pub struct RuntimeHandle {
    current: RwLock<Arc<Runtime>>,
    /// Reloads that succeeded, for the management API to report.
    generation: std::sync::atomic::AtomicU64,
}

impl RuntimeHandle {
    pub fn new(runtime: Runtime) -> Self {
        Self {
            current: RwLock::new(Arc::new(runtime)),
            generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The current view. Cheap, and taken once per connection so a reload cannot change the
    /// rules mid-request.
    pub fn load(&self) -> Arc<Runtime> {
        Arc::clone(&self.current.read().expect("runtime lock"))
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Replace the runtime. Callers build the new one first, so this cannot fail partway.
    pub fn store(&self, runtime: Runtime) {
        *self.current.write().expect("runtime lock") = Arc::new(runtime);
        self.generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::{Decision, DenyingDecider};

    fn runtime(profile: &str, warn: bool) -> Runtime {
        let mut chains = HashMap::new();
        chains.insert(
            Arc::from(profile),
            Arc::new(
                Chain::new(profile, vec![], Decision::Deny, Arc::new(DenyingDecider))
                    .warn_only(warn),
            ),
        );
        Runtime {
            chains,
            response_transforms: HashMap::new(),
            request_transforms: HashMap::new(),
            default_chain: Arc::new(Chain::new(
                "default",
                vec![],
                Decision::Deny,
                Arc::new(DenyingDecider),
            )),
            default_response_transforms: Vec::new(),
            default_request_transforms: Vec::new(),
            sessions: Arc::new(SessionRegistry::new(
                vec![],
                Some(Arc::from(profile)),
                false,
                false,
            )),
            passthrough: HostMatcher::default(),
            tls: test_engine(),
        }
    }

    /// A throwaway CA for tests that need *a* TlsEngine but do not care which.
    fn test_engine() -> Arc<TlsEngine> {
        let generated = marshal_tls::CertificateAuthority::generate("test", 1).unwrap();
        let ca =
            marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
                .unwrap();
        let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 16, 72));
        Arc::new(TlsEngine::new(minter).unwrap())
    }

    #[test]
    fn a_swap_is_visible_to_later_readers_but_not_earlier_ones() {
        // A connection reads once and keeps that view, so a reload never changes the rules
        // under a request already in flight.
        let handle = RuntimeHandle::new(runtime("before", false));
        let held = handle.load();

        handle.store(runtime("after", false));

        assert!(held.chains.contains_key("before"), "an existing view must not change");
        assert!(handle.load().chains.contains_key("after"));
        assert_eq!(handle.generation(), 1);
    }

    #[test]
    fn warn_only_profiles_are_reported() {
        let handle = RuntimeHandle::new(runtime("rollout", true));
        assert_eq!(handle.load().warn_only_profiles(), ["rollout"]);

        let handle = RuntimeHandle::new(runtime("live", false));
        assert!(handle.load().warn_only_profiles().is_empty());
    }
}
