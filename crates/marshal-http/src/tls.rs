//! The TLS client config for marshal's own outbound calls.

use std::sync::Arc;

/// Public roots, no client auth, HTTP/1.1 only.
///
/// Deliberately separate from the TLS config the *proxy* presents and uses on behalf of an
/// agent: this one is for calls marshal makes as itself — an LLM judge, an OAuth2 token
/// endpoint — and those are not subject to the interception machinery at all.
pub fn default_tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}
