//! The TLS client config for marshal's own outbound calls.

use std::sync::Arc;

/// Public roots, no client auth, HTTP/1.1 only.
///
/// Deliberately separate from the TLS config the *proxy* presents and uses on behalf of an
/// agent: this one is for calls marshal makes as itself — an LLM judge, an OAuth2 token
/// endpoint — and those are not subject to the interception machinery at all.
pub fn default_tls_config() -> Arc<rustls::ClientConfig> {
    with_extra_roots(&[]).expect("no extra roots cannot fail")
}

/// The same, plus the operator's own roots from `tls.upstream_ca_certs`.
///
/// An internal auth server behind a private CA is an ordinary deployment, and the proxy
/// already trusts it for proxied traffic. A call marshal makes *for itself* to the same host
/// failing on `UnknownIssuer` would be a distinction with no justification behind it — the
/// operator said "trust this CA", not "trust this CA for some connections".
pub fn with_extra_roots(
    extra_root_pems: &[String],
) -> Result<Arc<rustls::ClientConfig>, crate::HttpError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for pem in extra_root_pems {
        for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
            let cert = cert.map_err(|e| crate::HttpError::Tls(std::io::Error::other(e)))?;
            roots
                .add(cert)
                .map_err(|e| crate::HttpError::Tls(std::io::Error::other(e.to_string())))?;
        }
    }
    let mut cfg =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
