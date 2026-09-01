//! The rustls certificate resolver that mints per-SNI leaves during the handshake.

use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::leaf::LeafMinter;

/// Resolves a server certificate by minting one for the requested name.
///
/// A ClientHello with no SNI falls back to `fallback_name`, which the proxy sets to the
/// CONNECT authority. Without that fallback, a client connecting to a bare IP would get no
/// certificate and a confusing handshake failure rather than a certificate it can choose to
/// reject on its own terms.
#[derive(Debug)]
pub struct MintingResolver {
    minter: Arc<LeafMinter>,
    fallback_name: String,
}

impl MintingResolver {
    pub fn new(minter: Arc<LeafMinter>, fallback_name: impl Into<String>) -> Self {
        Self { minter, fallback_name: fallback_name.into() }
    }
}

impl ResolvesServerCert for MintingResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().unwrap_or(&self.fallback_name);
        match self.minter.get(name) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::error!(sni = %name, error = %e, "failed to mint a leaf certificate");
                None
            }
        }
    }
}
