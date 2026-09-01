//! On-the-fly leaf certificates, one per SNI, cached.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;

use crate::ca::{CaError, CertificateAuthority, signing_key_from_pem};

/// Mints and caches leaf certificates.
///
/// Minting costs a key generation and a signature — single-digit milliseconds, but paid on
/// every TLS handshake without a cache, which for an agent opening many short connections to
/// the same host is most of the handshake cost.
#[derive(Debug)]
pub struct LeafMinter {
    ca: Arc<CertificateAuthority>,
    cache: moka::sync::Cache<String, Arc<CertifiedKey>>,
    validity: time::Duration,
}

impl LeafMinter {
    pub fn new(ca: Arc<CertificateAuthority>, cache_size: u64, validity_hours: u32) -> Self {
        Self {
            ca,
            cache: moka::sync::Cache::builder()
                .max_capacity(cache_size)
                // Expire entries somewhat before the certificates themselves do, so a cached
                // leaf is never handed out close to its own expiry.
                .time_to_live(std::time::Duration::from_secs(
                    (validity_hours as u64).saturating_mul(3600) / 2,
                ))
                .build(),
            validity: time::Duration::hours(validity_hours as i64),
        }
    }

    /// Get or mint the leaf for `sni`.
    pub fn get(&self, sni: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let key = sni.to_ascii_lowercase();
        if let Some(hit) = self.cache.get(&key) {
            return Ok(hit);
        }
        let minted = Arc::new(self.mint(&key)?);
        self.cache.insert(key, Arc::clone(&minted));
        Ok(minted)
    }

    pub fn cache_len(&self) -> u64 {
        self.cache.entry_count()
    }

    fn mint(&self, sni: &str) -> Result<CertifiedKey, CaError> {
        let key = KeyPair::generate()?;

        // `CertificateParams::new` turns an IP literal into an IP SAN and anything else into
        // a DNS SAN, which is what a client validating a bare-IP connection needs.
        let mut params = CertificateParams::new(vec![sni.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, sni);
        params.key_usages =
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let now = time::OffsetDateTime::now_utc();
        // Backdated slightly: a client whose clock is a little behind ours should not reject
        // a certificate we minted moments ago.
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + self.validity;

        let cert = params.signed_by(&key, self.ca.issuer())?;
        let signing = signing_key_from_pem(&key.serialize_pem())?;

        // The chain is leaf-then-CA. Including the CA lets a client that already trusts it
        // build the path without a separate fetch.
        let chain: Vec<CertificateDer<'static>> =
            vec![cert.der().clone(), self.ca.cert_der().clone()];

        Ok(CertifiedKey::new(chain, signing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minter() -> LeafMinter {
        let generated = CertificateAuthority::generate("test CA", 30).unwrap();
        let ca = CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem).unwrap();
        LeafMinter::new(Arc::new(ca), 16, 72)
    }

    #[test]
    fn mints_a_chain_that_includes_the_ca() {
        let m = minter();
        let leaf = m.get("api.github.com").unwrap();
        assert_eq!(leaf.cert.len(), 2, "leaf then CA");
    }

    #[test]
    fn caches_by_sni_case_insensitively() {
        let m = minter();
        let a = m.get("api.github.com").unwrap();
        let b = m.get("API.GitHub.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "one certificate should serve both spellings");
        m.cache.run_pending_tasks();
        assert_eq!(m.cache_len(), 1);
    }

    #[test]
    fn different_hosts_get_different_certificates() {
        let m = minter();
        let a = m.get("api.github.com").unwrap();
        let b = m.get("api.openai.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_ne!(a.cert[0], b.cert[0]);
    }

    #[test]
    fn ip_literals_mint_successfully() {
        // A bare-IP CONNECT has no SNI, but a client may still validate against an IP SAN.
        let m = minter();
        assert!(m.get("127.0.0.1").is_ok());
    }
}
