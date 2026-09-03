//! The certificate authority the proxy signs leaf certificates with.
//!
//! Interception means the agent must trust a CA we control. That CA's private key is the most
//! dangerous artefact the project produces: anyone holding it can impersonate every site the
//! agent talks to. It is therefore written `0600`, never logged, never placed in an audit
//! record, and `marshal ca init` refuses to overwrite an existing one.

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("generating a certificate: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("{path} already exists; refusing to overwrite a CA. Delete it deliberately first.")]
    WouldOverwrite { path: String },

    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("writing {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} does not contain a PEM {expected}")]
    NoPem { path: String, expected: &'static str },

    #[error("building a rustls signing key: {0}")]
    SigningKey(String),
}

/// A loaded CA, ready to sign leaves.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No key material, by construction: this type is held for the lifetime of the process
        // and would otherwise be a standing invitation for a `{:?}` to leak it.
        f.debug_struct("CertificateAuthority").finish_non_exhaustive()
    }
}

/// A freshly generated CA, as PEM. Returned rather than written so the caller owns the
/// decision about where key material lands.
pub struct GeneratedCa {
    pub cert_pem: String,
    pub key_pem: String,
}

// Deliberately not derived: this struct holds the CA private key in plain text, and a derived
// Debug would put it in any log line that formatted the value.
impl std::fmt::Debug for GeneratedCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCa")
            .field("cert_pem", &"<pem>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl CertificateAuthority {
    /// Generate a new CA certificate and key.
    pub fn generate(common_name: &str, valid_days: u32) -> Result<GeneratedCa, CaError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();

        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.distinguished_name.push(DnType::OrganizationName, "bot-marshal");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.use_authority_key_identifier_extension = false;

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(valid_days as i64);

        let cert = params.self_signed(&key)?;
        Ok(GeneratedCa { cert_pem: cert.pem(), key_pem: key.serialize_pem() })
    }

    /// Load a CA from PEM text.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, CaError> {
        let key = KeyPair::from_pem(key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key)?;

        let cert_der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .transpose()
            .map_err(|e| CaError::Read {
                path: "<ca cert>".into(),
                source: std::io::Error::other(e),
            })?
            .ok_or(CaError::NoPem { path: "<ca cert>".into(), expected: "CERTIFICATE" })?;

        Ok(Self { issuer, cert_der, cert_pem: cert_pem.to_owned() })
    }

    /// Read a CA from disk.
    pub fn load(cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<Self, CaError> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|source| CaError::Read { path: cert_path.display().to_string(), source })?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|source| CaError::Read { path: key_path.display().to_string(), source })?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Write a generated CA to disk, refusing to clobber either file.
    ///
    /// The key is created with mode `0600` at open time rather than chmod-ed afterwards, so
    /// there is no window in which it is world-readable.
    pub fn write(
        ca: &GeneratedCa,
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<(), CaError> {
        for p in [cert_path, key_path] {
            if p.exists() {
                return Err(CaError::WouldOverwrite { path: p.display().to_string() });
            }
            if let Some(dir) = p.parent()
                && !dir.as_os_str().is_empty()
            {
                std::fs::create_dir_all(dir)
                    .map_err(|source| CaError::Write { path: dir.display().to_string(), source })?;
            }
        }

        std::fs::write(cert_path, &ca.cert_pem)
            .map_err(|source| CaError::Write { path: cert_path.display().to_string(), source })?;

        write_private(key_path, ca.key_pem.as_bytes())
            .map_err(|source| CaError::Write { path: key_path.display().to_string(), source })?;

        Ok(())
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    pub(crate) fn issuer(&self) -> &Issuer<'static, KeyPair> {
        &self.issuer
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Convert a rcgen key pair PEM into something rustls can sign with.
pub(crate) fn signing_key_from_pem(
    key_pem: &str,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, CaError> {
    // `NoItemsFound` is the "there was no key in there" case that `rustls-pemfile` expressed
    // as `Ok(None)`; every other error is a malformed one. Kept distinct because the two say
    // different things to whoever wrote the file.
    let der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| match e {
        rustls::pki_types::pem::Error::NoItemsFound => {
            CaError::NoPem { path: "<leaf key>".into(), expected: "PRIVATE KEY" }
        }
        other => CaError::SigningKey(other.to_string()),
    })?;
    private_key_to_signing_key(der)
}

pub(crate) fn private_key_to_signing_key(
    der: PrivateKeyDer<'static>,
) -> Result<std::sync::Arc<dyn rustls::sign::SigningKey>, CaError> {
    rustls::crypto::ring::sign::any_supported_type(&der)
        .map_err(|e| CaError::SigningKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_round_trips() {
        let ca = CertificateAuthority::generate("bot-marshal test CA", 30).unwrap();
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        CertificateAuthority::from_pem(&ca.cert_pem, &ca.key_pem).expect("loads back");
    }

    #[test]
    fn debug_never_exposes_key_material() {
        let ca = CertificateAuthority::generate("t", 1).unwrap();

        // Both the generated pair and the loaded CA must be safe to format.
        let rendered = format!("{ca:?}");
        assert!(!rendered.contains("PRIVATE"), "{rendered}");
        assert!(!rendered.contains(&ca.key_pem));

        let loaded = CertificateAuthority::from_pem(&ca.cert_pem, &ca.key_pem).unwrap();
        let rendered = format!("{loaded:?}");
        assert!(!rendered.contains("PRIVATE"));
        assert!(!rendered.contains("BEGIN"));
    }

    #[test]
    fn write_refuses_to_overwrite_and_uses_0600() {
        let dir = std::env::temp_dir().join(format!("marshal-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cert = dir.join("ca.crt");
        let key = dir.join("ca.key");

        let ca = CertificateAuthority::generate("t", 1).unwrap();
        CertificateAuthority::write(&ca, &cert, &key).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the CA key must never be group- or world-readable");
        }

        // A second init must not silently replace a CA that clients already trust.
        let again = CertificateAuthority::generate("t", 1).unwrap();
        assert!(matches!(
            CertificateAuthority::write(&again, &cert, &key),
            Err(CaError::WouldOverwrite { .. })
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
