//! PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), and the randomness it needs.
//!
//! PKCE exists because an authorization code travels through parts of a system the client does
//! not control — a browser, a redirect, sometimes a URL bar and a history file. Binding the
//! code to a secret only the party that *started* the flow holds means intercepting the code
//! is not enough to redeem it.
//!
//! That property is why marshal generates the verifier itself rather than passing an agent's
//! through: whoever holds the verifier is the only party that can complete the exchange.

use marshal_core::{Error, Result, base64url_encode};
use sha2::{Digest, Sha256};

/// A verifier and the challenge derived from it.
#[derive(Debug, Clone)]
pub struct Pkce {
    /// Sent only in the token request, never in the authorization request.
    pub verifier: String,
    /// Sent in the authorization request. `S256` of the verifier.
    pub challenge: String,
}

impl Pkce {
    /// 32 bytes of entropy, base64url-encoded to a 43-character verifier — the length RFC 7636
    /// §7.1 recommends, and comfortably inside the 43–128 range it permits.
    pub fn generate() -> Result<Self> {
        let verifier = random_urlsafe(32)?;
        let challenge = challenge_s256(&verifier);
        Ok(Self { verifier, challenge })
    }
}

/// The `S256` transformation: `base64url(sha256(ascii(verifier)))`, unpadded.
///
/// `plain` is not implemented. RFC 7636 §4.2 permits it only where the client cannot do
/// SHA-256, which is not a situation this code can be in, and it provides no protection at all
/// against an intercepted authorization request.
pub fn challenge_s256(verifier: &str) -> String {
    base64url_encode(Sha256::digest(verifier.as_bytes()).as_slice())
}

/// `n` bytes of OS entropy, base64url-encoded.
///
/// Used for the PKCE verifier and for the `state` parameter, which is the CSRF defence for the
/// redirect: a callback whose `state` marshal did not issue is somebody else's flow.
pub fn random_urlsafe(n: usize) -> Result<String> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Config(format!("cannot read operating-system entropy: {e}")))?;
    Ok(base64url_encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_the_rfc_7636_test_vector() {
        // RFC 7636 appendix B, verbatim.
        assert_eq!(
            challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_generated_verifier_is_the_length_the_rfc_recommends() {
        let p = Pkce::generate().unwrap();
        // 32 bytes base64url-encoded, unpadded.
        assert_eq!(p.verifier.len(), 43);
        assert!(p.verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn the_challenge_is_derived_from_the_verifier_and_is_not_the_verifier() {
        let p = Pkce::generate().unwrap();
        assert_eq!(p.challenge, challenge_s256(&p.verifier));
        assert_ne!(p.challenge, p.verifier);
    }

    #[test]
    fn two_generated_verifiers_differ() {
        // Cheap, but it catches the class of mistake where entropy is silently not read.
        let a = Pkce::generate().unwrap();
        let b = Pkce::generate().unwrap();
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn random_values_are_url_safe_so_they_survive_a_query_string() {
        let s = random_urlsafe(24).unwrap();
        assert!(!s.contains('+') && !s.contains('/') && !s.contains('='), "{s}");
    }
}
