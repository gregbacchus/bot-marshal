//! Boundary secret injection: the agent never holds the real credential.
//!
//! Every request the policy chain allows to a configured host gets the credential set,
//! unconditionally — never contingent on anything the client sent, and always replacing
//! whatever was there (if anything). There is no placeholder for a client to hold or present:
//! it does not need to know, or do anything about, the fact that the endpoint requires
//! authentication in the first place. `git clone https://github.com/owner/repo`, with no
//! credential anywhere in the command, authenticates.
//!
//! `rules` (the host scope a swap applies to) is therefore the entire trust boundary: within
//! it, every request the chain already allowed gets the credential, whether or not the agent
//! was trying to authenticate. Scope a swap as narrowly as the endpoint that actually needs
//! the credential.

use std::sync::Arc;

use marshal_core::{
    BodyRequirement, RequestContext, RequestTransform, Result, SecretSource, SecretValue,
};
use marshal_policy::HostMatcher;

/// How the credential is formatted into `Authorization`.
#[derive(Debug)]
pub enum Injection {
    /// `Authorization: Basic base64("{username}:{secret}")` — what git, most package
    /// registries, and container registry logins use.
    Basic { username: String },
    /// `Authorization: Bearer {secret}` — a plain API token.
    Bearer,
}

/// One credential rule: what to inject ([`Injection`]), resolved from ([`SecretSource`]), and
/// where it applies ([`HostMatcher`]).
pub struct SecretSwap {
    /// Name for the audit trail. Never the value.
    pub name: String,
    pub source: Arc<dyn SecretSource>,
    pub injection: Injection,
    pub hosts: HostMatcher,
}

impl std::fmt::Debug for SecretSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSwap")
            .field("name", &self.name)
            .field("injection", &self.injection)
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
        // Injection only ever sets a header; the body is never inspected or touched.
        BodyRequirement::Streaming
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        for swap in &self.swaps {
            if swap.hosts.matches(&cx.authority.host).is_none() {
                continue;
            }

            let real = swap.source.resolve().await?;
            let value = match &swap.injection {
                Injection::Basic { username } => format!(
                    "Basic {}",
                    base64_encode(format!("{username}:{}", real.expose()).as_bytes())
                ),
                Injection::Bearer => format!("Bearer {}", real.expose()),
            };
            if let Ok(v) = http::HeaderValue::from_str(&value) {
                cx.headers.insert(http::header::AUTHORIZATION, v);
                // The name, never the value.
                cx.evidence.record(format!("secrets.injected.{}", swap.name), true);
            }
        }
        Ok(())
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal standard-alphabet base64 encoder. Pulling in a dependency for one credential
/// header would be more surface than the ten lines it replaces.
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(BASE64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { BASE64_ALPHABET[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_matches_known_vectors() {
        // RFC 4648's own test vectors, so this isn't just internally self-consistent.
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_handles_every_padding_case() {
        assert_eq!(base64_encode(b"x-access-token:ghp_realtoken"), {
            // Cross-check against a second, independent implementation of the same alphabet
            // rather than against itself.
            let bytes = b"x-access-token:ghp_realtoken";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk.len();
                let mut buf = [0u8; 3];
                buf[..n].copy_from_slice(chunk);
                let val = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
                let chars: Vec<u8> = (0..4)
                    .map(|i| BASE64_ALPHABET[((val >> (18 - i * 6)) & 0x3f) as usize])
                    .collect();
                out.push(chars[0] as char);
                out.push(chars[1] as char);
                out.push(if n > 1 { chars[2] as char } else { '=' });
                out.push(if n > 2 { chars[3] as char } else { '=' });
            }
            out
        });
    }
}
