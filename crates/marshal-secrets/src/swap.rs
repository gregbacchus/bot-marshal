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
                let Some(replaced) = replace_in_header(text, &swap.proxy_value, real.expose())
                else {
                    continue;
                };
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
        value.to_str().map(|t| header_contains(t, &swap.proxy_value)).unwrap_or(false)
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

/// Whether `placeholder` appears in a header value, either directly (a bearer token, an API
/// key — anything the client sends as plain text) or inside the decoded credential of a
/// `Basic` challenge (`Authorization: Basic base64("user:password")`) — the scheme git,
/// package registries, and container registries all normally use. No configuration
/// distinguishes the two cases: this is not a heuristic guess at what a header *might* be,
/// it is recognising a fixed, unambiguous wire format (RFC 7617) once the header is already
/// one this swap was configured to look at.
fn header_contains(text: &str, placeholder: &str) -> bool {
    if text.contains(placeholder) {
        return true;
    }
    decode_basic(text).is_some_and(|decoded| decoded.contains(placeholder))
}

/// As [`header_contains`], but performs the substitution and returns the header's new value.
/// `None` means the placeholder was not found by either method, so the caller leaves the
/// header untouched.
fn replace_in_header(text: &str, placeholder: &str, real: &str) -> Option<String> {
    if text.contains(placeholder) {
        return Some(text.replace(placeholder, real));
    }
    let decoded = decode_basic(text)?;
    if !decoded.contains(placeholder) {
        return None;
    }
    Some(format!("Basic {}", base64_encode(decoded.replace(placeholder, real).as_bytes())))
}

/// Decode the credential out of a `Basic` challenge, if `text` is one. `None` for anything
/// else — a missing `Basic ` prefix, invalid base64, or non-UTF-8 decoded bytes — none of
/// which are errors, just "this header is not that".
fn decode_basic(text: &str) -> Option<String> {
    let encoded = text.strip_prefix("Basic ").or_else(|| text.strip_prefix("basic "))?;
    String::from_utf8(base64_decode(encoded)?).ok()
}

/// Minimal standard-alphabet base64 decoder, matching the one in `marshal-proxy`'s
/// `httpfront` — duplicated rather than shared, since pulling in a dependency (or a
/// cross-crate coupling) for either direction of twenty lines of encoding is more surface
/// than the thing it replaces.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
    fn base64_round_trips_through_all_padding_cases() {
        // One, two, and zero bytes of padding, so a chunk-boundary bug would show up.
        for input in ["a", "ab", "abc", "abcd", "x-access-token:ghp_realtoken", ""] {
            let encoded = base64_encode(input.as_bytes());
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(decoded, input.as_bytes(), "round-trip failed for {input:?}");
        }
    }

    #[test]
    fn base64_encode_matches_a_known_vector() {
        // RFC 4648's own test vector, so this isn't just internally self-consistent.
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
    }

    #[test]
    fn header_contains_finds_a_plain_bearer_token() {
        assert!(header_contains("Bearer marshal-placeholder", "marshal-placeholder"));
        assert!(!header_contains("Bearer something-else", "marshal-placeholder"));
    }

    #[test]
    fn header_contains_finds_a_placeholder_inside_basic_auth() {
        let encoded = base64_encode(b"x-access-token:marshal-placeholder");
        assert!(header_contains(&format!("Basic {encoded}"), "marshal-placeholder"));
    }

    #[test]
    fn header_contains_does_not_false_positive_on_an_unrelated_basic_header() {
        let encoded = base64_encode(b"someone:something-else");
        assert!(!header_contains(&format!("Basic {encoded}"), "marshal-placeholder"));
    }

    #[test]
    fn header_contains_ignores_malformed_basic_headers() {
        // Not valid base64, and not UTF-8 once decoded — neither should panic or false-match.
        assert!(!header_contains("Basic not-valid-base64!!!", "marshal-placeholder"));
        assert!(!header_contains(&format!("Basic {}", base64_encode(&[0xff, 0xfe])), "x"));
    }

    #[test]
    fn replace_in_header_swaps_a_plain_bearer_token() {
        let out =
            replace_in_header("Bearer marshal-placeholder", "marshal-placeholder", "real").unwrap();
        assert_eq!(out, "Bearer real");
    }

    #[test]
    fn replace_in_header_swaps_and_re_encodes_a_basic_challenge() {
        let encoded = base64_encode(b"x-access-token:marshal-placeholder");
        let out = replace_in_header(&format!("Basic {encoded}"), "marshal-placeholder", "ghp_real")
            .unwrap();
        assert_eq!(out, format!("Basic {}", base64_encode(b"x-access-token:ghp_real")));
    }

    #[test]
    fn replace_in_header_leaves_a_non_matching_header_alone() {
        assert!(
            replace_in_header("Bearer something-else", "marshal-placeholder", "real").is_none()
        );
        let encoded = base64_encode(b"someone:something-else");
        assert!(
            replace_in_header(&format!("Basic {encoded}"), "marshal-placeholder", "real").is_none()
        );
    }
}
