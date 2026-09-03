//! Boundary secret injection: the agent never holds the real credential.
//!
//! Two independent modes, chosen per swap by [`SwapKind`] — not a spectrum, two genuinely
//! different trust models:
//!
//! * [`SwapKind::Placeholder`] — the agent is a cooperating participant. It holds and sends a
//!   stand-in value (in a header, the query string, or the body), and this swaps it for the
//!   real credential wherever it's found. A prompt-injected agent can still *use* its
//!   placeholder against hosts the chain allows, but it cannot exfiltrate anything of value:
//!   the placeholder is worthless outside this proxy.
//! * [`SwapKind::Inject`] — the agent knows nothing about authentication at all. Every
//!   allowed request to the configured host gets the credential added, unconditionally. This
//!   is for a client that has no notion of the endpoint being authenticated in the first
//!   place — an anonymous `git clone`, a `docker pull` with no login step, an npm install
//!   against a registry that requires a token the agent was never given. There is nothing to
//!   swap because nothing was sent.
//!
//! `Inject` is a real trade-off, not a strictly worse `Placeholder`: within its host scope,
//! *every* request the chain allows is now authenticated, not just ones the agent specifically
//! constructed to carry a credential. See `docs/adr/0026-blind-credential-injection.md`.

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

/// Which of the two trust models a swap uses. See the module documentation.
#[derive(Debug)]
pub enum SwapKind {
    /// The agent sends `proxy_value`, found in whichever of `sites` it's configured to scan.
    Placeholder {
        /// What the agent sends. Safe to log; useless anywhere but here.
        proxy_value: String,
        sites: MatchSites,
        /// Refuse a matching request that does not carry the placeholder, rather than
        /// forwarding it unauthenticated and letting the agent see a confusing 401 from the
        /// upstream.
        require: bool,
    },
    /// The proxy constructs the credential itself and sets `Authorization` on every request
    /// this swap matches — the client sends nothing related to authentication.
    Inject(Injection),
}

/// A credential constructed and injected unconditionally, with no involvement from the
/// client. More variants (`Bearer`, a named custom header) follow the same shape if needed;
/// `Basic` is what git, most package registries, and container registry logins actually use.
#[derive(Debug)]
pub enum Injection {
    /// `Authorization: Basic base64("{username}:{secret}")`.
    Basic { username: String },
}

/// One credential rule: how it's authenticated ([`SwapKind`]), resolved from ([`SecretSource`]),
/// and where it applies ([`HostMatcher`]).
pub struct SecretSwap {
    /// Name for the audit trail. Never the value.
    pub name: String,
    pub source: Arc<dyn SecretSource>,
    pub kind: SwapKind,
    pub hosts: HostMatcher,
}

impl std::fmt::Debug for SecretSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.kind {
            SwapKind::Placeholder { .. } => "Placeholder",
            SwapKind::Inject(Injection::Basic { .. }) => "Inject(Basic)",
        };
        f.debug_struct("SecretSwap")
            .field("name", &self.name)
            .field("kind", &kind)
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
    /// `Inject` swaps have no placeholder — there is nothing the client ever sends to confuse
    /// with the real credential.
    pub fn proxy_values(&self) -> Vec<String> {
        self.swaps
            .iter()
            .filter_map(|s| match &s.kind {
                SwapKind::Placeholder { proxy_value, .. } => Some(proxy_value.clone()),
                SwapKind::Inject(_) => None,
            })
            .collect()
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
        // Only if some Placeholder swap actually scans bodies. Buffering every request
        // because one profile *might* need it would silently stop uploads streaming. Inject
        // swaps never need the body at all.
        let needs_body = self
            .swaps
            .iter()
            .any(|s| matches!(&s.kind, SwapKind::Placeholder { sites, .. } if sites.body));
        if needs_body {
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

            match &swap.kind {
                SwapKind::Placeholder { proxy_value, sites, require } => {
                    apply_placeholder(cx, swap, proxy_value, sites, *require).await?;
                }
                SwapKind::Inject(injection) => {
                    apply_inject(cx, swap, injection).await?;
                }
            }
        }
        Ok(())
    }
}

/// The client is a cooperating participant: find `proxy_value` wherever `sites` says to look,
/// and replace it with the real credential.
async fn apply_placeholder(
    cx: &mut RequestContext,
    swap: &SecretSwap,
    proxy_value: &str,
    sites: &MatchSites,
    require: bool,
) -> Result<()> {
    let mut swapped_anywhere = false;

    // Resolve lazily: a request that never presents the placeholder should not cause the
    // real credential to be read at all.
    if !placeholder_present(cx, proxy_value, sites) {
        if require {
            return Err(Error::Config(format!(
                "requests to `{}` must carry the `{}` placeholder, but this one did not. Send \
                 `{proxy_value}` where the credential would normally go.",
                cx.authority.host, swap.name
            )));
        }
        return Ok(());
    }

    let real = swap.source.resolve().await?;

    for (name, value) in cx.headers.clone().iter() {
        if !sites.headers.is_empty()
            && !sites.headers.iter().any(|h| h.eq_ignore_ascii_case(name.as_str()))
        {
            continue;
        }
        let Ok(text) = value.to_str() else { continue };
        let Some(replaced) = replace_in_header(text, proxy_value, real.expose()) else {
            continue;
        };
        if let Ok(v) = http::HeaderValue::from_str(&replaced) {
            cx.headers.insert(name.clone(), v);
            swapped_anywhere = true;
        }
    }

    if sites.query
        && let Some(q) = cx.uri.query()
        && q.contains(proxy_value)
    {
        let new_q = q.replace(proxy_value, real.expose());
        let path = cx.uri.path();
        if let Ok(uri) = format!("{path}?{new_q}").parse::<http::Uri>() {
            cx.uri = uri;
            swapped_anywhere = true;
        }
    }

    if sites.body
        && let marshal_core::BodyHandle::Buffered(bytes) = &cx.body
        && let Ok(text) = std::str::from_utf8(bytes)
        && text.contains(proxy_value)
    {
        let replaced = text.replace(proxy_value, real.expose());
        cx.body = marshal_core::BodyHandle::Buffered(bytes::Bytes::from(replaced));
        swapped_anywhere = true;
    }

    if swapped_anywhere {
        // The name, never the value.
        cx.evidence.record(format!("secrets.swapped.{}", swap.name), true);
    }
    Ok(())
}

/// The client sent nothing: construct the credential and set it unconditionally. Every
/// request that reaches here already passed the policy chain — that host allowlist is the
/// only gate, since there is no placeholder to check for.
async fn apply_inject(
    cx: &mut RequestContext,
    swap: &SecretSwap,
    injection: &Injection,
) -> Result<()> {
    let real = swap.source.resolve().await?;
    let value = match injection {
        Injection::Basic { username } => {
            format!("Basic {}", base64_encode(format!("{username}:{}", real.expose()).as_bytes()))
        }
    };
    if let Ok(v) = http::HeaderValue::from_str(&value) {
        cx.headers.insert(http::header::AUTHORIZATION, v);
        // The name, never the value.
        cx.evidence.record(format!("secrets.injected.{}", swap.name), true);
    }
    Ok(())
}

/// Whether the placeholder appears anywhere `sites` says to look.
fn placeholder_present(cx: &RequestContext, proxy_value: &str, sites: &MatchSites) -> bool {
    let in_headers = cx.headers.iter().any(|(name, value)| {
        if !sites.headers.is_empty()
            && !sites.headers.iter().any(|h| h.eq_ignore_ascii_case(name.as_str()))
        {
            return false;
        }
        value.to_str().map(|t| header_contains(t, proxy_value)).unwrap_or(false)
    });
    if in_headers {
        return true;
    }

    if sites.query && cx.uri.query().map(|q| q.contains(proxy_value)).unwrap_or(false) {
        return true;
    }

    if sites.body
        && let marshal_core::BodyHandle::Buffered(bytes) = &cx.body
        && let Ok(text) = std::str::from_utf8(bytes)
        && text.contains(proxy_value)
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
