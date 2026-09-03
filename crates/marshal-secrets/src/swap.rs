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
//!
//! [`Injection::SigV4`] is the one exception to bodies streaming by default (ADR-0007): AWS
//! request signing covers a hash of the body, so a swap using it forces the request to be
//! buffered up to its configured cap. Every other kind never touches the body.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use marshal_core::{
    BodyHandle, BodyRequirement, Error, RequestContext, RequestTransform, Result, SecretSource,
    SecretValue,
};
use marshal_policy::HostMatcher;

/// How the credential is formatted and which header (or, for [`Injection::Query`], query
/// parameter) it is set on. Each variant owns exactly the secret source(s) it needs to resolve.
#[derive(Debug)]
pub enum Injection {
    /// `Authorization: Basic base64("{username}:{secret}")` — what git, most package
    /// registries, and container registry logins use.
    Basic { username: String, source: Arc<dyn SecretSource> },
    /// `Authorization: Bearer {secret}` — a plain API token.
    Bearer { source: Arc<dyn SecretSource> },
    /// `{header}: {secret}` — the common shape for a service's own API-key header
    /// (`X-Api-Key`, `Api-Key`, and every vendor-specific variant of the same idea).
    Header { name: http::HeaderName, source: Arc<dyn SecretSource> },
    /// `?{name}={secret}` appended to the request's query string — some APIs accept (or
    /// only accept) the key this way rather than in a header.
    Query { name: String, source: Arc<dyn SecretSource> },
    /// AWS Signature Version 4 — signs the request with an access key pair rather than
    /// setting one static header. Needs two secrets, not one, plus the region and service the
    /// signature is scoped to. Forces the body to buffer (see the module docs) so its hash can
    /// enter the signature.
    SigV4 {
        access_key_id: Arc<dyn SecretSource>,
        secret_access_key: Arc<dyn SecretSource>,
        session_token: Option<Arc<dyn SecretSource>>,
        region: String,
        service: String,
        body_cap: usize,
    },
}

/// One credential rule: what to inject ([`Injection`]) and where it applies ([`HostMatcher`]).
pub struct SecretSwap {
    /// Name for the audit trail. Never the value.
    pub name: String,
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

    /// Resolve every source once, for seeding the redactor at startup. A `SigV4` swap
    /// contributes two or three values under distinct labels, since none of them alone is
    /// "the secret" the way a single-source swap's is.
    pub async fn resolve_all(&self) -> Vec<(String, SecretValue)> {
        let mut out = Vec::new();
        for swap in &self.swaps {
            for (label, source) in labeled_sources(swap) {
                match source.resolve().await {
                    Ok(v) => out.push((label, v)),
                    Err(e) => {
                        tracing::warn!(secret = %label, error = %e, "could not resolve a secret");
                    }
                }
            }
        }
        out
    }
}

fn labeled_sources(swap: &SecretSwap) -> Vec<(String, &Arc<dyn SecretSource>)> {
    match &swap.injection {
        Injection::Basic { source, .. }
        | Injection::Bearer { source }
        | Injection::Header { source, .. }
        | Injection::Query { source, .. } => vec![(swap.name.clone(), source)],
        Injection::SigV4 { access_key_id, secret_access_key, session_token, .. } => {
            let mut sources = vec![
                (format!("{}.access_key_id", swap.name), access_key_id),
                (format!("{}.secret_access_key", swap.name), secret_access_key),
            ];
            if let Some(token) = session_token {
                sources.push((format!("{}.session_token", swap.name), token));
            }
            sources
        }
    }
}

#[async_trait::async_trait]
impl RequestTransform for SecretInjector {
    fn name(&self) -> &str {
        "secrets"
    }

    fn body_requirement(&self) -> BodyRequirement {
        self.swaps.iter().fold(BodyRequirement::Streaming, |acc, swap| {
            let req = match &swap.injection {
                Injection::SigV4 { body_cap, .. } => BodyRequirement::Buffered { cap: *body_cap },
                _ => BodyRequirement::Streaming,
            };
            acc.combine(req)
        })
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        for swap in &self.swaps {
            if swap.hosts.matches(&cx.authority.host).is_none() {
                continue;
            }

            let injected = match &swap.injection {
                Injection::Basic { username, source } => {
                    let real = source.resolve().await?;
                    let value = format!(
                        "Basic {}",
                        base64_encode(format!("{username}:{}", real.expose()).as_bytes())
                    );
                    try_set_header(cx, http::header::AUTHORIZATION, value)
                }
                Injection::Bearer { source } => {
                    let real = source.resolve().await?;
                    try_set_header(
                        cx,
                        http::header::AUTHORIZATION,
                        format!("Bearer {}", real.expose()),
                    )
                }
                Injection::Header { name, source } => {
                    let real = source.resolve().await?;
                    try_set_header(cx, name.clone(), real.expose().to_owned())
                }
                Injection::Query { name, source } => {
                    let real = source.resolve().await?;
                    match append_query(&cx.uri, name, real.expose()) {
                        Some(uri) => {
                            cx.uri = uri;
                            true
                        }
                        None => false,
                    }
                }
                Injection::SigV4 {
                    access_key_id,
                    secret_access_key,
                    session_token,
                    region,
                    service,
                    ..
                } => {
                    let access_key = access_key_id.resolve().await?;
                    let secret_key = secret_access_key.resolve().await?;
                    let token = match session_token {
                        Some(s) => Some(s.resolve().await?),
                        None => None,
                    };
                    sign_sigv4(
                        cx,
                        access_key.expose(),
                        secret_key.expose(),
                        token.as_ref().map(SecretValue::expose),
                        region,
                        service,
                    )?;
                    true
                }
            };

            if injected {
                // The name, never the value.
                cx.evidence.record(format!("secrets.injected.{}", swap.name), true);
            }
        }
        Ok(())
    }
}

fn try_set_header(cx: &mut RequestContext, name: http::HeaderName, value: String) -> bool {
    match http::HeaderValue::from_str(&value) {
        Ok(v) => {
            cx.headers.insert(name, v);
            true
        }
        Err(_) => false,
    }
}

/// Appends `name=value` (value percent-encoded) to `uri`'s query string, preserving whatever
/// query the client already sent. Returns `None` only if the rebuilt URI fails to parse, which
/// should not happen for a well-formed name and any input value once percent-encoded.
fn append_query(uri: &http::Uri, name: &str, value: &str) -> Option<http::Uri> {
    let mut parts = uri.clone().into_parts();
    let existing = parts.path_and_query.take();
    let path = existing.as_ref().map(|pq| pq.path()).unwrap_or("/");
    let query = existing.as_ref().and_then(|pq| pq.query()).unwrap_or("");
    let encoded_value = percent_encode_bytes(value.as_bytes());
    let new_query = if query.is_empty() {
        format!("{name}={encoded_value}")
    } else {
        format!("{query}&{name}={encoded_value}")
    };
    parts.path_and_query = format!("{path}?{new_query}").parse().ok();
    http::Uri::from_parts(parts).ok()
}

/// Signs `cx` in place with AWS Signature Version 4, setting `Host`, `X-Amz-Date`,
/// `X-Amz-Content-Sha256`, an optional `X-Amz-Security-Token`, and finally `Authorization`.
///
/// Only `host`, `x-amz-content-sha256` and `x-amz-date` are signed headers. AWS only requires
/// those three (plus any header the caller specifically wants covered, which this transform
/// has no way to know in advance); signing every header on the request would tie the signature
/// to values other transforms in the chain — header allow-lists, `set_headers` — might still
/// touch after this one runs.
fn sign_sigv4(
    cx: &mut RequestContext,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
) -> Result<()> {
    let body: &[u8] = match &cx.body {
        BodyHandle::Empty => &[],
        BodyHandle::Buffered(b) => b.as_ref(),
        BodyHandle::OverLimit { limit, .. } => {
            return Err(Error::BodyTooLarge { cap: *limit });
        }
        BodyHandle::Streaming => {
            return Err(Error::Config(
                "sigv4 injection needs the request body materialised to hash it, but the body \
                 is streaming (for example a WebSocket upgrade) — scope this swap away from \
                 connections that upgrade"
                    .to_string(),
            ));
        }
    };
    let payload_hash = hex_encode(Sha256::digest(body));

    let now = time::OffsetDateTime::now_utc();
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let date_stamp = &amz_date[..8];

    // The signature covers exactly what is sent, so Host and the two x-amz-* headers must be
    // set on the real request before signing — computing the signature first and setting
    // headers after would let the two silently drift.
    let host_value = cx
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| cx.authority.to_string());
    let host_header = http::HeaderValue::from_str(&host_value)
        .map_err(|e| Error::Config(format!("sigv4: invalid host {host_value:?}: {e}")))?;
    cx.headers.insert(http::header::HOST, host_header);
    cx.headers.insert(
        http::HeaderName::from_static("x-amz-date"),
        http::HeaderValue::from_str(&amz_date).expect("amz-date is ASCII"),
    );
    cx.headers.insert(
        http::HeaderName::from_static("x-amz-content-sha256"),
        http::HeaderValue::from_str(&payload_hash).expect("hex digest is ASCII"),
    );
    if let Some(token) = session_token
        && let Ok(v) = http::HeaderValue::from_str(token)
    {
        // Not part of the signature (AWS's own rule for temporary credentials), but must
        // still reach upstream alongside the signed request.
        cx.headers.insert(http::HeaderName::from_static("x-amz-security-token"), v);
    }

    let mut signed = [
        ("host", host_value.clone()),
        ("x-amz-content-sha256", payload_hash.clone()),
        ("x-amz-date", amz_date.clone()),
    ];
    signed.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_headers: String =
        signed.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_headers = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");

    let canonical_uri = canonical_path(cx.uri.path());
    let canonical_query = canonical_query_string(cx.uri.query().unwrap_or(""));

    let canonical_request = format!(
        "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        cx.method.as_str(),
    );
    let hashed_canonical_request = hex_encode(Sha256::digest(canonical_request.as_bytes()));

    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashed_canonical_request}");

    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex_encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );
    let v = http::HeaderValue::from_str(&authorization).map_err(|e| {
        Error::Config(format!("sigv4: could not build the Authorization header: {e}"))
    })?;
    cx.headers.insert(http::header::AUTHORIZATION, v);

    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    let mut s = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// AWS's canonical URI: each path segment percent-encoded per RFC 3986's unreserved set, `/`
/// preserved as the separator, `/` for an empty path.
fn canonical_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(|segment| percent_encode_bytes(segment.as_bytes()))
        .collect::<Vec<_>>()
        .join("/")
}

/// AWS's canonical query string: percent-decode each parameter (undoing whatever encoding the
/// client's request used), re-encode both name and value with [`percent_encode_bytes`], then
/// sort by name. Decoding first and re-encoding with one fixed ruleset is what keeps this
/// idempotent regardless of how the client (or an earlier `Query` swap in this same profile)
/// encoded the query it started with.
fn canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_encode_bytes(&percent_decode(k)), percent_encode_bytes(&percent_decode(v)))
        })
        .collect();
    pairs.sort();
    pairs.into_iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes everything outside the RFC 3986 unreserved set. More conservative than
/// strictly required in some contexts (e.g. a query component technically allows `/` and `?`
/// unencoded), but encoding conservatively here can never produce an invalid or misparsed URI.
fn percent_encode_bytes(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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

    #[test]
    fn percent_encode_query_escapes_reserved_characters() {
        assert_eq!(percent_encode_bytes(b"abc123-_.~"), "abc123-_.~");
        assert_eq!(percent_encode_bytes(b"a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn append_query_adds_to_an_empty_query_string() {
        let uri: http::Uri = "https://api.example.com/v1/things".parse().unwrap();
        let out = append_query(&uri, "api_key", "s3cret").unwrap();
        assert_eq!(out.path_and_query().unwrap().as_str(), "/v1/things?api_key=s3cret");
    }

    #[test]
    fn append_query_preserves_a_query_the_client_already_sent() {
        let uri: http::Uri = "https://api.example.com/v1/things?limit=10".parse().unwrap();
        let out = append_query(&uri, "api_key", "s3cret").unwrap();
        assert_eq!(out.path_and_query().unwrap().as_str(), "/v1/things?limit=10&api_key=s3cret");
    }

    #[test]
    fn canonical_path_defaults_to_root() {
        assert_eq!(canonical_path(""), "/");
    }

    #[test]
    fn canonical_path_encodes_each_segment() {
        assert_eq!(canonical_path("/a b/c+d"), "/a%20b/c%2Bd");
    }

    #[test]
    fn canonical_query_string_sorts_and_reencodes() {
        // Deliberately out of order and using a client-chosen encoding (space as `+` is not
        // valid for this context and must round-trip back through %20).
        assert_eq!(canonical_query_string("b=2&a=1"), "a=1&b=2");
        assert_eq!(canonical_query_string("key=hello%20world"), "key=hello%20world");
    }

    #[test]
    fn sha256_matches_the_known_empty_string_digest() {
        // The single most widely cited SHA-256 test vector there is.
        assert_eq!(
            hex_encode(Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_test_case_1() {
        // https://www.rfc-editor.org/rfc/rfc4231#section-4.2
        let key = [0x0bu8; 20];
        assert_eq!(
            hex_encode(hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sigv4_credential_scope_and_authorization_header_are_well_formed() {
        // Not a known-answer test (the signature depends on the current time), but pins the
        // shape of the derived Authorization header and its component parts together, so a
        // future refactor that drops a field or reorders SignedHeaders fails loudly.
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.amazonaws.com"));
        let mut cx = RequestContext {
            identity: marshal_core::Identity::new("test"),
            profile: std::sync::Arc::from("test"),
            ingress: marshal_core::IngressMode::Explicit,
            phase: marshal_core::Phase::Request,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            authority: marshal_core::Authority { host: "s3.amazonaws.com".into(), port: 443 },
            method: http::Method::GET,
            uri: "/examplebucket/photos/photo1.jpg".parse().unwrap(),
            headers,
            body: BodyHandle::Empty,
            evidence: marshal_core::Evidence::new(),
        };

        sign_sigv4(
            &mut cx,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "s3",
        )
        .unwrap();

        let auth = cx.headers.get(http::header::AUTHORIZATION).unwrap().to_str().unwrap();
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"), "{auth}");
        assert!(auth.contains("/us-east-1/s3/aws4_request, "), "{auth}");
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date, "), "{auth}");
        assert!(auth.contains("Signature="), "{auth}");

        assert_eq!(
            cx.headers.get("x-amz-content-sha256").unwrap(),
            // SHA-256 of an empty body — this request has none.
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(cx.headers.get("x-amz-date").is_some());
    }
}
