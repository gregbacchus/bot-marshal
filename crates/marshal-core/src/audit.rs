//! The audit record: one structured entry per request.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence::{Fact, Flag, LayerOutcome};
use crate::verdict::Reason;

/// What was ultimately done with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// Emitted for every request, allowed or not.
///
/// Contains the full layer trail so any decision is reconstructable after the fact. Secrets
/// are redacted before a record is ever constructed — see `marshal-secrets`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub identity: String,
    /// `false` when no identity resolver matched.
    pub attributed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    pub profile: String,
    pub ingress: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub action: Action,
    /// Which layer produced the terminal verdict, and why.
    pub reason: Reason,
    /// True when the profile is in warn mode and this request *would* have been refused.
    ///
    /// `action` is then `allow` — the request was forwarded — and this field is the entire
    /// signal that policy disagreed. Filter on it to build an allowlist from real traffic.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub would_deny: bool,
    /// Every layer's verdict, in order.
    pub trail: Vec<LayerOutcome>,
    /// Typed observations from every layer *and* every transform — which DLP pattern matched,
    /// which MCP tool was called, which allowlist rule hit, which credential was injected.
    ///
    /// Distinct from `reason`, which is only the layer that *decided*. A request allowed by an
    /// allowlist still has a tool name worth recording, and nothing else in the record carries
    /// it. Omitted when empty, so a record with nothing to say looks exactly as it did before
    /// this field existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: BTreeMap<String, Fact>,
    /// Named boolean observations, e.g. `PossibleSecretInBody`. Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub flags: BTreeSet<Flag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub duration_ms: u64,
    /// Header names and values, request and response — see [`redact_headers`] for what
    /// actually reaches here. Omitted when there is nothing to show: a denial before any
    /// request was parsed, or a response nothing captured (a CONNECT, a raw-relayed plain
    /// request, a request refused before reaching the upstream).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response_headers: BTreeMap<String, String>,
}

/// Header names whose *value* is safe to record verbatim: transport and content negotiation
/// metadata, never a credential or anything that identifies a person. Everything else keeps
/// its name — audit records and the judge already treat header names as safe to see
/// (ADR-0012) — but has its value replaced, since a header this does not recognise is exactly
/// the shape an unanticipated vendor auth scheme takes.
///
/// `location` is deliberately excluded despite looking like routing metadata: an OAuth
/// authorization redirect carries the code in its query string, which is as sensitive as the
/// code itself.
const SAFE_HEADER_VALUES: &[&str] = &[
    "content-type",
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "date",
    "server",
    "vary",
    "via",
    "retry-after",
    "user-agent",
];

/// Header value the record shows in place of anything not in [`SAFE_HEADER_VALUES`].
const REDACTED_HEADER_VALUE: &str = "[redacted]";

/// Turn a header map into what an audit record shows: every header's name, and its value only
/// if the name is known to never carry a credential.
///
/// This is independent of, and in addition to, [`crate::Redactor`]: that scrubs values it has
/// already learned are secret, which cannot cover a value nobody has captured yet (exactly the
/// case debugging an exchange that never completed needs to see the shape of, without seeing
/// the credential itself). Name-based redaction covers the header before either question can
/// even be asked.
pub fn redact_headers(headers: &http::HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        let value = if SAFE_HEADER_VALUES.contains(&lower.as_str()) {
            headers
                .get_all(name)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            REDACTED_HEADER_VALUE.to_owned()
        };
        out.insert(lower, value);
    }
    out
}

/// Where audit records go.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    async fn emit(&self, record: AuditRecord);
}

#[cfg(test)]
mod redact_headers_tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(http::HeaderName::try_from(*k).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn shows_the_value_of_a_known_safe_header() {
        let out = redact_headers(&headers(&[("Content-Type", "application/json")]));
        assert_eq!(out.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn redacts_authorization_by_name_alone() {
        let out = redact_headers(&headers(&[("Authorization", "Bearer sk-real-secret-value")]));
        assert_eq!(out.get("authorization").unwrap(), REDACTED_HEADER_VALUE);
        assert!(!out.values().any(|v| v.contains("sk-real-secret-value")));
    }

    #[test]
    fn redacts_cookie_and_set_cookie() {
        let out = redact_headers(&headers(&[
            ("Cookie", "session=abc123"),
            ("Set-Cookie", "session=xyz; HttpOnly"),
        ]));
        assert_eq!(out.get("cookie").unwrap(), REDACTED_HEADER_VALUE);
        assert_eq!(out.get("set-cookie").unwrap(), REDACTED_HEADER_VALUE);
    }

    #[test]
    fn redacts_location_despite_looking_like_routing_metadata() {
        // An authorization redirect carries the code in the query string.
        let out = redact_headers(&headers(&[(
            "Location",
            "https://example.com/callback?code=super-secret-auth-code",
        )]));
        assert_eq!(out.get("location").unwrap(), REDACTED_HEADER_VALUE);
    }

    #[test]
    fn redacts_an_unrecognised_header_by_default() {
        // The whole point: a vendor's own auth scheme under a header this has never heard of
        // must not be shown just because it isn't on a denylist.
        let out = redact_headers(&headers(&[("X-Vendor-Session-Token", "totally-real-token")]));
        assert_eq!(out.get("x-vendor-session-token").unwrap(), REDACTED_HEADER_VALUE);
    }

    #[test]
    fn always_records_the_header_name_even_when_the_value_is_redacted() {
        let out = redact_headers(&headers(&[("Authorization", "secret")]));
        assert!(out.contains_key("authorization"));
    }
}
