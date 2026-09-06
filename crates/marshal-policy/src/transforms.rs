//! Request and response transforms owned by the policy crate.

use std::sync::Arc;

use marshal_core::{
    BodyHandle, BodyRequirement, RequestContext, RequestTransform, ResponseParts,
    ResponseTransform, Result,
};

use crate::jsonrpc;
use crate::mcp::McpPolicy;
use marshal_config::model::{ResponseOversizeAction, TruncationMethod};

/// Adds configured request headers, replacing any value the client supplied for the same
/// name. Values are parsed when the runtime is built, so an allowed request cannot discover
/// malformed configuration only after it is already in flight.
#[derive(Debug)]
pub struct RequestHeaderSetter {
    headers: Vec<(http::HeaderName, http::HeaderValue)>,
}

impl RequestHeaderSetter {
    pub fn new(headers: Vec<(http::HeaderName, http::HeaderValue)>) -> Self {
        Self { headers }
    }
}

#[async_trait::async_trait]
impl RequestTransform for RequestHeaderSetter {
    fn name(&self) -> &str {
        "set_request_headers"
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        for (name, value) in &self.headers {
            cx.headers.insert(name, value.clone());
        }
        Ok(())
    }
}

/// A compiled header filter: exactly one of allow (default-deny — keep only what matches) or
/// deny (default-allow — drop only what matches). Config validation is what enforces "exactly
/// one"; by the time this exists, that choice has already been made.
#[derive(Debug, Clone)]
pub enum HeaderFilterMode {
    Allow(Vec<String>),
    Deny(Vec<String>),
}

/// Case-insensitive glob match, `*` standing for any run of characters (including none) —
/// header names are ASCII per RFC 9110 §5.1, so a byte-wise comparison is exact rather than an
/// approximation. Simple recursive backtracking: header-name patterns are short and few, so
/// this never runs against an input where its worst case matters.
fn header_glob_matches(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => {
                rec(rest, s) || matches!(s.split_first(), Some((_, tail)) if rec(p, tail))
            }
            Some((pc, prest)) => match s.split_first() {
                Some((sc, srest)) if pc.eq_ignore_ascii_case(sc) => rec(prest, srest),
                _ => false,
            },
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

/// `is_managed` exempts framing/routing headers from whatever `mode` says — see
/// [`marshal_config::model::request_header_is_managed`] and its response-side counterpart.
/// Dropping `Host` because an operator's `allow` list forgot it, or `Content-Length` because a
/// `deny` pattern happened to match `content-*`, breaks the request/response outright rather
/// than filtering it; a filter's whole job is the headers *above* that layer, never the wire
/// framing underneath it.
fn header_filter_apply(
    headers: &mut http::HeaderMap,
    mode: &HeaderFilterMode,
    is_managed: fn(&http::HeaderName) -> bool,
) {
    let (patterns, keep_on_match): (&[String], bool) = match mode {
        HeaderFilterMode::Allow(patterns) => (patterns, true),
        HeaderFilterMode::Deny(patterns) => (patterns, false),
    };
    let drop: Vec<http::HeaderName> = headers
        .keys()
        .filter(|name| {
            if is_managed(name) {
                return false;
            }
            let matched = patterns.iter().any(|p| header_glob_matches(p, name.as_str()));
            matched != keep_on_match
        })
        .cloned()
        .collect();
    for name in drop {
        headers.remove(name);
    }
}

/// Filters request headers before the request leaves — see [`HeaderFilterMode`].
#[derive(Debug, Clone)]
pub struct RequestHeaderFilter {
    mode: HeaderFilterMode,
}

impl RequestHeaderFilter {
    pub fn new(mode: HeaderFilterMode) -> Self {
        Self { mode }
    }
}

#[async_trait::async_trait]
impl RequestTransform for RequestHeaderFilter {
    fn name(&self) -> &str {
        "filter_request_headers"
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        header_filter_apply(
            &mut cx.headers,
            &self.mode,
            marshal_config::model::request_header_is_managed,
        );
        Ok(())
    }
}

/// Filters response headers before the response reaches the agent — see [`HeaderFilterMode`].
#[derive(Debug, Clone)]
pub struct ResponseHeaderFilter {
    mode: HeaderFilterMode,
}

impl ResponseHeaderFilter {
    pub fn new(mode: HeaderFilterMode) -> Self {
        Self { mode }
    }
}

#[async_trait::async_trait]
impl ResponseTransform for ResponseHeaderFilter {
    fn name(&self) -> &str {
        "filter_response_headers"
    }

    // Headers only — the body is untouched, so a filter never has a reason to stop a response
    // from streaming.
    fn supports_streaming(&self) -> bool {
        true
    }

    async fn apply(&self, _cx: &RequestContext, resp: &mut ResponseParts) -> Result<()> {
        header_filter_apply(
            &mut resp.headers,
            &self.mode,
            marshal_config::model::response_header_is_managed,
        );
        Ok(())
    }
}

/// Bounds a response body before it reaches the agent.
#[derive(Debug)]
pub struct ResponseLimiter {
    max_bytes: usize,
    on_oversize: ResponseOversizeAction,
}

impl ResponseLimiter {
    pub fn new(max_bytes: usize, on_oversize: ResponseOversizeAction) -> Self {
        Self { max_bytes, on_oversize }
    }

    fn replace_body(&self, resp: &mut ResponseParts, body: bytes::Bytes, action: &'static str) {
        resp.headers.remove(http::header::CONTENT_ENCODING);
        resp.headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
        resp.headers.insert("x-marshal-response-limited", http::HeaderValue::from_static(action));
        resp.body = BodyHandle::Buffered(body);
    }

    fn truncate(&self, source: &[u8], method: TruncationMethod, marker: &str) -> bytes::Bytes {
        let marker_end = match method {
            TruncationMethod::Bytes => marker.len().min(self.max_bytes),
            TruncationMethod::Utf8 => utf8_prefix_len(marker.as_bytes(), self.max_bytes),
        };
        let marker = &marker.as_bytes()[..marker_end];
        let prefix_budget = self.max_bytes - marker.len();
        let prefix_end = match method {
            TruncationMethod::Bytes => source.len().min(prefix_budget),
            TruncationMethod::Utf8 => utf8_prefix_len(source, prefix_budget),
        };
        let mut out = Vec::with_capacity(prefix_end + marker.len());
        out.extend_from_slice(&source[..prefix_end]);
        out.extend_from_slice(marker);
        bytes::Bytes::from(out)
    }
}

fn utf8_prefix_len(bytes: &[u8], limit: usize) -> usize {
    let end = bytes.len().min(limit);
    match std::str::from_utf8(&bytes[..end]) {
        Ok(_) => end,
        Err(error) => error.valid_up_to(),
    }
}

#[async_trait::async_trait]
impl ResponseTransform for ResponseLimiter {
    fn name(&self) -> &str {
        "response_limit"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Buffered { cap: self.max_bytes }
    }

    async fn apply(&self, _cx: &RequestContext, resp: &mut ResponseParts) -> Result<()> {
        let raw_oversized = match &resp.body {
            BodyHandle::Buffered(source) if source.len() > self.max_bytes => {
                Some((source.clone(), source.len()))
            }
            BodyHandle::OverLimit { prefix, observed, .. } => Some((prefix.clone(), *observed)),
            _ => None,
        };

        // Encoded bytes carry no relationship to the decoded size the operator meant to cap —
        // a small compressed payload can decompress into an arbitrarily large one — so an
        // encoded response is treated as *always* potentially oversized, regardless of how
        // small the bytes on the wire look. `Fail` and `Truncate` both reason about how much
        // content there *actually is* and cannot proceed safely on that unknown, so they
        // refuse. `Replace` needs none of that: it discards the body outright regardless of
        // what it contained, so it is exactly as safe on encoded content as on plain content,
        // and only needs to run at all when the encoded bytes are themselves over the limit.
        let encoded = resp
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.eq_ignore_ascii_case("identity"));

        if !encoded && raw_oversized.is_none() {
            return Ok(());
        }

        if encoded && !matches!(self.on_oversize, ResponseOversizeAction::Replace { .. }) {
            let body = bytes::Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "error": "encoded_response_size_unknown",
                    "proxy": "bot-marshal",
                    "max_bytes": self.max_bytes,
                    "message": "cannot enforce a decoded response limit on encoded bytes; request identity encoding",
                }))
                .unwrap_or_default(),
            );
            resp.status = http::StatusCode::BAD_GATEWAY;
            resp.headers.insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            );
            self.replace_body(resp, body, "fail");
            return Ok(());
        }

        if encoded && raw_oversized.is_none() {
            // Encoded, under the raw-byte limit, and the action is `Replace`: nothing to do —
            // `Replace` only fires when there is actually something over the limit to replace.
            return Ok(());
        }
        // Reachable only with `raw_oversized` populated: either not encoded (checked above),
        // or encoded with `Replace` and already over the raw-byte limit (checked just above).
        let (source, observed) = raw_oversized.expect("oversize checked above");

        match &self.on_oversize {
            ResponseOversizeAction::Fail => {
                let body = bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({
                        "error": "response_too_large",
                        "proxy": "bot-marshal",
                        "max_bytes": self.max_bytes,
                        "received_at_least_bytes": observed,
                    }))
                    .unwrap_or_default(),
                );
                resp.status = http::StatusCode::BAD_GATEWAY;
                resp.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                );
                self.replace_body(resp, body, "fail");
            }
            ResponseOversizeAction::Truncate { method, marker } => {
                let body = self.truncate(&source, *method, marker);
                self.replace_body(resp, body, "truncate");
            }
            ResponseOversizeAction::Replace { body } => {
                resp.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                self.replace_body(resp, bytes::Bytes::copy_from_slice(body.as_bytes()), "replace");
            }
        }
        Ok(())
    }
}

/// Removes denied tools from a `tools/list` response.
///
/// This matters more than blocking the call. Refusing a `tools/call` gives the agent an error
/// to interpret, which for an LLM-driven agent means retries and creative workarounds.
/// Removing the tool from the listing means the intent never forms.
#[derive(Debug)]
pub struct McpToolFilter {
    policy: Arc<McpPolicy>,
    body_cap: usize,
}

impl McpToolFilter {
    pub fn new(policy: Arc<McpPolicy>, body_cap: usize) -> Self {
        Self { policy, body_cap }
    }

    /// Filter one JSON-RPC document, returning the tools removed.
    fn filter_document(&self, host: &str, doc: &mut serde_json::Value) -> Vec<String> {
        jsonrpc::filter_tools_list(doc, |name| self.policy.tool_is_visible(host, name))
    }

    /// Filter a `text/event-stream` chunk.
    ///
    /// MCP's streamable HTTP transport delivers responses as SSE, so the filter has to work
    /// on events rather than on a whole body. Each event is rewritten independently, which
    /// keeps the response streaming — buffering it to filter would undo the streaming
    /// guarantees the proxy makes everywhere else.
    pub fn filter_sse_chunk(&self, host: &str, chunk: &str) -> (String, Vec<String>) {
        let mut out = String::with_capacity(chunk.len());
        let mut removed = Vec::new();

        for line in chunk.split_inclusive('\n') {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            let Some(payload) = trimmed.strip_prefix("data:") else {
                out.push_str(line);
                continue;
            };
            let payload = payload.trim_start();

            let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(payload) else {
                out.push_str(line);
                continue;
            };

            let gone = self.filter_document(host, &mut doc);
            if gone.is_empty() {
                out.push_str(line);
                continue;
            }
            removed.extend(gone);

            // Re-serialise compactly: SSE data must not contain a bare newline, and an
            // embedded one would split the event.
            out.push_str("data: ");
            out.push_str(&serde_json::to_string(&doc).unwrap_or_else(|_| payload.to_owned()));
            out.push('\n');
        }
        (out, removed)
    }
}

#[async_trait::async_trait]
impl ResponseTransform for McpToolFilter {
    fn name(&self) -> &str {
        "mcp_tool_filter"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Buffered { cap: self.body_cap }
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn rewrite_chunk(&self, host: &str, chunk: &str) -> Option<String> {
        if !self.policy.governs(host) {
            return None;
        }
        let (rewritten, removed) = self.filter_sse_chunk(host, chunk);
        if !removed.is_empty() {
            tracing::info!(%host, ?removed, "filtered tools out of an MCP event");
        }
        Some(rewritten)
    }

    async fn apply(&self, cx: &RequestContext, resp: &mut ResponseParts) -> Result<()> {
        if !self.policy.governs(&cx.authority.host) {
            return Ok(());
        }

        let BodyHandle::Buffered(bytes) = &resp.body else {
            return Ok(());
        };
        let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Ok(());
        };

        let removed = self.filter_document(&cx.authority.host, &mut doc);
        if removed.is_empty() {
            return Ok(());
        }

        tracing::info!(
            host = %cx.authority.host,
            ?removed,
            "filtered tools out of an MCP listing"
        );

        let rewritten = serde_json::to_vec(&doc).map_err(|e| {
            marshal_core::Error::Other(format!("re-serialising a filtered tools/list: {e}"))
        })?;

        // The body changed length; a stale Content-Length desynchronises the connection.
        resp.headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(rewritten.len()));
        resp.body = BodyHandle::Buffered(bytes::Bytes::from(rewritten));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_config::layer::McpServer;

    fn header_map(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    #[test]
    fn glob_matches_a_trailing_star_case_insensitively() {
        assert!(header_glob_matches("content-*", "Content-Type"));
        assert!(header_glob_matches("content-*", "content-length"));
        assert!(!header_glob_matches("content-*", "accept"));
    }

    #[test]
    fn glob_matches_exact_names_case_insensitively() {
        assert!(header_glob_matches("authorization", "Authorization"));
        assert!(!header_glob_matches("authorization", "x-authorization"));
    }

    #[test]
    fn glob_matches_a_star_in_the_middle() {
        assert!(header_glob_matches("x-*-id", "x-request-id"));
        assert!(!header_glob_matches("x-*-id", "x-request-token"));
    }

    #[test]
    fn allow_keeps_only_matching_headers() {
        let mut h = header_map(&[
            ("accept", "*/*"),
            ("content-type", "application/json"),
            ("x-custom", "drop-me"),
        ]);
        header_filter_apply(
            &mut h,
            &HeaderFilterMode::Allow(vec!["accept*".into(), "content-*".into()]),
            marshal_config::model::request_header_is_managed,
        );
        assert!(h.contains_key("accept"));
        assert!(h.contains_key("content-type"));
        assert!(!h.contains_key("x-custom"));
    }

    #[test]
    fn deny_drops_only_matching_headers_and_keeps_the_rest() {
        let mut h = header_map(&[
            ("accept", "*/*"),
            ("chatgpt-account-id", "acct-1"),
            ("x-custom", "keep-me"),
        ]);
        header_filter_apply(
            &mut h,
            &HeaderFilterMode::Deny(vec!["chatgpt-account-id".into()]),
            marshal_config::model::request_header_is_managed,
        );
        assert!(h.contains_key("accept"));
        assert!(h.contains_key("x-custom"));
        assert!(!h.contains_key("chatgpt-account-id"));
    }

    #[test]
    fn a_multi_valued_header_is_removed_entirely_by_deny() {
        let mut h = http::HeaderMap::new();
        h.append(http::header::VIA, "1.1 a".parse().unwrap());
        h.append(http::header::VIA, "1.1 b".parse().unwrap());
        header_filter_apply(
            &mut h,
            &HeaderFilterMode::Deny(vec!["via".into()]),
            marshal_config::model::request_header_is_managed,
        );
        assert!(!h.contains_key(http::header::VIA));
    }

    #[test]
    fn an_allow_list_that_omits_host_does_not_strip_it() {
        // The exact bug this exists to prevent: `allow: ["accept*"]` reads as "keep only
        // Accept", but Host is wire framing, not a header a filter has any business dropping.
        let mut h = header_map(&[("accept", "*/*"), ("host", "example.com")]);
        header_filter_apply(
            &mut h,
            &HeaderFilterMode::Allow(vec!["accept*".into()]),
            marshal_config::model::request_header_is_managed,
        );
        assert!(h.contains_key("host"), "Host must survive an allow-list that never named it");
    }

    #[test]
    fn a_deny_list_matching_content_length_by_glob_does_not_strip_it() {
        let mut h = header_map(&[("content-length", "42"), ("content-type", "text/plain")]);
        header_filter_apply(
            &mut h,
            &HeaderFilterMode::Deny(vec!["content-*".into()]),
            marshal_config::model::request_header_is_managed,
        );
        assert!(h.contains_key("content-length"), "framing headers are never dropped by deny");
        assert!(!h.contains_key("content-type"), "an unmanaged header the pattern named is");
    }

    fn filter() -> McpToolFilter {
        let servers: Vec<McpServer> = serde_yaml_ng::from_str(
            r#"
- rules: [{ host: "mcp.example.com" }]
  tools:
    - name: "search_*"
    - name: "create_issue"
"#,
        )
        .unwrap();
        McpToolFilter::new(Arc::new(McpPolicy::compile(&servers).unwrap()), 1024 * 1024)
    }

    #[test]
    fn sse_events_are_filtered_without_buffering_the_stream() {
        let chunk = "event: message\n\
                     data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[\
                     {\"name\":\"search_code\"},{\"name\":\"delete_repository\"}]}}\n\
                     \n";
        let (out, removed) = filter().filter_sse_chunk("mcp.example.com", chunk);

        assert_eq!(removed, ["delete_repository"]);
        assert!(out.starts_with("event: message\n"), "framing must survive: {out:?}");
        assert!(out.contains("search_code"));
        assert!(!out.contains("delete_repository"));
        assert!(out.ends_with("\n\n"), "the blank line terminating the event: {out:?}");
    }

    #[test]
    fn non_data_lines_and_unparseable_payloads_pass_through_unchanged() {
        let f = filter();
        for chunk in [": a comment\n\n", "event: ping\ndata: not-json\n\n", "\n"] {
            let (out, removed) = f.filter_sse_chunk("mcp.example.com", chunk);
            assert_eq!(out, chunk, "{chunk:?}");
            assert!(removed.is_empty());
        }
    }

    #[test]
    fn a_rewritten_event_never_contains_a_bare_newline() {
        // A pretty-printed payload would split one event into several and corrupt the stream.
        let chunk = "data: {\"result\":{\"tools\":[{\"name\":\"a\"},{\"name\":\"search_x\"}]}}\n\n";
        let (out, _) = filter().filter_sse_chunk("mcp.example.com", chunk);
        let data_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("data:")).collect();
        assert_eq!(data_lines.len(), 1, "the event was split: {out:?}");
    }

    #[tokio::test]
    async fn json_responses_are_filtered_and_content_length_corrected() {
        use marshal_core::{Authority, Evidence, Identity, IngressMode, Phase};

        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "tools": [
                { "name": "search_code" },
                { "name": "delete_repository" }
            ]}
        }))
        .unwrap();

        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(body.len()));
        let mut resp = ResponseParts {
            status: http::StatusCode::OK,
            headers,
            body: BodyHandle::Buffered(bytes::Bytes::from(body.clone())),
        };

        let cx = RequestContext {
            identity: Identity::new("t"),
            profile: Arc::from("p"),
            ingress: IngressMode::Explicit,
            phase: Phase::Request,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            authority: Authority { host: "mcp.example.com".into(), port: 443 },
            method: http::Method::POST,
            uri: "/mcp".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: BodyHandle::Empty,
            evidence: Evidence::new(),
        };

        filter().apply(&cx, &mut resp).await.unwrap();

        let BodyHandle::Buffered(out) = &resp.body else { panic!("body not buffered") };
        let doc: serde_json::Value = serde_json::from_slice(out).unwrap();
        let names: Vec<&str> = doc["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["search_code"]);

        let declared: usize =
            resp.headers[http::header::CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
        assert_eq!(declared, out.len(), "a stale Content-Length desynchronises the connection");
        assert_ne!(declared, body.len());
    }
}
