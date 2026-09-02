//! Response transforms owned by the policy crate.

use std::sync::Arc;

use marshal_core::{
    BodyHandle, BodyRequirement, RequestContext, ResponseParts, ResponseTransform, Result,
};

use crate::jsonrpc;
use crate::mcp::McpPolicy;

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
