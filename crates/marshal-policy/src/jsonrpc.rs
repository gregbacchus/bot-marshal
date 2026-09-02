//! Just enough JSON-RPC 2.0 to police MCP.
//!
//! Deliberately tolerant: anything that does not parse as a JSON-RPC call is simply not an
//! MCP request, and the layer passes rather than erroring. A proxy that rejected malformed
//! JSON would be enforcing a rule nobody asked for, on traffic that may not be MCP at all.

use serde_json::Value;

/// A parsed `tools/call`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    /// Echoed back in an error response so the client can correlate it.
    pub id: Option<Value>,
    pub tool: String,
    pub arguments: Option<Value>,
}

/// What a JSON-RPC message is, as far as this proxy cares.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    ToolsCall(ToolCall),
    /// A `tools/list` request; the interesting part is its *response*.
    ToolsList {
        id: Option<Value>,
    },
    /// Some other JSON-RPC method.
    Other {
        method: String,
        id: Option<Value>,
    },
}

/// Parse a request body. `None` means "not a JSON-RPC request", not "invalid".
pub fn parse_request(body: &[u8]) -> Option<Message> {
    let doc: Value = serde_json::from_slice(body).ok()?;
    parse_request_value(&doc)
}

pub fn parse_request_value(doc: &Value) -> Option<Message> {
    // The version field is what distinguishes JSON-RPC from arbitrary JSON that happens to
    // have a `method` key.
    if doc.get("jsonrpc")?.as_str()? != "2.0" {
        return None;
    }
    let method = doc.get("method")?.as_str()?.to_owned();
    let id = doc.get("id").cloned();

    match method.as_str() {
        "tools/call" => {
            let params = doc.get("params")?;
            Some(Message::ToolsCall(ToolCall {
                id,
                tool: params.get("name")?.as_str()?.to_owned(),
                arguments: params.get("arguments").cloned(),
            }))
        }
        "tools/list" => Some(Message::ToolsList { id }),
        _ => Some(Message::Other { method, id }),
    }
}

/// Build a JSON-RPC error response.
///
/// A denied MCP call must come back as a JSON-RPC error rather than an HTTP 403. The client
/// is an MCP implementation: a transport-level failure looks to it like the server is down,
/// which produces retries and reconnects, whereas a protocol-level error is something the
/// agent can read and act on.
pub fn error_response(id: Option<Value>, code: i64, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            // -32000 is the reserved range for implementation-defined server errors.
            "code": code,
            "message": message,
        }
    })
}

/// Rewrite a `tools/list` result in place, keeping only tools `visible` accepts.
///
/// Returns the names removed, for the audit trail.
pub fn filter_tools_list(doc: &mut Value, visible: impl Fn(&str) -> bool) -> Vec<String> {
    let Some(tools) = doc.get_mut("result").and_then(|r| r.get_mut("tools")) else {
        return Vec::new();
    };
    let Some(array) = tools.as_array_mut() else { return Vec::new() };

    let mut removed = Vec::new();
    array.retain(|tool| {
        let Some(name) = tool.get("name").and_then(|n| n.as_str()) else {
            // A malformed entry is dropped rather than passed through: an agent cannot use a
            // tool with no name, and letting it past would mean a tool escaping the filter
            // simply by omitting the field the filter reads.
            removed.push("<unnamed>".to_string());
            return false;
        };
        if visible(name) {
            true
        } else {
            removed.push(name.to_owned());
            false
        }
    });
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_tools_call() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"create_issue","arguments":{"owner":"me"}}}"#;
        let Some(Message::ToolsCall(call)) = parse_request(body) else { panic!("not parsed") };
        assert_eq!(call.tool, "create_issue");
        assert_eq!(call.id, Some(serde_json::json!(7)));
        assert_eq!(call.arguments.unwrap()["owner"], "me");
    }

    #[test]
    fn parses_tools_list_and_other_methods() {
        assert_eq!(
            parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            Some(Message::ToolsList { id: Some(serde_json::json!(1)) })
        );
        assert!(matches!(
            parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#),
            Some(Message::Other { .. })
        ));
    }

    #[test]
    fn non_jsonrpc_bodies_are_not_mcp_rather_than_invalid() {
        // A proxy that erred here would be enforcing a rule nobody asked for, on traffic
        // that may not be MCP at all.
        assert_eq!(parse_request(b"not json"), None);
        assert_eq!(parse_request(br#"{"method":"tools/call"}"#), None, "no jsonrpc version");
        assert_eq!(parse_request(br#"{"jsonrpc":"1.0","method":"x"}"#), None);
        assert_eq!(parse_request(b"{}"), None);
        assert_eq!(parse_request(b""), None);
    }

    #[test]
    fn a_tools_call_without_params_is_not_a_call() {
        assert_eq!(parse_request(br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#), None);
    }

    #[test]
    fn filters_a_tools_list_result() {
        let mut doc = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "tools": [
                { "name": "search_code" },
                { "name": "delete_repository" },
                { "name": "create_issue" }
            ]}
        });
        let removed = filter_tools_list(&mut doc, |n| n != "delete_repository");
        assert_eq!(removed, ["delete_repository"]);

        let names: Vec<&str> = doc["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["search_code", "create_issue"]);
    }

    #[test]
    fn an_unnamed_tool_is_dropped_rather_than_passed() {
        // Otherwise a tool escapes the filter simply by omitting the field the filter reads.
        let mut doc = serde_json::json!({
            "result": { "tools": [ { "description": "no name here" } ] }
        });
        let removed = filter_tools_list(&mut doc, |_| true);
        assert_eq!(removed, ["<unnamed>"]);
        assert!(doc["result"]["tools"].as_array().unwrap().is_empty());
    }

    #[test]
    fn responses_without_a_tools_list_are_untouched() {
        let mut doc = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": { "ok": true } });
        let before = doc.clone();
        assert!(filter_tools_list(&mut doc, |_| false).is_empty());
        assert_eq!(doc, before);
    }

    #[test]
    fn error_responses_echo_the_request_id() {
        // Without the id the client cannot correlate the failure with its call, and will
        // usually treat it as a transport fault.
        let e = error_response(Some(serde_json::json!(42)), -32000, "denied");
        assert_eq!(e["id"], 42);
        assert_eq!(e["error"]["code"], -32000);
        assert_eq!(e["jsonrpc"], "2.0");

        assert_eq!(error_response(None, -32000, "x")["id"], serde_json::Value::Null);
    }
}
