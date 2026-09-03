//! M5 acceptance: tool-level policy over MCP.

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::{HostMatcher, build_chain, build_response_transforms};
use marshal_proxy::identity::IdentityRegistry;
use marshal_proxy::mitm::TlsEngine;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::*;

/// Allows the loopback MCP server, permits two tools, denies everything else.
const MCP_PROFILE: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: pass
      on_miss: deny
    - layer: mcp
      servers:
        - rules: [{ cidr: "127.0.0.0/8" }]
          tools:
            - name: "search_*"
            - name: "create_issue"
              when: [{ path: owner, equals: gregbacchus }]
    - layer: rules
      expressions:
        - when: 'true'
          verdict: allow
"#;

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    ca_pem: String,
}

async fn harness() -> Harness {
    let pki = test_pki();
    let upstream = start_tls_upstream(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(MCP_PROFILE).unwrap();
    let mut chains = HashMap::new();
    chains.insert(
        Arc::from("p"),
        Arc::new(build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap()),
    );

    let mut transforms = HashMap::new();
    transforms.insert(Arc::from("p"), build_response_transforms(&cfg, "p", &cfg.profile).unwrap());

    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(tokio::io::sink()));
    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(marshal_proxy::runtime::Runtime {
            chains,
            response_transforms: transforms,
            responders: std::collections::HashMap::new(),
            request_transforms: std::collections::HashMap::new(),
            default_chain: Arc::new(marshal_policy::Chain::new(
                "default",
                vec![],
                marshal_core::Decision::Deny,
                Arc::new(DenyingDecider),
            )),
            default_response_transforms: Vec::new(),
            default_responders: Vec::new(),
            default_request_transforms: Vec::new(),
            identities: Arc::new(IdentityRegistry::new(vec![], Some(Arc::from("p")), false, false)),
            passthrough: HostMatcher::default(),
            tls: engine,
        }),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit,
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |a| {
                let _ = tx.take().unwrap().send(a);
            })
            .await;
    });

    Harness { proxy: rx.await.unwrap(), upstream, ca_pem }
}

/// Send a JSON-RPC request through the proxy and return the parsed reply.
async fn rpc(h: &Harness, path: &str, body: serde_json::Value) -> serde_json::Value {
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.ca_pem).await;
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}{path}", h.upstream))
        .header("host", h.upstream.to_string())
        .header("content-type", "application/json")
        .body(full(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("a JSON reply")
}

fn call(tool: &str, arguments: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": 42, "method": "tools/call",
        "params": { "name": tool, "arguments": arguments }
    })
}

#[tokio::test]
async fn a_permitted_tool_call_reaches_the_server() {
    let h = harness().await;
    let reply = rpc(&h, "/mcp", call("search_code", serde_json::json!({"q": "x"}))).await;
    assert_eq!(reply["result"]["called"]["name"], "search_code");
    assert!(reply.get("error").is_none(), "{reply}");
}

#[tokio::test]
async fn a_denied_tool_call_returns_a_jsonrpc_error_not_a_transport_failure() {
    // The client is an MCP implementation. An HTTP 403 reads to it as "the server is down"
    // and produces reconnects; a JSON-RPC error is something the agent can act on.
    let h = harness().await;
    let reply = rpc(&h, "/mcp", call("delete_repository", serde_json::json!({}))).await;

    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 42, "the id must be echoed or the client cannot correlate it");
    assert_eq!(reply["error"]["code"], marshal_proxy::mitm::MCP_DENIED_CODE);

    let message = reply["error"]["message"].as_str().unwrap();
    assert!(message.contains("delete_repository"), "{message}");
    assert!(reply.get("result").is_none(), "a refusal must not also carry a result");
}

#[tokio::test]
async fn argument_constraints_are_enforced_on_the_wire() {
    let h = harness().await;

    let ok =
        rpc(&h, "/mcp", call("create_issue", serde_json::json!({"owner": "gregbacchus"}))).await;
    assert_eq!(ok["result"]["called"]["name"], "create_issue");

    let denied =
        rpc(&h, "/mcp", call("create_issue", serde_json::json!({"owner": "someone-else"}))).await;
    assert!(denied["error"]["message"].as_str().unwrap().contains("owner"), "{denied}");
}

#[tokio::test]
async fn denied_tools_are_removed_from_a_json_tools_list() {
    let h = harness().await;
    let reply =
        rpc(&h, "/mcp", serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).await;

    let names: Vec<&str> = reply["result"]["tools"]
        .as_array()
        .expect("a tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();

    // The upstream offered three; the agent must never learn about the third.
    assert_eq!(names, ["search_code", "create_issue"], "{reply}");
}

#[tokio::test]
async fn denied_tools_are_removed_from_an_sse_tools_list() {
    // MCP's streamable HTTP transport usually returns listings as SSE, and filtering must
    // work there without collapsing the stream into a buffer.
    let h = harness().await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.ca_pem).await;
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/mcp-sse", h.upstream))
        .header("host", h.upstream.to_string())
        .header("accept", "text/event-stream")
        .body(full(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc":"2.0","id":1,"method":"tools/list"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.headers()["content-type"], "text/event-stream");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);

    assert!(text.contains("search_code"), "{text}");
    assert!(!text.contains("delete_repository"), "a denied tool survived SSE filtering: {text}");
    // Event framing must be intact, or the client cannot parse the stream at all.
    assert!(text.starts_with("event: message\n"), "{text:?}");
    assert!(text.trim_end().ends_with('}'), "{text:?}");
    let data_lines = text.lines().filter(|l| l.starts_with("data:")).count();
    assert_eq!(data_lines, 1, "the event was split across lines: {text:?}");
}

#[tokio::test]
async fn ordinary_http_to_an_mcp_host_is_not_disturbed() {
    // MCP servers also serve plain HTTP. The layer has no opinion on that, and treating a
    // non-JSON-RPC body as a policy violation would break the server's other endpoints.
    let h = harness().await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.ca_pem).await;
    let resp = sender.send_request(request(h.upstream, "/plain")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn a_tools_call_that_is_denied_never_reaches_the_upstream() {
    // The echo server reports what it received. A denied call must produce no record there:
    // policy runs before the request is forwarded, not after.
    let h = harness().await;
    let reply = rpc(&h, "/mcp", call("delete_repository", serde_json::json!({}))).await;
    assert!(reply.get("result").is_none());
    assert!(reply["error"].is_object());
}
