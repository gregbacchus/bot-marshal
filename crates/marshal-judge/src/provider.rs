//! Calling out to an LLM to answer a scoping question, and only that.
//!
//! # Hardening against the request being adversarial
//!
//! The content under review is attacker-influenced — a prompt-injected agent can shape the
//! method, host, path, and header names the judge sees, and (before this layer even runs) it
//! may have tried to talk the *proxy* into ignoring its own instructions. Two things hold
//! that off structurally rather than by convention:
//!
//! * The request is placed in the `messages` array as clearly delimited data, inside explicit
//!   `<request>` tags, never concatenated into the system prompt. The operator's instructions
//!   and the untrusted content are never the same string.
//! * The verdict comes back through a forced tool call (`tool_choice`), not by parsing prose.
//!   The model has exactly one way to answer, and this layer has exactly one way to read it:
//!   deserialise the tool's `input`. There is no free-text path for an injected instruction to
//!   influence, because none of the response is treated as instructions to begin with.
//!
//! What this does *not* guarantee: that the underlying model cannot be talked into answering
//! "allow" by a sufficiently crafted `<request>` payload even through that data channel. That
//! is a live-model behavioural property, not a parsing one, and no amount of request
//! structuring proves it in a unit test. Treat the judge as a defence-in-depth layer, not a
//! substitute for the layers before it in the chain.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use serde::Deserialize;

use crate::request::JudgeRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    /// The model was not confident enough to decide. Falls through to whatever the chain
    /// does next, exactly like any other layer's `Pass`.
    Pass,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JudgeVerdict {
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("resolving the provider host: {0}")]
    Resolve(#[source] std::io::Error),
    #[error("connecting to the provider: {0}")]
    Connect(#[source] std::io::Error),
    #[error("tls handshake with the provider: {0}")]
    Tls(#[source] std::io::Error),
    #[error("http error talking to the provider: {0}")]
    Http(#[from] hyper::Error),
    #[error("the provider returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("the provider's response did not contain a verdict tool call")]
    NoToolCall,
    #[error("the verdict tool call was malformed: {0}")]
    MalformedVerdict(#[from] serde_json::Error),
    #[error("`{0}` is not set")]
    MissingApiKey(String),
}

/// Something that can turn a request into a verdict. A trait so tests can substitute a fake
/// without a network.
#[async_trait::async_trait]
pub trait Provider: Send + Sync + std::fmt::Debug {
    async fn judge(
        &self,
        request: &JudgeRequest,
        prompt: &str,
    ) -> Result<JudgeVerdict, ProviderError>;
}

const VERDICT_TOOL_NAME: &str = "verdict";

fn verdict_tool_schema() -> serde_json::Value {
    serde_json::json!({
        "name": VERDICT_TOOL_NAME,
        "description": "Report the policy decision for the request under review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "decision": { "type": "string", "enum": ["allow", "deny", "pass"] },
                "reason": { "type": "string", "description": "One sentence explaining the decision." }
            },
            "required": ["decision", "reason"]
        }
    })
}

fn user_content(request: &JudgeRequest) -> String {
    // Explicit tags around the untrusted content, and an instruction that only ever refers to
    // calling the tool — there is no point at which model output flows back into a prompt.
    format!(
        "<request>\n\
         method: {}\n\
         host: {}\n\
         path: {}\n\
         header_names: {:?}\n\
         </request>\n\n\
         Evaluate the request above against the policy and call the `{VERDICT_TOOL_NAME}` \
         tool with your decision.",
        request.method, request.host, request.path, request.header_names,
    )
}

#[derive(Debug)]
pub struct AnthropicProvider {
    model: String,
    api_key: String,
    max_tokens: u32,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AnthropicProvider {
    pub fn new(model: String, api_key: String, max_tokens: Option<u32>) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg =
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        Self { model, api_key, max_tokens: max_tokens.unwrap_or(256), tls_config: Arc::new(cfg) }
    }

    /// Read the API key from the named environment variable. A missing key is a startup-time
    /// configuration error, not a per-request one — callers should surface it before the
    /// layer ever handles traffic.
    pub fn from_env(
        model: String,
        api_key_env: &str,
        max_tokens: Option<u32>,
    ) -> Result<Self, ProviderError> {
        let api_key = std::env::var(api_key_env)
            .map_err(|_| ProviderError::MissingApiKey(api_key_env.to_owned()))?;
        Ok(Self::new(model, api_key, max_tokens))
    }
}

#[async_trait::async_trait]
impl Provider for AnthropicProvider {
    async fn judge(
        &self,
        request: &JudgeRequest,
        prompt: &str,
    ) -> Result<JudgeVerdict, ProviderError> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": prompt,
            "messages": [{ "role": "user", "content": user_content(request) }],
            "tools": [verdict_tool_schema()],
            "tool_choice": { "type": "tool", "name": VERDICT_TOOL_NAME },
        });
        let bytes = serde_json::to_vec(&body).expect("judge request body serialises");

        let req = Request::builder()
            .method("POST")
            .uri("https://api.anthropic.com/v1/messages")
            .header("host", "api.anthropic.com")
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .body(
                Full::new(Bytes::from(bytes))
                    .map_err(|e: std::convert::Infallible| match e {})
                    .boxed(),
            )
            .expect("well-formed request");

        let response = self.send(req).await?;
        parse_verdict(response)
    }
}

impl AnthropicProvider {
    /// One request, one connection. The judge is called rarely enough relative to ordinary
    /// proxy traffic that connection reuse is an optimisation worth deferring rather than
    /// complexity worth carrying from the start.
    async fn send(
        &self,
        req: Request<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>>,
    ) -> Result<serde_json::Value, ProviderError> {
        let addr = tokio::net::lookup_host(("api.anthropic.com", 443))
            .await
            .map_err(ProviderError::Resolve)?
            .next()
            .ok_or_else(|| {
                ProviderError::Resolve(std::io::Error::other("no address for api.anthropic.com"))
            })?;

        let tcp = tokio::net::TcpStream::connect(addr).await.map_err(ProviderError::Connect)?;
        let server_name = rustls::pki_types::ServerName::try_from("api.anthropic.com")
            .expect("static hostname")
            .to_owned();
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config))
            .connect(server_name, tcp)
            .await
            .map_err(ProviderError::Tls)?;

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let body = resp.into_body().collect().await?.to_bytes();

        if !status.is_success() {
            return Err(ProviderError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }

        serde_json::from_slice(&body).map_err(ProviderError::MalformedVerdict)
    }
}

/// Pull the forced tool call's `input` out of an Anthropic Messages response and deserialise
/// it as the verdict. This is the only place response content is ever interpreted, and it is
/// interpreted as structured data, never as text.
fn parse_verdict(response: serde_json::Value) -> Result<JudgeVerdict, ProviderError> {
    let tool_input = response
        .get("content")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
        .find(|block| block.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        .and_then(|block| block.get("input"))
        .ok_or(ProviderError::NoToolCall)?;

    Ok(serde_json::from_value(tool_input.clone())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_content_places_the_request_inside_explicit_tags() {
        let req = JudgeRequest {
            method: "POST".into(),
            host: "api.github.com".into(),
            path: "/repos/x/y".into(),
            header_names: vec!["authorization".into(), "content-type".into()],
        };
        let content = user_content(&req);
        assert!(content.contains("<request>"));
        assert!(content.contains("</request>"));
        assert!(content.contains("method: POST"));
        assert!(content.contains("host: api.github.com"));
        // Never a value, only names — the whole point of JudgeRequest's shape.
        assert!(!content.to_lowercase().contains("bearer"));
    }

    #[test]
    fn parses_a_well_formed_tool_call_response() {
        let response = serde_json::json!({
            "content": [
                { "type": "text", "text": "some preamble the model might add" },
                { "type": "tool_use", "name": "verdict", "input": { "decision": "deny", "reason": "writes a workflow file" } }
            ]
        });
        let v = parse_verdict(response).unwrap();
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.reason, "writes a workflow file");
    }

    #[test]
    fn a_response_with_no_tool_call_is_an_explicit_error() {
        // Falling back to parsing the "text" block here would reopen exactly the free-text
        // path the forced tool call exists to close.
        let response = serde_json::json!({ "content": [{ "type": "text", "text": "allow it" }] });
        assert!(matches!(parse_verdict(response), Err(ProviderError::NoToolCall)));
    }

    #[test]
    fn an_unknown_decision_value_is_a_parse_error_not_a_silent_default() {
        let response = serde_json::json!({
            "content": [{ "type": "tool_use", "name": "verdict", "input": { "decision": "maybe", "reason": "x" } }]
        });
        assert!(matches!(parse_verdict(response), Err(ProviderError::MalformedVerdict(_))));
    }

    #[test]
    fn from_env_reports_a_missing_key_by_name() {
        let err =
            AnthropicProvider::from_env("m".into(), "MARSHAL_TEST_DEFINITELY_ABSENT_KEY", None)
                .unwrap_err();
        assert!(
            matches!(err, ProviderError::MissingApiKey(k) if k == "MARSHAL_TEST_DEFINITELY_ABSENT_KEY")
        );
    }
}
