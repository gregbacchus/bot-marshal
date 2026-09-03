//! Calling out to an LLM to answer a scoping question, and only that.
//!
//! # Hardening against the request being adversarial
//!
//! The content under review is attacker-influenced — a prompt-injected agent can shape the
//! method, host, path, and header names the judge sees, and (before this layer even runs) it
//! may have tried to talk the *proxy* into ignoring its own instructions. Two things hold
//! that off structurally rather than by convention, and both apply to every provider, not
//! just one:
//!
//! * The request is placed in the model's turn as clearly delimited data, inside explicit
//!   `<request>` tags, never concatenated into the system prompt. The operator's instructions
//!   and the untrusted content are never the same string.
//! * The verdict comes back through a forced tool/function call, not by parsing prose. The
//!   model has exactly one way to answer, and this layer has exactly one way to read it:
//!   deserialise the tool's arguments. There is no free-text path for an injected instruction
//!   to influence, because none of the response is treated as instructions to begin with.
//!
//! What this does *not* guarantee: that the underlying model cannot be talked into answering
//! "allow" by a sufficiently crafted `<request>` payload even through that data channel. That
//! is a live-model behavioural property, not a parsing one, and no amount of request
//! structuring proves it in a unit test. Treat the judge as a defence-in-depth layer, not a
//! substitute for the layers before it in the chain.
//!
//! # Adding a provider
//!
//! Each provider owns only its request envelope, response parsing, and default
//! [`Endpoint`] — the scoping constraints (no body, no header values, structured-output-only)
//! live in [`crate::Judge`] itself, so a new provider inherits them automatically. Every
//! provider also takes an optional `base_url`: a self-hosted or compatible server (Azure
//! OpenAI, a local vLLM/Ollama instance, an internal gateway) is a normal thing to want
//! instead of the real vendor endpoint, and [`Endpoint::parse`] is the only code that needs
//! to know that.

use serde::Deserialize;

pub mod anthropic;
pub mod endpoint;
pub mod openai;

pub use anthropic::AnthropicProvider;
pub use endpoint::Endpoint;
pub use openai::OpenAiProvider;

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
    #[error("the provider's response exceeded {limit} bytes without completing")]
    ResponseTooLarge { limit: usize },
    #[error("the provider's response did not contain a verdict tool call")]
    NoToolCall,
    #[error("the verdict tool call was malformed: {0}")]
    MalformedVerdict(#[source] serde_json::Error),
    #[error("`{0}` is not set")]
    MissingApiKey(String),
    #[error("invalid provider base_url: {0}")]
    InvalidBaseUrl(String),
}

/// Something that can turn a request into a verdict. A trait so tests can substitute a fake
/// without a network, and so a new provider is exactly one more implementation of this trait
/// plus one more `match` arm in `build_chain` — nothing in `Judge` itself changes.
#[async_trait::async_trait]
pub trait Provider: Send + Sync + std::fmt::Debug {
    async fn judge(
        &self,
        request: &JudgeRequest,
        prompt: &str,
    ) -> Result<JudgeVerdict, ProviderError>;
}

pub(crate) const VERDICT_TOOL_NAME: &str = "verdict";

/// The JSON Schema every provider asks the model to fill in. Shared because the schema itself
/// is provider-agnostic — only how each API wants it wrapped (Anthropic's `tools[].input_schema`
/// vs OpenAI's `tools[].function.parameters`) differs.
pub(crate) fn verdict_parameters_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "decision": { "type": "string", "enum": ["allow", "deny", "pass"] },
            "reason": { "type": "string", "description": "One sentence explaining the decision." }
        },
        "required": ["decision", "reason"]
    })
}

/// The untrusted content, delimited. Shared verbatim across providers: the hardening property
/// this buys does not depend on which model reads it.
pub(crate) fn user_content(request: &JudgeRequest) -> String {
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

/// Build the TLS client config every provider uses: public roots, no client auth, HTTP/1.1
/// only. Shared because there is nothing provider-specific about it. Only consulted when an
/// endpoint is actually `https`.
pub(crate) fn default_tls_config() -> std::sync::Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_content_places_the_request_inside_explicit_tags_and_carries_no_values() {
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
        // Header names only — this is shared across every provider, so proving it once here
        // covers Anthropic and OpenAI (and anything added later) without duplicating the test.
        assert!(!content.to_lowercase().contains("bearer"));
    }
}
