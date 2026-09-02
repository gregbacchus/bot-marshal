//! The Anthropic Messages API.
//!
//! Its tool-use response carries `input` as a native JSON object — parsed directly, no second
//! decode step. Contrast [`super::openai`], whose `arguments` field is a JSON-encoded string.

use std::sync::Arc;

use crate::request::JudgeRequest;

use super::{
    JudgeVerdict, Provider, ProviderError, VERDICT_TOOL_NAME, connect_and_post_json,
    default_tls_config, json_post_request, user_content, verdict_parameters_schema,
};

const HOST: &str = "api.anthropic.com";

#[derive(Debug)]
pub struct AnthropicProvider {
    model: String,
    api_key: String,
    max_tokens: u32,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AnthropicProvider {
    pub fn new(model: String, api_key: String, max_tokens: Option<u32>) -> Self {
        Self {
            model,
            api_key,
            max_tokens: max_tokens.unwrap_or(256),
            tls_config: default_tls_config(),
        }
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
            "tools": [{
                "name": VERDICT_TOOL_NAME,
                "description": "Report the policy decision for the request under review.",
                "input_schema": verdict_parameters_schema(),
            }],
            "tool_choice": { "type": "tool", "name": VERDICT_TOOL_NAME },
        });

        let req = json_post_request(
            "https://api.anthropic.com/v1/messages",
            HOST,
            &[("x-api-key", &self.api_key), ("anthropic-version", "2023-06-01")],
            body,
        );

        let response = connect_and_post_json(HOST, &self.tls_config, req).await?;
        parse_verdict(response)
    }
}

/// Pull the forced tool call's `input` out of an Anthropic Messages response and deserialise
/// it as the verdict — a native JSON object already, no second decode. This is the only place
/// response content is ever interpreted, and it is interpreted as structured data, never text.
fn parse_verdict(response: serde_json::Value) -> Result<JudgeVerdict, ProviderError> {
    let tool_input = response
        .get("content")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
        .find(|block| block.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        .and_then(|block| block.get("input"))
        .ok_or(ProviderError::NoToolCall)?;

    serde_json::from_value(tool_input.clone()).map_err(ProviderError::MalformedVerdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Decision;

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
