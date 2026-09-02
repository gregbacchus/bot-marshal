//! The OpenAI Chat Completions API.
//!
//! Verified against OpenAI's published OpenAPI spec
//! (<https://raw.githubusercontent.com/openai/openai-openapi/master/openapi.yaml>) rather
//! than assumed, specifically because it differs from Anthropic's shape in a way that would
//! silently break parsing if guessed: `message.tool_calls[].function.arguments` is a
//! **JSON-encoded string**, not a nested object — the spec's own example renders it as
//! `"arguments": "{\n\"location\": \"Boston, MA\"\n}"`. It needs a second decode step that
//! Anthropic's native-object `input` does not.

use std::sync::Arc;

use crate::request::JudgeRequest;

use super::{
    JudgeVerdict, Provider, ProviderError, VERDICT_TOOL_NAME, connect_and_post_json,
    default_tls_config, json_post_request, user_content, verdict_parameters_schema,
};

const HOST: &str = "api.openai.com";

#[derive(Debug)]
pub struct OpenAiProvider {
    model: String,
    api_key: String,
    max_tokens: u32,
    tls_config: Arc<rustls::ClientConfig>,
}

impl OpenAiProvider {
    pub fn new(model: String, api_key: String, max_tokens: Option<u32>) -> Self {
        Self {
            model,
            api_key,
            max_tokens: max_tokens.unwrap_or(256),
            tls_config: default_tls_config(),
        }
    }

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
impl Provider for OpenAiProvider {
    async fn judge(
        &self,
        request: &JudgeRequest,
        prompt: &str,
    ) -> Result<JudgeVerdict, ProviderError> {
        let body = serde_json::json!({
            "model": self.model,
            "max_completion_tokens": self.max_tokens,
            "messages": [
                { "role": "system", "content": prompt },
                { "role": "user", "content": user_content(request) },
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": VERDICT_TOOL_NAME,
                    "description": "Report the policy decision for the request under review.",
                    "parameters": verdict_parameters_schema(),
                },
            }],
            "tool_choice": { "type": "function", "function": { "name": VERDICT_TOOL_NAME } },
        });

        let req = json_post_request(
            "https://api.openai.com/v1/chat/completions",
            HOST,
            &[("authorization", &format!("Bearer {}", self.api_key))],
            body,
        );

        let response = connect_and_post_json(HOST, &self.tls_config, req).await?;
        parse_verdict(response)
    }
}

/// Pull the forced function call's `arguments` out of a Chat Completions response.
///
/// `arguments` is a JSON string, not an object — this is the one place OpenAI's shape differs
/// from Anthropic's in a way that matters, and getting it wrong means treating a string like
/// `"{\"decision\":\"allow\", ...}"` as if it were already the object, which fails to
/// deserialise in a way that is easy to misdiagnose as "the model returned nonsense" rather
/// than "the response needs a second decode".
fn parse_verdict(response: serde_json::Value) -> Result<JudgeVerdict, ProviderError> {
    let arguments = response
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
        .and_then(|tc| tc.first())
        .and_then(|call| call.get("function"))
        .and_then(|f| f.get("arguments"))
        .and_then(|a| a.as_str())
        .ok_or(ProviderError::NoToolCall)?;

    serde_json::from_str(arguments).map_err(ProviderError::MalformedVerdict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Decision;

    /// Shaped exactly like the OpenAPI spec's own documented example response, arguments
    /// string included, so this test would have caught treating it as a nested object.
    #[test]
    fn parses_the_string_encoded_arguments() {
        let response = serde_json::json!({
            "id": "chatcmpl-abc123",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "verdict",
                            "arguments": "{\"decision\": \"deny\", \"reason\": \"writes a workflow file\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let v = parse_verdict(response).unwrap();
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.reason, "writes a workflow file");
    }

    #[test]
    fn a_response_with_no_tool_call_is_an_explicit_error() {
        let response = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "allow it" } }]
        });
        assert!(matches!(parse_verdict(response), Err(ProviderError::NoToolCall)));
    }

    #[test]
    fn malformed_json_inside_the_arguments_string_is_a_parse_error() {
        // The spec itself warns the model does not always generate valid JSON here.
        let response = serde_json::json!({
            "choices": [{ "message": { "tool_calls": [{
                "function": { "name": "verdict", "arguments": "{not valid json" }
            }] } }]
        });
        assert!(matches!(parse_verdict(response), Err(ProviderError::MalformedVerdict(_))));
    }

    #[test]
    fn an_unknown_decision_value_is_a_parse_error_not_a_silent_default() {
        let response = serde_json::json!({
            "choices": [{ "message": { "tool_calls": [{
                "function": { "name": "verdict", "arguments": "{\"decision\": \"maybe\", \"reason\": \"x\"}" }
            }] } }]
        });
        assert!(matches!(parse_verdict(response), Err(ProviderError::MalformedVerdict(_))));
    }

    #[test]
    fn from_env_reports_a_missing_key_by_name() {
        let err =
            OpenAiProvider::from_env("m".into(), "MARSHAL_TEST_DEFINITELY_ABSENT_KEY_2", None)
                .unwrap_err();
        assert!(
            matches!(err, ProviderError::MissingApiKey(k) if k == "MARSHAL_TEST_DEFINITELY_ABSENT_KEY_2")
        );
    }
}
