//! Model-table routing and the request/response transform pair that applies it.

use bytes::Bytes;
use marshal_config::{LlmDialect, LlmListen, LlmRouterConfig, LlmUnmapped};
use marshal_core::{
    Authority, BodyHandle, BodyRequirement, Error, LlmRoute, RequestContext, RequestResponder,
    RequestTransform, ResponseParts, ResponseTransform, Result, SseRewriter, SynthesizedResponse,
};
use serde_json::{Value, json};

use crate::sse::DialectSse;
use crate::translate::{Dialect, translate_request, translate_response};

#[derive(Debug)]
pub struct LlmRouter {
    config: LlmRouterConfig,
}

impl LlmRouter {
    pub fn new(config: LlmRouterConfig) -> Self {
        Self { config }
    }

    fn host_matches(left: &str, right: &str) -> bool {
        left.trim_end_matches('.').eq_ignore_ascii_case(right.trim_end_matches('.'))
    }

    fn listen_for<'a>(&'a self, host: &str, path: &str) -> Option<&'a LlmListen> {
        self.config.listen.iter().find(|listen| {
            listen.hosts.iter().any(|candidate| Self::host_matches(candidate, host))
                && if listen.paths.is_empty() {
                    path == listen.dialect.default_chat_path()
                } else {
                    listen.paths.iter().any(|candidate| candidate == path)
                }
        })
    }

    fn listens_on(&self, host: &str) -> bool {
        self.config
            .listen
            .iter()
            .any(|listen| listen.hosts.iter().any(|h| Self::host_matches(h, host)))
    }

    fn dialect(value: &str) -> Result<Dialect> {
        match value {
            "openai" => Ok(Dialect::Openai),
            "anthropic" => Ok(Dialect::Anthropic),
            "system_one" => Ok(Dialect::SystemOne),
            other => Err(Error::Other(format!("unknown LLM dialect `{other}` in route state"))),
        }
    }

    fn replace_json_body(body: &mut BodyHandle, value: &Value) -> Result<usize> {
        let encoded = serde_json::to_vec(value)
            .map_err(|e| Error::Other(format!("could not encode routed LLM JSON: {e}")))?;
        let len = encoded.len();
        *body = BodyHandle::Buffered(Bytes::from(encoded));
        Ok(len)
    }
}

#[async_trait::async_trait]
impl RequestTransform for LlmRouter {
    fn name(&self) -> &str {
        "llm_router"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

    fn body_requirement_for(&self, authority: &Authority, uri: &http::Uri) -> BodyRequirement {
        if self.listen_for(&authority.host, uri.path()).is_none() {
            return BodyRequirement::Streaming;
        }
        BodyRequirement::Buffered { cap: self.config.max_request_bytes }
    }

    fn defers_connect(&self, host: &str) -> bool {
        self.listens_on(host)
            && self
                .config
                .models
                .values()
                .any(|target| !Self::host_matches(&target.host, host) || target.port != 443)
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        let Some(listen) = self.listen_for(&cx.authority.host, cx.uri.path()) else {
            return Ok(());
        };
        let bytes = match &cx.body {
            BodyHandle::Buffered(bytes) => bytes,
            BodyHandle::OverLimit { .. } => {
                return Err(Error::BodyTooLarge { cap: self.config.max_request_bytes });
            }
            BodyHandle::Empty | BodyHandle::Streaming => {
                return Err(Error::Other(
                    "LLM router requires a buffered JSON request body".into(),
                ));
            }
        };
        let body: Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::Other(format!("LLM request body is not valid JSON: {e}")))?;
        let from_model = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Other("LLM request body has no string `model` field".into()))?
            .to_owned();
        let Some(target) = self.config.models.get(&from_model) else {
            return match self.config.unmapped {
                LlmUnmapped::Pass => Ok(()),
                LlmUnmapped::Deny => Err(Error::Other(format!(
                    "LLM model `{from_model}` is not present in the router model map"
                ))),
            };
        };

        let client_dialect = Dialect::from(listen.dialect);
        let origin_dialect = Dialect::from(target.dialect);
        let translated = translate_request(client_dialect, origin_dialect, body, &target.model)
            .map_err(|e| Error::Other(format!("could not translate LLM request: {e}")))?;
        let len = Self::replace_json_body(&mut cx.body, &translated)?;

        // These belong to the client-facing endpoint. They must not cross to a mapped origin;
        // an origin credential, if configured, is injected by the later secret transform.
        for name in [
            "authorization",
            "x-api-key",
            "content-encoding",
            "anthropic-version",
            "anthropic-beta",
            "openai-organization",
            "openai-project",
        ] {
            cx.headers.remove(name);
        }
        cx.headers
            .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
        cx.headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
        if target.dialect == LlmDialect::Anthropic {
            cx.headers.insert("anthropic-version", http::HeaderValue::from_static("2023-06-01"));
        }

        let path = target.path.as_deref().unwrap_or_else(|| target.dialect.default_chat_path());
        cx.uri = path
            .parse()
            .map_err(|e| Error::Other(format!("invalid mapped LLM path `{path}`: {e}")))?;
        cx.authority = Authority { host: target.host.clone(), port: target.port };
        cx.evidence.record("llm_router.from_model", from_model.clone());
        cx.evidence.record("llm_router.to_model", target.model.clone());
        cx.evidence.record("llm_router.to_host", target.host.clone());
        cx.evidence.record("llm_router.to_dialect", target.dialect.as_str());
        cx.llm_route = Some(LlmRoute {
            client_dialect: listen.dialect.as_str().into(),
            origin_dialect: target.dialect.as_str().into(),
            from_model,
            to_model: target.model.clone(),
            to_host: target.host.clone(),
        });
        Ok(())
    }
}

#[async_trait::async_trait]
impl ResponseTransform for LlmRouter {
    fn name(&self) -> &str {
        "llm_router"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

    fn body_requirement_for(&self, cx: &RequestContext) -> BodyRequirement {
        if cx.llm_route.is_none() {
            return BodyRequirement::Streaming;
        }
        BodyRequirement::Buffered { cap: self.config.max_response_bytes }
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    async fn apply(&self, cx: &RequestContext, response: &mut ResponseParts) -> Result<()> {
        let Some(route) = &cx.llm_route else { return Ok(()) };
        let bytes = match &response.body {
            BodyHandle::Buffered(bytes) => bytes,
            BodyHandle::OverLimit { .. } => {
                return Err(Error::BodyTooLarge { cap: self.config.max_response_bytes });
            }
            BodyHandle::Empty | BodyHandle::Streaming => return Ok(()),
        };
        if bytes.is_empty() {
            return Ok(());
        }
        let body: Value = serde_json::from_slice(bytes)
            .map_err(|e| Error::Other(format!("LLM response body is not valid JSON: {e}")))?;
        let translated = translate_response(
            Self::dialect(&route.origin_dialect)?,
            Self::dialect(&route.client_dialect)?,
            body,
            &route.from_model,
        )
        .map_err(|e| Error::Other(format!("could not translate LLM response: {e}")))?;
        let len = Self::replace_json_body(&mut response.body, &translated)?;
        response.headers.remove(http::header::CONTENT_ENCODING);
        response
            .headers
            .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/json"));
        response.headers.insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
        Ok(())
    }

    fn stream_session(&self, cx: &RequestContext) -> Option<Box<dyn SseRewriter>> {
        let route = cx.llm_route.as_ref()?;
        if route.client_dialect == "system_one" {
            return None;
        }
        Some(Box::new(DialectSse::new(
            Self::dialect(&route.origin_dialect).ok()?,
            Self::dialect(&route.client_dialect).ok()?,
            &route.from_model,
        )))
    }
}

#[async_trait::async_trait]
impl RequestResponder for LlmRouter {
    fn name(&self) -> &str {
        "llm_router"
    }

    async fn respond(&self, cx: &mut RequestContext) -> Result<Option<SynthesizedResponse>> {
        if cx.method != http::Method::GET || cx.uri.path() != "/v1/models" {
            return Ok(None);
        }
        let openai_listen = self.config.listen.iter().any(|listen| {
            listen.dialect == LlmDialect::Openai
                && listen.hosts.iter().any(|host| Self::host_matches(host, &cx.authority.host))
        });
        if !openai_listen {
            return Ok(None);
        }
        let data: Vec<Value> = self
            .config
            .models
            .iter()
            .filter(|(_, target)| target.dialect != LlmDialect::SystemOne)
            .map(|(model, _)| json!({"id": model, "object": "model", "owned_by": "bot-marshal"}))
            .collect();
        let body = Bytes::from(
            serde_json::to_vec(&json!({"object": "list", "data": data}))
                .map_err(|e| Error::Other(format!("could not encode LLM model catalog: {e}")))?,
        );
        Ok(Some(SynthesizedResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body,
            code: "model_catalog".into(),
            message: "served the configured client-facing LLM model catalog".into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use marshal_config::{LlmDialect, LlmListen, LlmModelTarget, LlmRouterConfig, LlmUnmapped};
    use marshal_core::{
        Authority, BodyHandle, Evidence, Identity, IngressMode, Phase, RequestContext,
        RequestResponder, RequestTransform, ResponseParts, ResponseTransform,
    };
    use serde_json::{Value, json};

    use super::LlmRouter;

    fn router(unmapped: LlmUnmapped) -> LlmRouter {
        LlmRouter::new(LlmRouterConfig {
            listen: vec![
                LlmListen {
                    dialect: LlmDialect::Openai,
                    hosts: vec!["api.openai.test".into()],
                    paths: Vec::new(),
                },
                LlmListen {
                    dialect: LlmDialect::Anthropic,
                    hosts: vec!["api.anthropic.test".into()],
                    paths: Vec::new(),
                },
            ],
            models: BTreeMap::from([
                (
                    "fast".into(),
                    LlmModelTarget {
                        model: "gpt-origin".into(),
                        dialect: LlmDialect::Openai,
                        host: "openai.origin.test".into(),
                        path: None,
                        port: 8443,
                    },
                ),
                (
                    "smart".into(),
                    LlmModelTarget {
                        model: "claude-origin".into(),
                        dialect: LlmDialect::Anthropic,
                        host: "anthropic.origin.test".into(),
                        path: None,
                        port: 443,
                    },
                ),
            ]),
            unmapped,
            max_request_bytes: 1024,
            max_response_bytes: 2048,
        })
    }

    fn request(host: &str, path: &str, body: Value) -> RequestContext {
        let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::AUTHORIZATION, "Bearer client-secret".parse().unwrap());
        headers.insert("x-api-key", "client-secret".parse().unwrap());
        headers.insert(http::header::CONTENT_ENCODING, "identity".parse().unwrap());
        headers.insert(http::header::CONTENT_LENGTH, bytes.len().into());
        RequestContext {
            identity: Identity::new("test"),
            profile: Arc::from("test"),
            ingress: IngressMode::Explicit,
            phase: Phase::Request,
            client_addr: "127.0.0.1:1234".parse().unwrap(),
            authority: Authority { host: host.into(), port: 443 },
            method: http::Method::POST,
            uri: path.parse().unwrap(),
            headers,
            body: BodyHandle::Buffered(bytes),
            evidence: Evidence::new(),
            llm_route: None,
        }
    }

    fn json_body(body: &BodyHandle) -> Value {
        serde_json::from_slice(body.as_bytes().expect("buffered body")).unwrap()
    }

    #[tokio::test]
    async fn same_dialect_mapping_rewrites_origin_model_path_and_sensitive_headers() {
        let router = router(LlmUnmapped::Deny);
        let mut cx = request(
            "api.openai.test",
            "/v1/chat/completions",
            json!({"model":"fast","messages":[{"role":"user","content":"hi"}]}),
        );

        RequestTransform::apply(&router, &mut cx).await.unwrap();

        assert_eq!(cx.authority, Authority { host: "openai.origin.test".into(), port: 8443 });
        assert_eq!(cx.uri.path(), "/v1/chat/completions");
        assert_eq!(json_body(&cx.body)["model"], "gpt-origin");
        assert!(!cx.headers.contains_key(http::header::AUTHORIZATION));
        assert!(!cx.headers.contains_key("x-api-key"));
        assert!(!cx.headers.contains_key(http::header::CONTENT_ENCODING));
        assert_eq!(cx.llm_route.as_ref().unwrap().from_model, "fast");
        assert_eq!(cx.evidence.fact("llm_router.to_host").unwrap(), "openai.origin.test");
    }

    #[tokio::test]
    async fn openai_request_and_anthropic_response_translate_across_dialects() {
        let router = router(LlmUnmapped::Deny);
        let mut cx = request(
            "api.openai.test",
            "/v1/chat/completions",
            json!({
                "model":"smart",
                "messages":[
                    {"role":"system","content":"be brief"},
                    {"role":"user","content":"hi"}
                ],
                "max_tokens":32
            }),
        );

        RequestTransform::apply(&router, &mut cx).await.unwrap();
        assert_eq!(cx.authority.host, "anthropic.origin.test");
        assert_eq!(cx.uri.path(), "/v1/messages");
        assert_eq!(json_body(&cx.body)["system"], "be brief");
        assert!(cx.headers.contains_key("anthropic-version"));

        let response = json!({
            "id":"msg_1", "type":"message", "role":"assistant",
            "model":"claude-origin", "content":[{"type":"text","text":"hello"}],
            "stop_reason":"end_turn", "usage":{"input_tokens":2,"output_tokens":1}
        });
        let bytes = Bytes::from(serde_json::to_vec(&response).unwrap());
        let mut resp = ResponseParts {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([
                (http::header::CONTENT_TYPE, "application/json".parse().unwrap()),
                (http::header::CONTENT_LENGTH, bytes.len().into()),
            ]),
            body: BodyHandle::Buffered(bytes),
        };
        ResponseTransform::apply(&router, &cx, &mut resp).await.unwrap();
        let translated = json_body(&resp.body);
        assert_eq!(translated["object"], "chat.completion");
        assert_eq!(translated["model"], "smart");
        assert_eq!(translated["choices"][0]["message"]["content"], "hello");
    }

    #[tokio::test]
    async fn unmapped_models_fail_closed_or_pass_unchanged_as_configured() {
        let mut denied = request(
            "api.openai.test",
            "/v1/chat/completions",
            json!({"model":"unknown","messages":[]}),
        );
        let err =
            RequestTransform::apply(&router(LlmUnmapped::Deny), &mut denied).await.unwrap_err();
        assert!(err.to_string().contains("unknown"), "{err}");

        let mut passed = request(
            "api.openai.test",
            "/v1/chat/completions",
            json!({"model":"unknown","messages":[]}),
        );
        RequestTransform::apply(&router(LlmUnmapped::Pass), &mut passed).await.unwrap();
        assert_eq!(passed.authority.host, "api.openai.test");
        assert_eq!(json_body(&passed.body)["model"], "unknown");
        assert!(passed.llm_route.is_none());
    }

    #[tokio::test]
    async fn non_chat_paths_are_out_of_scope() {
        let router = router(LlmUnmapped::Deny);
        let mut cx = request("api.openai.test", "/v1/embeddings", json!({"model":"unknown"}));
        RequestTransform::apply(&router, &mut cx).await.unwrap();
        assert_eq!(cx.authority.host, "api.openai.test");
        assert!(cx.llm_route.is_none());
    }

    #[tokio::test]
    async fn openai_model_catalog_lists_client_facing_model_names() {
        let router = router(LlmUnmapped::Deny);
        let mut cx = request("api.openai.test", "/v1/models", json!({}));
        cx.method = http::Method::GET;
        cx.body = BodyHandle::Empty;

        let response = router.respond(&mut cx).await.unwrap().expect("catalog response");
        assert_eq!(response.status, 200);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        let ids: Vec<_> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|model| model["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["fast", "smart"]);
    }

    #[tokio::test]
    async fn only_listen_hosts_defer_connect_and_routed_streams_get_a_session() {
        let router = router(LlmUnmapped::Deny);
        assert!(router.defers_connect("API.OPENAI.TEST"));
        assert!(!router.defers_connect("example.com"));

        let listen = Authority { host: "api.openai.test".into(), port: 443 };
        assert_eq!(
            RequestTransform::body_requirement_for(
                &router,
                &listen,
                &"/v1/chat/completions".parse().unwrap()
            ),
            marshal_core::BodyRequirement::Buffered { cap: 1024 }
        );
        assert_eq!(
            RequestTransform::body_requirement_for(
                &router,
                &listen,
                &"/v1/embeddings".parse().unwrap()
            ),
            marshal_core::BodyRequirement::Streaming
        );

        let mut cx = request(
            "api.openai.test",
            "/v1/chat/completions",
            json!({"model":"smart","messages":[]}),
        );
        RequestTransform::apply(&router, &mut cx).await.unwrap();
        assert_eq!(
            ResponseTransform::body_requirement_for(&router, &cx),
            marshal_core::BodyRequirement::Buffered { cap: 2048 }
        );
        assert!(router.stream_session(&cx).is_some());

        let unrelated = request("example.com", "/", json!({}));
        assert_eq!(
            ResponseTransform::body_requirement_for(&router, &unrelated),
            marshal_core::BodyRequirement::Streaming
        );
    }
    #[tokio::test]
    async fn native_decision_routing_preserves_questions_and_strips_client_credentials() {
        let config = serde_json::from_value(json!({
            "listen": [{"dialect": "system_one", "hosts": ["decisions.test"]}],
            "models": {"quick": {"model": "typesafe/jev-1.13", "dialect": "system_one", "host": "decisionapi.net"}}
        })).unwrap();
        let router = LlmRouter::new(config);
        let questions = json!({"route": {"type": "choice", "instructions": "Pick a route", "criteria": {"fast": "Simple", "slow": "Complex"}}});
        let state = json!({"task": "test", "nested": ["context"]});
        let mut cx = request(
            "decisions.test",
            "/v1/systemone",
            json!({"model": "quick", "state": state, "questions": questions}),
        );
        RequestTransform::apply(&router, &mut cx).await.unwrap();
        assert_eq!(cx.authority.host, "decisionapi.net");
        assert_eq!(cx.uri.path(), "/v1/systemone");
        assert!(!cx.headers.contains_key("authorization"));
        assert!(!cx.headers.contains_key("x-api-key"));
        let body = json_body(&cx.body);
        assert_eq!(body["model"], "typesafe/jev-1.13");
        assert_eq!(body["state"], state);
        assert_eq!(body["questions"], questions);
        let answers = json!({"route": {"type": "choice", "choice": "fast", "confidence": 0.9, "probabilities": {"fast": 0.95, "slow": 0.05}}});
        let mut response = ResponseParts { status: http::StatusCode::OK, headers: http::HeaderMap::new(), body: BodyHandle::Buffered(Bytes::from(serde_json::to_vec(&json!({"model": "typesafe/jev-1.13", "answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0}})).unwrap())) };
        ResponseTransform::apply(&router, &cx, &mut response).await.unwrap();
        let output = json_body(&response.body);
        assert_eq!(output["model"], "quick");
        assert_eq!(output["answers"], answers);
        assert!(ResponseTransform::stream_session(&router, &cx).is_none());
    }
    #[tokio::test]
    async fn decision_routes_refuse_chat_conversion_invalid_input_and_streaming() {
        let config: LlmRouterConfig = serde_json::from_value(json!({
            "listen": [{"dialect": "system_one", "hosts": ["decisions.test"]}],
            "models": {"quick": {"model": "jev-latest", "dialect": "system_one", "host": "api.typesafe.ai"}, "chat": {"model": "chat", "dialect": "openai", "host": "api.openai.com"}}
        })).unwrap();
        let router = LlmRouter::new(config);
        for body in [
            json!({"model":"quick","state":"x","questions":{}}),
            json!({"model":"quick","state":"x","questions":{"x":{}},"stream":true}),
            json!({"model":"chat","state":"x","questions":{"x":{}}}),
        ] {
            let mut cx = request("decisions.test", "/v1/systemone", body);
            assert!(RequestTransform::apply(&router, &mut cx).await.is_err());
            assert_eq!(cx.authority.host, "decisions.test");
            assert!(cx.llm_route.is_none());
        }
        let ordinary = request("decisions.test", "/other", json!({}));
        assert_eq!(
            RequestTransform::body_requirement_for(&router, &ordinary.authority, &ordinary.uri),
            marshal_core::BodyRequirement::Streaming
        );
    }
}
