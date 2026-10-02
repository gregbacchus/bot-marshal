//! Request and response JSON translation between Chat Completions and Messages.

use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Openai,
    Anthropic,
    SystemOne,
}

impl From<marshal_config::LlmDialect> for Dialect {
    fn from(d: marshal_config::LlmDialect) -> Self {
        match d {
            marshal_config::LlmDialect::Openai => Self::Openai,
            marshal_config::LlmDialect::Anthropic => Self::Anthropic,
            marshal_config::LlmDialect::SystemOne => Self::SystemOne,
        }
    }
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::SystemOne => "system_one",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TranslateError {
    #[error("request body is not JSON")]
    NotJson,
    #[error("{0}")]
    Other(String),
}

pub fn translate_request(
    from: Dialect,
    to: Dialect,
    mut body: Value,
    mapped_model: &str,
) -> Result<Value, TranslateError> {
    if from == Dialect::SystemOne
        && (!body.get("state").is_some_and(|v| v.is_string() || v.is_object() || v.is_array())
            || body.get("questions").and_then(Value::as_object).is_none_or(|q| q.is_empty())
            || body.get("stream").and_then(Value::as_bool) == Some(true))
    {
        return Err(TranslateError::Other(
            "System One requires state and non-empty questions; streaming is not supported".into(),
        ));
    }
    if from == to {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".into(), json!(mapped_model));
        }
        return Ok(body);
    }
    match (from, to) {
        (Dialect::Openai, Dialect::Anthropic) => openai_request_to_anthropic(body, mapped_model),
        (Dialect::Anthropic, Dialect::Openai) => anthropic_request_to_openai(body, mapped_model),
        _ => Err(TranslateError::Other(
            "System One decision and chat dialects cannot be translated".into(),
        )),
    }
}

pub fn translate_response(
    from_origin: Dialect,
    to_client: Dialect,
    mut body: Value,
    client_model: &str,
) -> Result<Value, TranslateError> {
    body = map_error_shape(from_origin, to_client, body);
    if from_origin == to_client {
        rewrite_model_field(&mut body, client_model);
        return Ok(body);
    }
    let translated = match (from_origin, to_client) {
        (Dialect::Anthropic, Dialect::Openai) => anthropic_response_to_openai(body, client_model),
        (Dialect::Openai, Dialect::Anthropic) => openai_response_to_anthropic(body, client_model),
        _ => {
            return Err(TranslateError::Other(
                "System One decision and chat dialects cannot be translated".into(),
            ));
        }
    };
    Ok(translated)
}

fn rewrite_model_field(body: &mut Value, model: &str) {
    if let Some(obj) = body.as_object_mut()
        && obj.contains_key("model")
    {
        obj.insert("model".into(), json!(model));
    }
}

fn map_error_shape(from: Dialect, to: Dialect, body: Value) -> Value {
    if from == to {
        return body;
    }
    match (from, to) {
        (Dialect::Anthropic, Dialect::Openai) => {
            if body.get("type").and_then(|t| t.as_str()) == Some("error")
                || body.get("error").is_some()
            {
                let message = body
                    .pointer("/error/message")
                    .and_then(|v| v.as_str())
                    .or_else(|| body.get("message").and_then(|v| v.as_str()))
                    .unwrap_or("origin error")
                    .to_owned();
                let kind = body
                    .pointer("/error/type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("api_error")
                    .to_owned();
                return json!({ "error": { "message": message, "type": kind, "code": kind } });
            }
            body
        }
        (Dialect::Openai, Dialect::Anthropic) => {
            if let Some(err) = body.get("error") {
                let message = err.get("message").and_then(|v| v.as_str()).unwrap_or("origin error");
                let kind = err
                    .get("type")
                    .and_then(|v| v.as_str())
                    .or_else(|| err.get("code").and_then(|v| v.as_str()))
                    .unwrap_or("api_error");
                return json!({
                    "type": "error",
                    "error": { "type": kind, "message": message }
                });
            }
            body
        }
        _ => body,
    }
}

fn openai_request_to_anthropic(body: Value, model: &str) -> Result<Value, TranslateError> {
    let obj = body.as_object().ok_or(TranslateError::NotJson)?;
    let mut system_parts = Vec::new();
    let mut messages = Vec::new();
    if let Some(arr) = obj.get("messages").and_then(|v| v.as_array()) {
        for msg in arr {
            let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
            match role {
                "system" => {
                    if let Some(text) = message_text(msg) {
                        system_parts.push(text);
                    }
                }
                "user" | "assistant" => messages.push(openai_message_to_anthropic(msg, role)),
                "tool" => {
                    let id = msg.get("tool_call_id").and_then(|v| v.as_str()).unwrap_or("");
                    let text = message_text(msg).unwrap_or_default();
                    messages.push(json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": id,
                            "content": text,
                        }]
                    }));
                }
                _ => messages.push(openai_message_to_anthropic(msg, "user")),
            }
        }
    }

    let mut out = json!({
        "model": model,
        "messages": messages,
        "max_tokens": obj.get("max_tokens")
            .or_else(|| obj.get("max_completion_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(4096),
    });
    let out_obj = out.as_object_mut().expect("object");
    if !system_parts.is_empty() {
        out_obj.insert("system".into(), json!(system_parts.join("\n\n")));
    }
    if let Some(t) = obj.get("temperature") {
        out_obj.insert("temperature".into(), t.clone());
    }
    if let Some(stop) = obj.get("stop") {
        let seq = match stop {
            Value::String(s) => json!([s]),
            other => other.clone(),
        };
        out_obj.insert("stop_sequences".into(), seq);
    }
    if let Some(stream) = obj.get("stream") {
        out_obj.insert("stream".into(), stream.clone());
    }
    if let Some(tools) = obj.get("tools").and_then(|v| v.as_array()) {
        let converted: Vec<Value> = tools.iter().map(openai_tool_to_anthropic).collect();
        out_obj.insert("tools".into(), json!(converted));
    }
    if let Some(choice) = obj.get("tool_choice") {
        out_obj.insert("tool_choice".into(), openai_tool_choice_to_anthropic(choice));
    }
    Ok(out)
}

fn openai_message_to_anthropic(msg: &Value, role: &str) -> Value {
    let mut content_blocks = Vec::new();
    if let Some(text) = message_text(msg)
        && !text.is_empty()
    {
        content_blocks.push(json!({ "type": "text", "text": text }));
    }
    if let Some(calls) = msg.get("tool_calls").and_then(|v| v.as_array()) {
        for call in calls {
            let id = call.get("id").and_then(|v| v.as_str()).unwrap_or("toolu_unknown");
            let name =
                call.pointer("/function/name").and_then(|v| v.as_str()).unwrap_or("function");
            let args = call.pointer("/function/arguments").and_then(|v| v.as_str()).unwrap_or("{}");
            let input: Value = serde_json::from_str(args).unwrap_or_else(|_| json!({}));
            content_blocks.push(json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }
    }
    let content = if content_blocks.is_empty() {
        json!("")
    } else if content_blocks.len() == 1 && content_blocks[0]["type"] == "text" {
        content_blocks[0]["text"].clone()
    } else {
        json!(content_blocks)
    };
    json!({ "role": role, "content": content })
}

fn openai_tool_to_anthropic(tool: &Value) -> Value {
    let func = tool.get("function").unwrap_or(tool);
    json!({
        "name": func.get("name").cloned().unwrap_or(json!("function")),
        "description": func.get("description").cloned().unwrap_or(json!("")),
        "input_schema": func.get("parameters").cloned().unwrap_or(json!({"type":"object","properties":{}})),
    })
}

fn openai_tool_choice_to_anthropic(choice: &Value) -> Value {
    match choice.as_str() {
        Some("none") => json!({ "type": "none" }),
        Some("auto") => json!({ "type": "auto" }),
        Some("required") => json!({ "type": "any" }),
        _ => {
            if let Some(name) = choice.pointer("/function/name").and_then(|v| v.as_str()) {
                json!({ "type": "tool", "name": name })
            } else {
                json!({ "type": "auto" })
            }
        }
    }
}

fn anthropic_request_to_openai(body: Value, model: &str) -> Result<Value, TranslateError> {
    let obj = body.as_object().ok_or(TranslateError::NotJson)?;
    let mut messages = Vec::new();
    if let Some(system) = obj.get("system") {
        let text = match system {
            Value::String(s) => s.clone(),
            Value::Array(blocks) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
            _ => String::new(),
        };
        if !text.is_empty() {
            messages.push(json!({ "role": "system", "content": text }));
        }
    }
    if let Some(arr) = obj.get("messages").and_then(|v| v.as_array()) {
        for msg in arr {
            messages.extend(anthropic_message_to_openai(msg));
        }
    }
    let mut out = json!({
        "model": model,
        "messages": messages,
    });
    let out_obj = out.as_object_mut().expect("object");
    if let Some(max) = obj.get("max_tokens") {
        out_obj.insert("max_tokens".into(), max.clone());
    }
    if let Some(t) = obj.get("temperature") {
        out_obj.insert("temperature".into(), t.clone());
    }
    if let Some(stop) = obj.get("stop_sequences") {
        out_obj.insert("stop".into(), stop.clone());
    }
    if let Some(stream) = obj.get("stream") {
        out_obj.insert("stream".into(), stream.clone());
    }
    if let Some(tools) = obj.get("tools").and_then(|v| v.as_array()) {
        let converted: Vec<Value> = tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.get("name").cloned().unwrap_or(json!("function")),
                        "description": t.get("description").cloned().unwrap_or(json!("")),
                        "parameters": t.get("input_schema").cloned().unwrap_or(json!({"type":"object"})),
                    }
                })
            })
            .collect();
        out_obj.insert("tools".into(), json!(converted));
    }
    if let Some(choice) = obj.get("tool_choice") {
        out_obj.insert("tool_choice".into(), anthropic_tool_choice_to_openai(choice));
    }
    Ok(out)
}

fn anthropic_message_to_openai(msg: &Value) -> Vec<Value> {
    let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("user");
    let mut out = Vec::new();
    match msg.get("content") {
        Some(Value::String(s)) => {
            out.push(json!({ "role": role, "content": s }));
        }
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            let mut tool_calls = Vec::new();
            for block in blocks {
                match block.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                            texts.push(t.to_owned());
                        }
                    }
                    Some("tool_use") => {
                        let args = block.get("input").cloned().unwrap_or(json!({}));
                        tool_calls.push(json!({
                            "id": block.get("id").cloned().unwrap_or(json!("call_unknown")),
                            "type": "function",
                            "function": {
                                "name": block.get("name").cloned().unwrap_or(json!("function")),
                                "arguments": serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
                            }
                        }));
                    }
                    Some("tool_result") => {
                        out.push(json!({
                            "role": "tool",
                            "tool_call_id": block.get("tool_use_id").cloned().unwrap_or(json!("")),
                            "content": block.get("content").map(content_as_text).unwrap_or_else(|| "".into()),
                        }));
                    }
                    _ => {}
                }
            }
            if !texts.is_empty() || !tool_calls.is_empty() {
                let mut m = json!({ "role": role, "content": texts.join("\n") });
                if !tool_calls.is_empty() {
                    m["tool_calls"] = json!(tool_calls);
                }
                out.insert(0, m);
            }
        }
        _ => out.push(json!({ "role": role, "content": "" })),
    }
    out
}

fn anthropic_tool_choice_to_openai(choice: &Value) -> Value {
    match choice.get("type").and_then(|v| v.as_str()) {
        Some("none") => json!("none"),
        Some("any") => json!("required"),
        Some("tool") => json!({
            "type": "function",
            "function": { "name": choice.get("name").cloned().unwrap_or(json!("function")) }
        }),
        _ => json!("auto"),
    }
}

fn anthropic_response_to_openai(body: Value, model: &str) -> Value {
    if body.get("error").is_some() || body.get("type").and_then(|t| t.as_str()) == Some("error") {
        return body;
    }
    let id = body.get("id").cloned().unwrap_or(json!("chatcmpl-marshal"));
    let content = body.get("content").cloned().unwrap_or(json!([]));
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    if let Some(blocks) = content.as_array() {
        for block in blocks {
            match block.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(|v| v.as_str()) {
                        text.push_str(t);
                    }
                }
                Some("tool_use") => {
                    let args = block.get("input").cloned().unwrap_or(json!({}));
                    tool_calls.push(json!({
                        "id": block.get("id").cloned().unwrap_or(json!("call_unknown")),
                        "type": "function",
                        "function": {
                            "name": block.get("name").cloned().unwrap_or(json!("function")),
                            "arguments": serde_json::to_string(&args).unwrap_or_else(|_| "{}".into()),
                        }
                    }));
                }
                _ => {}
            }
        }
    }
    let stop = body.pointer("/stop_reason").and_then(|v| v.as_str()).unwrap_or("end_turn");
    let finish = match stop {
        "tool_use" => "tool_calls",
        "max_tokens" => "length",
        _ => "stop",
    };
    let mut message = json!({ "role": "assistant", "content": if text.is_empty() { Value::Null } else { json!(text) } });
    if !tool_calls.is_empty() {
        message["tool_calls"] = json!(tool_calls);
        if text.is_empty() {
            message["content"] = Value::Null;
        }
    }
    json!({
        "id": id,
        "object": "chat.completion",
        "model": model,
        "choices": [{ "index": 0, "message": message, "finish_reason": finish }],
        "usage": {
            "prompt_tokens": body.pointer("/usage/input_tokens").cloned().unwrap_or(json!(0)),
            "completion_tokens": body.pointer("/usage/output_tokens").cloned().unwrap_or(json!(0)),
            "total_tokens": json!(
                body.pointer("/usage/input_tokens").and_then(|v| v.as_u64()).unwrap_or(0)
                    + body.pointer("/usage/output_tokens").and_then(|v| v.as_u64()).unwrap_or(0)
            ),
        }
    })
}

fn openai_response_to_anthropic(body: Value, model: &str) -> Value {
    if body.get("error").is_some() {
        return body;
    }
    let message = body.pointer("/choices/0/message").cloned().unwrap_or(json!({}));
    let mut content = Vec::new();
    if let Some(text) = message.get("content").and_then(|v| v.as_str())
        && !text.is_empty()
    {
        content.push(json!({ "type": "text", "text": text }));
    }
    if let Some(calls) = message.get("tool_calls").and_then(|v| v.as_array()) {
        for call in calls {
            let args = call.pointer("/function/arguments").and_then(|v| v.as_str()).unwrap_or("{}");
            let input: Value = serde_json::from_str(args).unwrap_or_else(|_| json!({}));
            content.push(json!({
                "type": "tool_use",
                "id": call.get("id").cloned().unwrap_or(json!("toolu_unknown")),
                "name": call.pointer("/function/name").cloned().unwrap_or(json!("function")),
                "input": input,
            }));
        }
    }
    let finish =
        body.pointer("/choices/0/finish_reason").and_then(|v| v.as_str()).unwrap_or("stop");
    let stop_reason = match finish {
        "tool_calls" => "tool_use",
        "length" => "max_tokens",
        _ => "end_turn",
    };
    json!({
        "id": body.get("id").cloned().unwrap_or(json!("msg_marshal")),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": body.pointer("/usage/prompt_tokens").cloned().unwrap_or(json!(0)),
            "output_tokens": body.pointer("/usage/completion_tokens").cloned().unwrap_or(json!(0)),
        }
    })
}

fn message_text(msg: &Value) -> Option<String> {
    match msg.get("content") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(parts)) => {
            let t: Vec<&str> = parts
                .iter()
                .filter_map(|p| {
                    if p.get("type").and_then(|t| t.as_str()) == Some("text") {
                        p.get("text").and_then(|v| v.as_str())
                    } else {
                        p.as_str()
                    }
                })
                .collect();
            Some(t.join("\n"))
        }
        _ => None,
    }
}

fn content_as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_system_and_user_become_anthropic_system_field() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "hi"}
            ],
            "max_tokens": 32
        });
        let out = translate_request(Dialect::Openai, Dialect::Anthropic, body, "claude-x").unwrap();
        assert_eq!(out["model"], "claude-x");
        assert_eq!(out["system"], "be brief");
        assert_eq!(out["messages"][0]["role"], "user");
        assert_eq!(out["messages"][0]["content"], "hi");
        assert_eq!(out["max_tokens"], 32);
    }

    #[test]
    fn anthropic_system_becomes_openai_system_message() {
        let body = json!({
            "model": "claude-x",
            "system": "be brief",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let out = translate_request(Dialect::Anthropic, Dialect::Openai, body, "gpt-4o").unwrap();
        assert_eq!(out["model"], "gpt-4o");
        assert_eq!(out["messages"][0]["role"], "system");
        assert_eq!(out["messages"][1]["content"], "hi");
    }

    #[test]
    fn openai_tool_call_arguments_are_a_json_string() {
        let body = json!({
            "id": "msg_1",
            "type": "message",
            "content": [{
                "type": "tool_use",
                "id": "toolu_1",
                "name": "lookup",
                "input": {"city": "Boston"}
            }],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 1, "output_tokens": 2}
        });
        let out = translate_response(Dialect::Anthropic, Dialect::Openai, body, "gpt-4o").unwrap();
        let args = out["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let parsed: Value = serde_json::from_str(args).unwrap();
        assert_eq!(parsed["city"], "Boston");
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(out["model"], "gpt-4o");
    }

    #[test]
    fn same_dialect_only_rewrites_the_model() {
        let body = json!({"model": "gpt-4o", "messages": []});
        let out =
            translate_request(Dialect::Openai, Dialect::Openai, body, "openai/gpt-4o").unwrap();
        assert_eq!(out["model"], "openai/gpt-4o");
        assert_eq!(out["messages"], json!([]));
    }
}
