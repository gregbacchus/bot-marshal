//! Stateful SSE translation between Chat Completions chunks and Anthropic events.

use marshal_core::SseRewriter;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

use crate::translate::Dialect;

pub struct DialectSse {
    from_origin: Dialect,
    to_client: Dialect,
    client_model: String,
    message_id: String,
    started: bool,
    text_started: bool,
    text_block_index: Option<i64>,
    next_anthropic_block_index: i64,
    openai_to_anthropic_tool: BTreeMap<i64, i64>,
    open_anthropic_blocks: BTreeSet<i64>,
    anthropic_to_openai_tool: BTreeMap<i64, i64>,
    next_openai_tool_index: i64,
}

impl DialectSse {
    pub fn new(from_origin: Dialect, to_client: Dialect, client_model: &str) -> Self {
        Self {
            from_origin,
            to_client,
            client_model: client_model.to_owned(),
            message_id: "chatcmpl-marshal".into(),
            started: false,
            text_started: false,
            text_block_index: None,
            next_anthropic_block_index: 0,
            openai_to_anthropic_tool: BTreeMap::new(),
            open_anthropic_blocks: BTreeSet::new(),
            anthropic_to_openai_tool: BTreeMap::new(),
            next_openai_tool_index: 0,
        }
    }
}

impl SseRewriter for DialectSse {
    fn rewrite(&mut self, chunk: &str) -> String {
        if self.from_origin == self.to_client {
            return rewrite_model_in_sse(chunk, &self.client_model);
        }
        match (self.from_origin, self.to_client) {
            (Dialect::Anthropic, Dialect::Openai) => self.anthropic_chunk_to_openai(chunk),
            (Dialect::Openai, Dialect::Anthropic) => self.openai_chunk_to_anthropic(chunk),
            _ => chunk.to_owned(),
        }
    }
}

fn rewrite_model_in_sse(chunk: &str, model: &str) -> String {
    let mut out = String::new();
    for event in chunk.split("\n\n") {
        if event.trim().is_empty() {
            continue;
        }
        let rewritten = rewrite_one_data_event(event, model);
        out.push_str(&rewritten);
        if !rewritten.ends_with("\n\n") {
            out.push_str("\n\n");
        }
    }
    out
}

fn rewrite_one_data_event(event: &str, model: &str) -> String {
    let mut lines = Vec::new();
    for line in event.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if rest.trim() == "[DONE]" {
                lines.push(line.to_owned());
                continue;
            }
            if let Ok(mut v) = serde_json::from_str::<Value>(rest) {
                if let Some(obj) = v.as_object_mut()
                    && obj.contains_key("model")
                {
                    obj.insert("model".into(), json!(model));
                }
                lines.push(format!("data: {v}"));
                continue;
            }
        }
        lines.push(line.to_owned());
    }
    lines.join("\n") + "\n\n"
}

impl DialectSse {
    fn anthropic_chunk_to_openai(&mut self, chunk: &str) -> String {
        let mut out = String::new();
        for raw in chunk.split("\n\n") {
            if raw.trim().is_empty() {
                continue;
            }
            let (event_name, data) = parse_sse_event(raw);
            let Some(data) = data else { continue };
            if data.trim().is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            match event_name.as_deref() {
                Some("message_start") => {
                    if let Some(id) = v.pointer("/message/id").and_then(|x| x.as_str()) {
                        self.message_id = id.to_owned();
                    }
                    self.started = true;
                    out.push_str(&self.openai_data(json!({
                        "id": self.message_id,
                        "object": "chat.completion.chunk",
                        "model": self.client_model,
                        "choices": [{ "index": 0, "delta": { "role": "assistant" }, "finish_reason": Value::Null }]
                    })));
                }
                Some("content_block_start") => {
                    if v.pointer("/content_block/type").and_then(|t| t.as_str()) == Some("tool_use")
                    {
                        let id = v.pointer("/content_block/id").cloned().unwrap_or(json!("call_x"));
                        let name =
                            v.pointer("/content_block/name").cloned().unwrap_or(json!("function"));
                        let block_idx = v.get("index").and_then(|i| i.as_i64()).unwrap_or(0);
                        let idx =
                            *self.anthropic_to_openai_tool.entry(block_idx).or_insert_with(|| {
                                let idx = self.next_openai_tool_index;
                                self.next_openai_tool_index += 1;
                                idx
                            });
                        out.push_str(&self.openai_data(json!({
                            "id": self.message_id,
                            "object": "chat.completion.chunk",
                            "model": self.client_model,
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": idx,
                                        "id": id,
                                        "type": "function",
                                        "function": { "name": name, "arguments": "" }
                                    }]
                                },
                                "finish_reason": Value::Null
                            }]
                        })));
                    }
                }
                Some("content_block_delta") => {
                    if let Some(text) = v.pointer("/delta/text").and_then(|t| t.as_str()) {
                        self.text_started = true;
                        out.push_str(&self.openai_data(json!({
                            "id": self.message_id,
                            "object": "chat.completion.chunk",
                            "model": self.client_model,
                            "choices": [{ "index": 0, "delta": { "content": text }, "finish_reason": Value::Null }]
                        })));
                    } else if let Some(partial) =
                        v.pointer("/delta/partial_json").and_then(|t| t.as_str())
                    {
                        let block_idx = v.get("index").and_then(|i| i.as_i64()).unwrap_or(0);
                        let idx =
                            self.anthropic_to_openai_tool.get(&block_idx).copied().unwrap_or(0);
                        out.push_str(&self.openai_data(json!({
                            "id": self.message_id,
                            "object": "chat.completion.chunk",
                            "model": self.client_model,
                            "choices": [{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": idx,
                                        "function": { "arguments": partial }
                                    }]
                                },
                                "finish_reason": Value::Null
                            }]
                        })));
                    }
                }
                Some("message_delta") => {
                    let stop = v.pointer("/delta/stop_reason").and_then(|s| s.as_str());
                    if let Some(stop) = stop {
                        let finish = match stop {
                            "tool_use" => "tool_calls",
                            "max_tokens" => "length",
                            _ => "stop",
                        };
                        out.push_str(&self.openai_data(json!({
                            "id": self.message_id,
                            "object": "chat.completion.chunk",
                            "model": self.client_model,
                            "choices": [{ "index": 0, "delta": {}, "finish_reason": finish }]
                        })));
                    }
                }
                Some("message_stop") => {
                    out.push_str("data: [DONE]\n\n");
                }
                _ => {}
            }
        }
        out
    }

    fn openai_chunk_to_anthropic(&mut self, chunk: &str) -> String {
        let mut out = String::new();
        for raw in chunk.split("\n\n") {
            if raw.trim().is_empty() {
                continue;
            }
            let data_line = raw.lines().find_map(|l| l.strip_prefix("data: "));
            let Some(data) = data_line else { continue };
            if data.trim() == "[DONE]" {
                self.close_anthropic_blocks(&mut out);
                out.push_str(&anthropic_event("message_stop", json!({})));
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                self.message_id = id.to_owned();
            }
            if !self.started {
                self.started = true;
                out.push_str(&anthropic_event(
                    "message_start",
                    json!({
                        "type": "message_start",
                        "message": {
                            "id": self.message_id,
                            "type": "message",
                            "role": "assistant",
                            "model": self.client_model,
                            "content": [],
                        }
                    }),
                ));
            }
            let delta = v.pointer("/choices/0/delta").cloned().unwrap_or(json!({}));
            if let Some(text) = delta.get("content").and_then(|t| t.as_str()) {
                if !self.text_started {
                    self.text_started = true;
                    let index = self.next_anthropic_block_index;
                    self.next_anthropic_block_index += 1;
                    self.text_block_index = Some(index);
                    self.open_anthropic_blocks.insert(index);
                    out.push_str(&anthropic_event(
                        "content_block_start",
                        json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": { "type": "text", "text": "" }
                        }),
                    ));
                }
                let index = self.text_block_index.expect("set with text_started");
                out.push_str(&anthropic_event(
                    "content_block_delta",
                    json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": { "type": "text_delta", "text": text }
                    }),
                ));
            }
            if let Some(calls) = delta.get("tool_calls").and_then(|c| c.as_array()) {
                for call in calls {
                    if let Some(name) = call.pointer("/function/name") {
                        let openai_idx = call.get("index").and_then(|i| i.as_i64()).unwrap_or(0);
                        let idx =
                            *self.openai_to_anthropic_tool.entry(openai_idx).or_insert_with(|| {
                                let idx = self.next_anthropic_block_index;
                                self.next_anthropic_block_index += 1;
                                idx
                            });
                        self.open_anthropic_blocks.insert(idx);
                        out.push_str(&anthropic_event(
                            "content_block_start",
                            json!({
                                "type": "content_block_start",
                                "index": idx,
                                "content_block": {
                                    "type": "tool_use",
                                    "id": call.get("id").cloned().unwrap_or(json!("toolu_x")),
                                    "name": name,
                                    "input": {}
                                }
                            }),
                        ));
                    }
                    if let Some(args) = call.pointer("/function/arguments").and_then(|a| a.as_str())
                        && !args.is_empty()
                    {
                        let openai_idx = call.get("index").and_then(|i| i.as_i64()).unwrap_or(0);
                        let idx = self
                            .openai_to_anthropic_tool
                            .get(&openai_idx)
                            .copied()
                            .unwrap_or(openai_idx);
                        out.push_str(&anthropic_event(
                            "content_block_delta",
                            json!({
                                "type": "content_block_delta",
                                "index": idx,
                                "delta": { "type": "input_json_delta", "partial_json": args }
                            }),
                        ));
                    }
                }
            }
            if let Some(finish) = v.pointer("/choices/0/finish_reason").and_then(|f| f.as_str()) {
                self.close_anthropic_blocks(&mut out);
                let stop = match finish {
                    "tool_calls" => "tool_use",
                    "length" => "max_tokens",
                    _ => "end_turn",
                };
                out.push_str(&anthropic_event(
                    "message_delta",
                    json!({ "type": "message_delta", "delta": { "stop_reason": stop } }),
                ));
            }
        }
        out
    }

    fn close_anthropic_blocks(&mut self, out: &mut String) {
        for index in std::mem::take(&mut self.open_anthropic_blocks) {
            out.push_str(&anthropic_event("content_block_stop", json!({ "index": index })));
        }
        self.text_started = false;
        self.text_block_index = None;
    }

    fn openai_data(&self, v: Value) -> String {
        format!("data: {v}\n\n")
    }
}

fn anthropic_event(name: &str, data: Value) -> String {
    format!("event: {name}\ndata: {data}\n\n")
}

fn parse_sse_event(raw: &str) -> (Option<String>, Option<&str>) {
    let mut event = None;
    let mut data = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("event: ") {
            event = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data = Some(rest);
        }
    }
    (event, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::SseRewriter;

    #[test]
    fn anthropic_text_deltas_become_openai_chunks() {
        let mut s = DialectSse::new(Dialect::Anthropic, Dialect::Openai, "gpt-4o");
        let chunk = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let out = s.rewrite(chunk);
        assert!(out.contains("chat.completion.chunk"), "{out}");
        assert!(out.contains("\"content\":\"Hi\""), "{out}");
        assert!(out.contains("data: [DONE]"), "{out}");
    }

    #[test]
    fn openai_text_and_tool_chunks_become_ordered_anthropic_blocks() {
        let mut s = DialectSse::new(Dialect::Openai, Dialect::Anthropic, "smart");
        let chunk = concat!(
            "data: {\"id\":\"chat_1\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat_1\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chat_1\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = s.rewrite(chunk);
        assert!(
            out.contains("\"content_block\":{\"text\":\"\",\"type\":\"text\"},\"index\":0"),
            "{out}"
        );
        assert!(out.contains("\"content_block\":{\"id\":\"call_1\""), "{out}");
        assert!(out.contains("\"index\":1,\"type\":\"content_block_start\""), "{out}");
        let text_stop = out.find("data: {\"index\":0}").unwrap();
        let tool_stop = out.find("data: {\"index\":1}").unwrap();
        let message_delta = out.find("event: message_delta").unwrap();
        assert!(text_stop < message_delta && tool_stop < message_delta, "{out}");
        assert!(out.ends_with("event: message_stop\ndata: {}\n\n"), "{out}");
    }

    #[test]
    fn same_dialect_streams_rewrite_the_model_alias() {
        let mut s = DialectSse::new(Dialect::Openai, Dialect::Openai, "client-alias");
        let out = s.rewrite(
            "data: {\"model\":\"origin-model\",\"choices\":[{\"delta\":{}}]}\n\ndata: [DONE]\n\n",
        );
        assert!(out.contains("\"model\":\"client-alias\""), "{out}");
        assert!(out.contains("data: [DONE]"), "{out}");
    }
}
