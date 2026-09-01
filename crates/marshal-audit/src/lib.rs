//! Structured audit records and sinks.
//!
//! Every request produces exactly one record, allowed or denied, carrying the full layer
//! trail so a decision can be reconstructed after the fact.

use std::sync::Arc;

use marshal_core::{Action, AuditRecord, AuditSink};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// Writes one JSON object per line.
///
/// Line-delimited rather than a JSON array so the stream is tailable and a crash mid-write
/// costs one record rather than the whole file's parseability.
#[derive(Debug)]
pub struct JsonSink<W> {
    writer: Mutex<W>,
}

impl<W: AsyncWrite + Unpin + Send> JsonSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer: Mutex::new(writer) }
    }
}

impl JsonSink<tokio::io::Stdout> {
    pub fn stdout() -> Arc<Self> {
        Arc::new(JsonSink::new(tokio::io::stdout()))
    }
}

#[async_trait::async_trait]
impl<W: AsyncWrite + Unpin + Send + std::fmt::Debug> AuditSink for JsonSink<W> {
    async fn emit(&self, record: AuditRecord) {
        let Ok(mut line) = serde_json::to_vec(&record) else {
            tracing::error!("failed to serialise an audit record; dropping it");
            return;
        };
        line.push(b'\n');

        let mut w = self.writer.lock().await;
        if let Err(e) = w.write_all(&line).await {
            // An audit sink that cannot write must complain loudly. Silent loss of the audit
            // trail is worse than a noisy log, because the whole point of the proxy is that
            // someone can later answer "what did the agent do?".
            tracing::error!(error = %e, "failed to write an audit record");
        }
        let _ = w.flush().await;
    }
}

/// Mirrors records into `tracing` in addition to the JSON stream, at a level chosen by the
/// outcome: denials are warnings, because they are the events a human wants surfaced.
#[derive(Debug)]
pub struct TracingSink;

#[async_trait::async_trait]
impl AuditSink for TracingSink {
    async fn emit(&self, r: AuditRecord) {
        match r.action {
            Action::Allow => tracing::info!(
                session = %r.session,
                profile = %r.profile,
                host = %r.host,
                method = %r.method,
                layer = %r.reason.layer,
                duration_ms = r.duration_ms,
                "allow"
            ),
            Action::Deny => tracing::warn!(
                session = %r.session,
                profile = %r.profile,
                host = %r.host,
                method = %r.method,
                layer = %r.reason.layer,
                code = %r.reason.code,
                "deny: {}",
                r.reason.message
            ),
        }
    }
}

/// Fans one record out to several sinks.
#[derive(Debug)]
pub struct MultiSink(Vec<Arc<dyn AuditSink>>);

impl MultiSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self(sinks)
    }
}

#[async_trait::async_trait]
impl AuditSink for MultiSink {
    async fn emit(&self, record: AuditRecord) {
        for sink in &self.0 {
            sink.emit(record.clone()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::{LayerOutcome, Reason};

    fn record() -> AuditRecord {
        AuditRecord {
            session: "agent-a".into(),
            attributed: true,
            resolver: Some("proxy_auth".into()),
            profile: "coding-agent".into(),
            ingress: "explicit".into(),
            host: "api.github.com".into(),
            method: "CONNECT".into(),
            path: String::new(),
            action: Action::Deny,
            reason: Reason::new("allowlist", "host_not_allowlisted", "nope"),
            trail: vec![LayerOutcome {
                layer: "denylist".into(),
                verdict: "pass".into(),
                duration_us: 3,
                detail: None,
                cached: false,
            }],
            status_code: None,
            duration_ms: 7,
        }
    }

    #[tokio::test]
    async fn emits_one_json_line_per_record() {
        let buf: Vec<u8> = Vec::new();
        let sink = JsonSink::new(buf);
        sink.emit(record()).await;
        sink.emit(record()).await;

        let out = sink.writer.into_inner();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["action"], "deny");
        assert_eq!(parsed["reason"]["code"], "host_not_allowlisted");
        assert_eq!(parsed["trail"][0]["layer"], "denylist");
    }
}
