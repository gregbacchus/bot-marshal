//! Structured audit records and sinks.
//!
//! Every request produces exactly one record, allowed or denied, carrying the full layer
//! trail so a decision can be reconstructed after the fact.

use std::sync::Arc;

use marshal_core::{Action, AuditRecord, AuditSink, Redactor};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// Writes one JSON object per line.
///
/// Line-delimited rather than a JSON array so the stream is tailable and a crash mid-write
/// costs one record rather than the whole file's parseability.
#[derive(Debug)]
pub struct JsonSink<W> {
    writer: Mutex<W>,
    redactor: Redactor,
}

impl<W: AsyncWrite + Unpin + Send> JsonSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer: Mutex::new(writer), redactor: Redactor::default() }
    }

    /// Scrub the given real secret values from every record before it is written.
    ///
    /// Applied to the serialised document rather than to named fields, so a field added to
    /// `AuditRecord` later cannot quietly become a new way for a credential to escape.
    pub fn redacting(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
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
        let mut line = if self.redactor.is_empty() {
            match serde_json::to_vec(&record) {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!("failed to serialise an audit record; dropping it");
                    return;
                }
            }
        } else {
            let Ok(mut value) = serde_json::to_value(&record) else {
                tracing::error!("failed to serialise an audit record; dropping it");
                return;
            };
            self.redactor.redact_json(&mut value);
            match serde_json::to_vec(&value) {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!("failed to serialise an audit record; dropping it");
                    return;
                }
            }
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
#[derive(Debug, Default)]
pub struct TracingSink {
    redactor: Redactor,
}

impl TracingSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn redacting(redactor: Redactor) -> Self {
        Self { redactor }
    }
}

#[async_trait::async_trait]
impl AuditSink for TracingSink {
    async fn emit(&self, r: AuditRecord) {
        // The message is the only free-text field, and so the only one a secret could reach.
        let message = self.redactor.redact(&r.reason.message);
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
                "deny: {message}",
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
    async fn redaction_removes_secrets_from_anywhere_in_the_record() {
        // The end-to-end proxy test asserts the secret is absent from the audit stream, but
        // no field carries a header value today, so it would pass with redaction disabled.
        // This one puts the secret where a future change might: in the free-text message,
        // in a structured rule field, and in the layer trail.
        const SECRET: &str = "ghp_realsecretvalue0000000000000000000000";

        let mut r = record();
        r.reason.message = format!("upstream rejected {SECRET}");
        r.reason.rule = Some(SECRET.to_string());
        r.trail[0].detail = Some(format!("saw {SECRET} in a header"));
        r.path = format!("/callback?token={SECRET}");

        let sink = JsonSink::new(Vec::new()).redacting(Redactor::new([SECRET.to_string()]));
        sink.emit(r).await;

        let text = String::from_utf8(sink.writer.into_inner()).unwrap();
        assert!(!text.contains(SECRET), "{text}");
        assert_eq!(text.matches(marshal_core::redact::PLACEHOLDER).count(), 4);

        // Redaction must not be indiscriminate: the record is still usable.
        let parsed: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(parsed["host"], "api.github.com");
        assert_eq!(parsed["reason"]["code"], "host_not_allowlisted");
    }

    #[tokio::test]
    async fn without_a_redactor_records_pass_through_verbatim() {
        // The control for the test above: proves the assertion there is doing work.
        const SECRET: &str = "ghp_realsecretvalue0000000000000000000000";
        let mut r = record();
        r.reason.message = format!("upstream rejected {SECRET}");

        let sink = JsonSink::new(Vec::new());
        sink.emit(r).await;
        let text = String::from_utf8(sink.writer.into_inner()).unwrap();
        assert!(text.contains(SECRET));
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
