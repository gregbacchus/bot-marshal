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

/// How much of each record [`RequestTracingSink`] emits. `Audit` is a strict superset of
/// `Access`'s fields — there's no reason to want both at once, so this is a level, not a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestDetail {
    /// Who, what host, which layer decided, how long it took.
    Access,
    /// Everything `Access` carries, plus the status code, cache/would-deny flags, and the
    /// full layer trail.
    Audit,
}

/// Emits one line per request via `tracing`, always `target: "access"` regardless of detail
/// level — so a query filtering on that target keeps working whichever level is configured.
/// Denials are warnings, because they are the events a human watching the log wants to see
/// stand out.
///
/// At [`RequestDetail::Audit`], `tracing`'s fields are flat, so the trail (a nested
/// structure) travels as a JSON string rather than a real nested value — still fully
/// queryable (`journalctl -o json | jq '.F_TRAIL | fromjson'`, or the same idea piping a
/// JSON-formatted stdout through `jq`), just not natively nested the way a file written by
/// [`JsonSink`] is. Reach for `JsonSink` (via `--audit-log`) instead of this when a pristine,
/// natively-nested structure matters more than having it flow through the same sink as
/// everything else.
#[derive(Debug)]
pub struct RequestTracingSink {
    detail: RequestDetail,
    redactor: Redactor,
}

impl RequestTracingSink {
    pub fn new(detail: RequestDetail) -> Self {
        Self { detail, redactor: Redactor::default() }
    }

    pub fn redacting(detail: RequestDetail, redactor: Redactor) -> Self {
        Self { detail, redactor }
    }
}

#[async_trait::async_trait]
impl AuditSink for RequestTracingSink {
    async fn emit(&self, r: AuditRecord) {
        // The message is the only free-text field, and so the only one a secret could reach.
        let message = self.redactor.redact(&r.reason.message);
        if self.detail == RequestDetail::Access {
            match r.action {
                Action::Allow => tracing::info!(
                    target: "access",
                    identity = %r.identity,
                    profile = %r.profile,
                    host = %r.host,
                    method = %r.method,
                    layer = %r.reason.layer,
                    duration_ms = r.duration_ms,
                    "allow"
                ),
                Action::Deny => tracing::warn!(
                    target: "access",
                    identity = %r.identity,
                    profile = %r.profile,
                    host = %r.host,
                    method = %r.method,
                    layer = %r.reason.layer,
                    code = %r.reason.code,
                    "deny: {message}",
                ),
            }
            return;
        }

        let trail = self.redactor.redact(&serde_json::to_string(&r.trail).unwrap_or_default());
        match r.action {
            Action::Allow => tracing::info!(
                target: "access",
                identity = %r.identity,
                attributed = r.attributed,
                resolver = r.resolver.as_deref().unwrap_or(""),
                profile = %r.profile,
                ingress = %r.ingress,
                host = %r.host,
                method = %r.method,
                path = %r.path,
                layer = %r.reason.layer,
                code = %r.reason.code,
                cached = r.reason.cached,
                would_deny = r.would_deny,
                status_code = r.status_code.unwrap_or_default(),
                duration_ms = r.duration_ms,
                trail = %trail,
                "allow"
            ),
            Action::Deny => tracing::warn!(
                target: "access",
                identity = %r.identity,
                attributed = r.attributed,
                resolver = r.resolver.as_deref().unwrap_or(""),
                profile = %r.profile,
                ingress = %r.ingress,
                host = %r.host,
                method = %r.method,
                path = %r.path,
                layer = %r.reason.layer,
                code = %r.reason.code,
                cached = r.reason.cached,
                would_deny = r.would_deny,
                status_code = r.status_code.unwrap_or_default(),
                duration_ms = r.duration_ms,
                trail = %trail,
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
            identity: "agent-a".into(),
            attributed: true,
            resolver: Some("proxy_auth".into()),
            profile: "coding-agent".into(),
            ingress: "explicit".into(),
            host: "api.github.com".into(),
            method: "CONNECT".into(),
            path: String::new(),
            action: Action::Deny,
            reason: Reason::new("allowlist", "host_not_allowlisted", "nope"),
            would_deny: false,
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
