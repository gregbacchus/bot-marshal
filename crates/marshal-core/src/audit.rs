//! The audit record: one structured entry per request.

use crate::evidence::LayerOutcome;
use crate::verdict::Reason;

/// What was ultimately done with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// Emitted for every request, allowed or not.
///
/// Contains the full layer trail so any decision is reconstructable after the fact. Secrets
/// are redacted before a record is ever constructed — see `marshal-secrets`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub session: String,
    /// `false` when no session resolver matched.
    pub attributed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    pub profile: String,
    pub ingress: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub action: Action,
    /// Which layer produced the terminal verdict, and why.
    pub reason: Reason,
    /// Every layer's verdict, in order.
    pub trail: Vec<LayerOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub duration_ms: u64,
}

/// Where audit records go.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    async fn emit(&self, record: AuditRecord);
}
