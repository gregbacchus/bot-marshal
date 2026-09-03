//! The audit record: one structured entry per request.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence::{Fact, Flag, LayerOutcome};
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
    pub identity: String,
    /// `false` when no identity resolver matched.
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
    /// True when the profile is in warn mode and this request *would* have been refused.
    ///
    /// `action` is then `allow` — the request was forwarded — and this field is the entire
    /// signal that policy disagreed. Filter on it to build an allowlist from real traffic.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub would_deny: bool,
    /// Every layer's verdict, in order.
    pub trail: Vec<LayerOutcome>,
    /// Typed observations from every layer *and* every transform — which DLP pattern matched,
    /// which MCP tool was called, which allowlist rule hit, which credential was injected.
    ///
    /// Distinct from `reason`, which is only the layer that *decided*. A request allowed by an
    /// allowlist still has a tool name worth recording, and nothing else in the record carries
    /// it. Omitted when empty, so a record with nothing to say looks exactly as it did before
    /// this field existed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: BTreeMap<String, Fact>,
    /// Named boolean observations, e.g. `PossibleSecretInBody`. Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub flags: BTreeSet<Flag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub duration_ms: u64,
}

/// Where audit records go.
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    async fn emit(&self, record: AuditRecord);
}
