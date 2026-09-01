//! Verdicts: what a policy layer decides.

use crate::evidence::Evidence;
use crate::request::RequestContext;

/// The outcome of evaluating one [`PolicyLayer`](crate::policy::PolicyLayer).
///
/// `Allow` and `Deny` are terminal: the chain stops. `Pass` falls through to the next layer,
/// carrying the evidence gathered so far. If *every* layer passes, the profile's
/// `default_action` decides — that terminal default is where default-deny actually lives.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Terminal: permit the request, skipping all later layers.
    Allow(Reason),
    /// Terminal: refuse the request.
    Deny(Reason),
    /// Undecided: hand off to the next layer with accumulated evidence.
    Pass(Evidence),
    /// Terminal-pending: hand to the [`Decider`] (interactive approval).
    Defer(ApprovalRequest),
}

impl Verdict {
    /// Whether this verdict stops the chain.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Verdict::Pass(_))
    }
}

/// The terminal action applied when every layer in the chain returned `Pass`.
///
/// Defaults to `Deny`. `marshal config check` refuses a profile that sets `Allow` without
/// an explicit acknowledgement, because this single field is the product's core guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    #[default]
    Deny,
    Allow,
}

/// A structured, machine-readable explanation of a verdict.
///
/// Rendered into the 403 body so an agent can act on it rather than retry-loop, and emitted
/// verbatim into the audit record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Reason {
    /// Which layer decided, or `"default_action"` for the terminal default.
    pub layer: String,
    /// Stable machine-readable code, e.g. `"host_not_in_allowlist"`.
    pub code: String,
    /// Human-readable detail.
    pub message: String,
    /// Which rule inside the layer matched, when the layer can attribute it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Whether this verdict came from a cache rather than a fresh evaluation.
    #[serde(default)]
    pub cached: bool,
}

impl Reason {
    pub fn new(
        layer: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            layer: layer.into(),
            code: code.into(),
            message: message.into(),
            rule: None,
            cached: false,
        }
    }

    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule = Some(rule.into());
        self
    }

    pub fn cached(mut self) -> Self {
        self.cached = true;
        self
    }
}

/// A request parked awaiting a human decision.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub layer: String,
    pub summary: String,
    pub evidence: Evidence,
}

/// Resolves [`Verdict::Defer`] into a terminal verdict.
///
/// The MVP implementation always denies; an interactive approval flow drops in here later
/// without touching the chain.
#[async_trait::async_trait]
pub trait Decider: Send + Sync + std::fmt::Debug {
    async fn decide(&self, cx: &RequestContext, req: ApprovalRequest) -> Verdict;
}

/// The default [`Decider`]: refuses anything deferred.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyingDecider;

#[async_trait::async_trait]
impl Decider for DenyingDecider {
    async fn decide(&self, _cx: &RequestContext, req: ApprovalRequest) -> Verdict {
        Verdict::Deny(Reason::new(
            req.layer,
            "approval_unavailable",
            "request was deferred for approval but no approval channel is configured",
        ))
    }
}
