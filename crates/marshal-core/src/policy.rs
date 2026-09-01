//! The two traits the architecture turns on: deciding *whether*, and deciding *how*.

use crate::error::Result;
use crate::evidence::Evidence;
use crate::request::{RequestContext, ResponseParts};
use crate::verdict::Verdict;

/// Rough cost of evaluating a layer. Layers are ordered cheapest-first, and
/// `marshal config check` warns when an expensive layer precedes a cheap one — that mistake
/// is invisible until the latency bill arrives.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CostClass {
    /// Microseconds: string and CIDR matching.
    Trivial,
    /// Sub-millisecond: expression evaluation.
    Cheap,
    /// Milliseconds: regex sweeps, entropy scoring, body scanning.
    Moderate,
    /// Hundreds of milliseconds and a network round trip: the LLM judge.
    Expensive,
}

/// What to do when a layer errors or times out.
///
/// Every layer must declare this. An LLM provider outage must not brick all egress, and must
/// not silently open it either — whichever happens is a config choice that lands in the audit
/// record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    #[default]
    Deny,
    Pass,
    Allow,
}

/// Decides **whether** a request may proceed.
///
/// Layers are chained cheapest-first and short-circuit on `Allow`/`Deny`; `Pass` falls through
/// carrying evidence. Ordering is semantically significant: a denylist at position 1 beats a
/// later judge approval purely by being first.
#[async_trait::async_trait]
pub trait PolicyLayer: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn cost(&self) -> CostClass;

    /// What the chain applies if `evaluate` returns `Err` or exceeds its timeout.
    fn on_error(&self) -> FailureMode {
        FailureMode::default()
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict>;

    /// Response-phase evaluation. Defaults to allowing; used by MCP `tools/list` filtering
    /// and response-side DLP.
    async fn evaluate_response(
        &self,
        _cx: &RequestContext,
        _resp: &ResponseParts,
        ev: &Evidence,
    ) -> Result<Verdict> {
        Ok(Verdict::Pass(ev.clone()))
    }
}

/// Decides **how** a permitted request is rewritten.
///
/// Transforms run only after the chain has allowed. Secret injection is a transform, not a
/// policy layer: it is not a decision.
#[async_trait::async_trait]
pub trait Transform: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    async fn on_request(&self, cx: &mut RequestContext) -> Result<()>;

    async fn on_response(&self, _cx: &RequestContext, _resp: &mut ResponseParts) -> Result<()> {
        Ok(())
    }
}
