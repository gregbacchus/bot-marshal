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

    /// Whether this layer needs a real request — method, path, headers, body — rather than
    /// just a destination.
    ///
    /// Such a layer is skipped during the `Connect` phase, because it has nothing to judge
    /// there. It also means the layer only ever runs when TLS is intercepted, which the proxy
    /// warns about at startup if no CA is configured: a rule that silently never evaluates is
    /// worse than one that fails loudly.
    fn needs_request(&self) -> bool {
        false
    }

    /// How much of the request body this layer needs materialised.
    ///
    /// A layer that scans bodies cannot work on a stream, and the runner uses this to decide
    /// whether to buffer before evaluating. Declaring it is how a layer says "requests I
    /// apply to stop streaming", which is a real cost and should be visible in config rather
    /// than discovered when an upload stalls.
    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

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

/// How much of a body a transform needs materialised before it can run.
///
/// Bodies stream by default, which is what makes SSE, WebSockets and large uploads work. A
/// transform that needs bytes has to say so and name a cap, so the cost of buffering is
/// declared rather than discovered — and so the runner can reject a config whose transforms
/// would buffer a stream that must not be buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRequirement {
    /// Sees headers only; the body passes through untouched.
    Streaming,
    /// Needs the body in memory, up to `cap` bytes.
    ///
    /// What happens when a body exceeds the cap is a configured choice — refuse the request,
    /// or pass it through untransformed — never a silent truncation.
    Buffered { cap: usize },
}

impl BodyRequirement {
    pub fn buffers(&self) -> bool {
        matches!(self, BodyRequirement::Buffered { .. })
    }

    /// Combine two requirements. Buffering wins over streaming, and the larger cap wins:
    /// if one participant needs 1MiB and another 64KiB, buffering only 64KiB would leave the
    /// first silently working on a truncated body.
    pub fn combine(self, other: Self) -> Self {
        use BodyRequirement::*;
        match (self, other) {
            (Streaming, Streaming) => Streaming,
            (Buffered { cap }, Streaming) | (Streaming, Buffered { cap }) => Buffered { cap },
            (Buffered { cap: a }, Buffered { cap: b }) => Buffered { cap: a.max(b) },
        }
    }
}

/// Decides **how** a permitted request is rewritten on its way out.
///
/// Request transforms run only after the chain has allowed. Secret injection is a request
/// transform, not a policy layer: swapping a placeholder for a real credential is not a
/// decision about whether the request may proceed.
#[async_trait::async_trait]
pub trait RequestTransform: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()>;
}

/// Decides **how** a response is rewritten on its way back to the agent.
///
/// Separate from [`RequestTransform`] because the two differ in more than direction. A
/// response transform may rewrite content the agent will act on — redacting a credential the
/// upstream echoed, summarising a body too large to be useful, compacting a payload before it
/// consumes an agent's context — and those need the whole body, whereas most request
/// transforms only touch headers.
///
/// That makes [`BodyRequirement`] load-bearing here rather than advisory: a transform that
/// summarises cannot run over a stream, so declaring `Buffered` is how it says that a
/// response it applies to is no longer streamable. Applying one to an SSE or WebSocket
/// response is a configuration error, not something to discover at runtime when the agent's
/// stream stalls.
#[async_trait::async_trait]
pub trait ResponseTransform: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

    /// Whether this transform can enforce its behavior one streaming chunk at a time.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// The request is available because a response is rarely interpretable without it — what
    /// to redact, or how aggressively to compact, usually depends on what was asked.
    async fn apply(&self, cx: &RequestContext, resp: &mut ResponseParts) -> Result<()>;

    /// Rewrite one chunk of a streaming text body, if this transform can work incrementally.
    ///
    /// Returning `Some` is how a transform avoids forcing the response to be buffered.
    /// Filtering a `tools/list` out of an SSE stream can be done event by event; summarising
    /// a body cannot, and such a transform simply declines here and buffers instead.
    ///
    /// Only the host is supplied, not the whole request: a transform that works on a stream
    /// by definition cannot depend on the request body, and saying so in the signature is
    /// better than passing a context whose body is meaningless.
    fn rewrite_chunk(&self, _host: &str, _chunk: &str) -> Option<String> {
        None
    }
}

/// A response marshal produces itself, instead of forwarding the request.
#[derive(Debug, Clone)]
pub struct SynthesizedResponse {
    pub status: u16,
    /// Set verbatim. `content-length` is added by the proxy from the body.
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
    /// Machine-readable code for the audit record, e.g. `"oauth2_terminated"`. The layer name
    /// comes from [`RequestResponder::name`].
    pub code: String,
    /// One line for a human reading the audit trail.
    pub message: String,
}

/// **Answers** a request, rather than deciding whether it may proceed or rewriting it.
///
/// The third thing that can happen to an allowed request, alongside being transformed and
/// being forwarded. Until this existed, a request that did not reach the upstream had been
/// denied; now it may also have been *served*, by marshal, on the upstream's behalf.
///
/// It exists for one situation, and the shape follows from it: marshal has taken over a
/// protocol exchange the client believes it is conducting, and must give the client a
/// well-formed answer rather than a refusal. An OAuth2 token endpoint whose credential marshal
/// already holds is the case that motivated it — the client's request cannot be allowed
/// through (it would redeem, or fail to redeem, a code marshal owns) and cannot be refused
/// (the client's state machine would stall on an error it cannot act on).
///
/// Deliberately **not** a [`PolicyLayer`]: a layer decides *whether*, runs before transforms,
/// and therefore never sees the request as it would actually have been sent. A responder runs
/// last, on the finished request, which is the only point at which "what would the upstream
/// have been asked?" is a well-formed question.
///
/// See [ADR-0031](../../../docs/adr/0031-a-responder-may-answer-a-request.md).
#[async_trait::async_trait]
pub trait RequestResponder: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    /// A responder that inspects a request body must say so, exactly as a transform does.
    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Streaming
    }

    /// `Some` to answer the request; `None` to let it go upstream unchanged.
    ///
    /// `&mut` so a responder can record evidence whether or not it answers — "considered and
    /// declined" is worth as much in an audit trail as "answered".
    async fn respond(&self, cx: &mut RequestContext) -> Result<Option<SynthesizedResponse>>;
}
