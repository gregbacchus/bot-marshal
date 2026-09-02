//! The MCP policy layer: gating `tools/call`.
//!
//! `tools/list` filtering is a *response* concern and lives in
//! [`crate::transforms::McpToolFilter`], because removing entries from a payload is mutation
//! rather than a decision.

use std::sync::Arc;

use marshal_core::{
    BodyHandle, BodyRequirement, CostClass, Evidence, PolicyLayer, Reason, RequestContext, Result,
    Verdict,
};

use crate::jsonrpc::{self, Message};
use crate::mcp::{McpPolicy, Refusal};

#[derive(Debug)]
pub struct Mcp {
    policy: Arc<McpPolicy>,
    body_cap: usize,
}

impl Mcp {
    pub fn new(policy: Arc<McpPolicy>, body_cap: usize) -> Self {
        Self { policy, body_cap }
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Mcp {
    fn name(&self) -> &str {
        "mcp"
    }

    fn cost(&self) -> CostClass {
        CostClass::Cheap
    }

    fn needs_request(&self) -> bool {
        true
    }

    fn body_requirement(&self) -> BodyRequirement {
        // The tool name and its arguments are in the body; there is nothing to police
        // without it.
        BodyRequirement::Buffered { cap: self.body_cap }
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        if !self.policy.governs(&cx.authority.host) {
            return Ok(Verdict::Pass(ev.clone()));
        }

        let BodyHandle::Buffered(bytes) = &cx.body else {
            // Either there is no body, or it exceeded the cap. An MCP call that does not fit
            // in the cap cannot be inspected, and an uninspected call to a governed server is
            // exactly what this layer exists to prevent.
            if matches!(cx.body, BodyHandle::Streaming) {
                return Ok(Verdict::Deny(Reason::new(
                    "mcp",
                    "mcp_body_too_large",
                    format!(
                        "a request to the MCP server `{}` exceeded the {} byte inspection \
                         cap, so its tool call could not be checked",
                        cx.authority.host, self.body_cap
                    ),
                )));
            }
            return Ok(Verdict::Pass(ev.clone()));
        };

        let Some(message) = jsonrpc::parse_request(bytes) else {
            // Not JSON-RPC. MCP servers also serve ordinary HTTP; this layer has no opinion
            // on that.
            return Ok(Verdict::Pass(ev.clone()));
        };

        let mut ev = ev.clone();
        match message {
            Message::ToolsList { id } => {
                // Recorded so the response transform knows to filter this response, and so
                // the denial renderer can produce a JSON-RPC error if a later layer refuses.
                ev.record("mcp.method", "tools/list");
                record_id(&mut ev, id);
                ev.flag("McpToolsList");
                Ok(Verdict::Pass(ev))
            }
            Message::Other { method, id } => {
                ev.record("mcp.method", method);
                record_id(&mut ev, id);
                Ok(Verdict::Pass(ev))
            }
            Message::ToolsCall(call) => {
                ev.record("mcp.method", "tools/call");
                ev.record("mcp.tool", call.tool.clone());
                record_id(&mut ev, call.id.clone());

                match self.policy.check_call(
                    &cx.authority.host,
                    &call.tool,
                    call.arguments.as_ref(),
                ) {
                    Ok(()) => Ok(Verdict::Pass(ev)),
                    Err(refusal) => {
                        let message = match &refusal {
                            Refusal::UnknownTool => format!(
                                "the tool `{}` is not permitted on `{}` by profile `{}`",
                                call.tool, cx.authority.host, cx.profile
                            ),
                            Refusal::ConstraintFailed { detail, .. } => detail.clone(),
                        };
                        Ok(Verdict::Deny(
                            Reason::new("mcp", refusal.code(), message).with_rule(call.tool),
                        ))
                    }
                }
            }
        }
    }
}

/// Record the JSON-RPC id so a denial can be rendered as a protocol error rather than a
/// transport failure.
fn record_id(ev: &mut Evidence, id: Option<serde_json::Value>) {
    if let Some(id) = id {
        ev.record("mcp.request_id", id);
    }
}
