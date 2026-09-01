//! Hard denies.
//!
//! Placed first in the chain, so its verdict beats any later approval — including the LLM
//! judge — purely by virtue of the chain short-circuiting. That precedence needs no special
//! rule; it is a consequence of ordering.

use marshal_core::{CostClass, Evidence, PolicyLayer, Reason, RequestContext, Result, Verdict};

use crate::hosts::HostMatcher;

#[derive(Debug)]
pub struct Denylist {
    matcher: HostMatcher,
}

impl Denylist {
    pub fn new(matcher: HostMatcher) -> Self {
        Self { matcher }
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Denylist {
    fn name(&self) -> &str {
        "denylist"
    }

    fn cost(&self) -> CostClass {
        CostClass::Trivial
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        match self.matcher.matches(&cx.authority.host) {
            Some(kind) => Ok(Verdict::Deny(
                Reason::new(
                    "denylist",
                    "host_denied",
                    format!("`{}` is explicitly denied", cx.authority.host),
                )
                .with_rule(kind.rule()),
            )),
            None => Ok(Verdict::Pass(ev.clone())),
        }
    }
}
