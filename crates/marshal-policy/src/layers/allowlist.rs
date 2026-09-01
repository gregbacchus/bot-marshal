//! Domain and CIDR allowlisting.

use marshal_config::layer::Outcome;
use marshal_core::{CostClass, Evidence, PolicyLayer, Reason, RequestContext, Result, Verdict};

use crate::hosts::HostMatcher;

#[derive(Debug)]
pub struct Allowlist {
    matcher: HostMatcher,
    /// Usually `Allow`. Set to `Pass` to make the allowlist a *precondition* — the host must
    /// be listed, but a later layer still gets to decide.
    on_match: Outcome,
    /// Usually `Pass`, leaving the terminal `default_action` to refuse. Set to `Deny` to make
    /// this layer itself the wall.
    on_miss: Outcome,
}

impl Allowlist {
    pub fn new(matcher: HostMatcher, on_match: Outcome, on_miss: Outcome) -> Self {
        Self { matcher, on_match, on_miss }
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Allowlist {
    fn name(&self) -> &str {
        "allowlist"
    }

    fn cost(&self) -> CostClass {
        CostClass::Trivial
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        let host = &cx.authority.host;

        match self.matcher.matches(host) {
            Some(kind) => {
                let mut ev = ev.clone();
                ev.record("allowlist.matched", kind.rule());
                Ok(apply(
                    self.on_match,
                    ev,
                    Reason::new("allowlist", "host_allowed", format!("`{host}` is allowlisted"))
                        .with_rule(kind.rule()),
                ))
            }
            None => Ok(apply(
                self.on_miss,
                ev.clone(),
                Reason::new(
                    "allowlist",
                    "host_not_allowlisted",
                    format!(
                        "`{host}` is not in this profile's allowlist. Add the domain to the \
                         profile, or import a bundle that contains it."
                    ),
                ),
            )),
        }
    }
}

fn apply(outcome: Outcome, ev: Evidence, reason: Reason) -> Verdict {
    match outcome {
        Outcome::Allow => Verdict::Allow(reason),
        Outcome::Deny => Verdict::Deny(reason),
        Outcome::Pass => Verdict::Pass(ev),
    }
}
