//! The policy chain runner.
//!
//! Layers are evaluated in order and short-circuit on the first terminal verdict. `Pass`
//! falls through carrying accumulated evidence. If every layer passes, the profile's
//! `default_action` decides — that terminal is where default-deny actually lives, and it is
//! the only place in the codebase that can turn "nobody had an opinion" into "allow".

use std::sync::Arc;
use std::time::Instant;

use marshal_core::{
    Action, Decider, Decision, Evidence, FailureMode, LayerOutcome, PolicyLayer, Reason,
    RequestContext, Verdict,
};

/// The terminal result of running the chain.
#[derive(Debug)]
pub struct Outcome {
    pub action: Action,
    pub reason: Reason,
    /// Every layer's verdict, in order, for the audit record.
    pub evidence: Evidence,
}

#[derive(Debug)]
pub struct Chain {
    profile: Arc<str>,
    layers: Vec<Arc<dyn PolicyLayer>>,
    default_action: Decision,
    decider: Arc<dyn Decider>,
}

impl Chain {
    pub fn new(
        profile: impl AsRef<str>,
        layers: Vec<Arc<dyn PolicyLayer>>,
        default_action: Decision,
        decider: Arc<dyn Decider>,
    ) -> Self {
        Self { profile: Arc::from(profile.as_ref()), layers, default_action, decider }
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.iter().map(|l| l.name()).collect()
    }

    /// Layers that only ever run on an intercepted request.
    pub fn request_only_layers(&self) -> Vec<&str> {
        self.layers.iter().filter(|l| l.needs_request()).map(|l| l.name()).collect()
    }

    /// The strongest body requirement any layer declares.
    pub fn body_requirement(&self) -> marshal_core::BodyRequirement {
        self.layers
            .iter()
            .map(|l| l.body_requirement())
            .fold(marshal_core::BodyRequirement::Streaming, |acc, r| acc.combine(r))
    }

    pub async fn evaluate(&self, cx: &RequestContext) -> Outcome {
        let mut evidence = cx.evidence.clone();

        for layer in &self.layers {
            // A layer that needs a real request has nothing to say about a CONNECT; it will
            // evaluate once the tunnel is intercepted.
            if layer.needs_request() && cx.phase == marshal_core::Phase::Connect {
                continue;
            }

            let started = Instant::now();
            let result = layer.evaluate(cx, &evidence).await;
            let elapsed_us = started.elapsed().as_micros() as u64;

            // An `Err` is not a verdict. The layer's declared failure mode applies, so an
            // error can never quietly become an allow.
            let verdict = match result {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(layer = layer.name(), error = %e, "policy layer failed");
                    evidence.push_outcome(LayerOutcome {
                        layer: layer.name().to_owned(),
                        verdict: "error".into(),
                        duration_us: elapsed_us,
                        detail: Some(e.to_string()),
                        cached: false,
                    });
                    match layer.on_error() {
                        FailureMode::Deny => {
                            return self.terminate(
                                Action::Deny,
                                Reason::new(
                                    layer.name(),
                                    "layer_error",
                                    format!("{} failed and its failure mode is deny", layer.name()),
                                ),
                                evidence,
                            );
                        }
                        FailureMode::Allow => {
                            return self.terminate(
                                Action::Allow,
                                Reason::new(
                                    layer.name(),
                                    "layer_error",
                                    format!(
                                        "{} failed and its failure mode is allow",
                                        layer.name()
                                    ),
                                ),
                                evidence,
                            );
                        }
                        FailureMode::Pass => continue,
                    }
                }
            };

            match verdict {
                Verdict::Allow(reason) => {
                    evidence.push_outcome(outcome_of(layer.name(), "allow", elapsed_us, &reason));
                    return self.terminate(Action::Allow, reason, evidence);
                }
                Verdict::Deny(reason) => {
                    evidence.push_outcome(outcome_of(layer.name(), "deny", elapsed_us, &reason));
                    return self.terminate(Action::Deny, reason, evidence);
                }
                Verdict::Pass(next) => {
                    // Layers receive evidence read-only and return additions; the runner is
                    // the only thing that advances it.
                    evidence = next;
                    evidence.push_outcome(LayerOutcome {
                        layer: layer.name().to_owned(),
                        verdict: "pass".into(),
                        duration_us: elapsed_us,
                        detail: None,
                        cached: false,
                    });
                }
                Verdict::Defer(req) => {
                    evidence.push_outcome(LayerOutcome {
                        layer: layer.name().to_owned(),
                        verdict: "defer".into(),
                        duration_us: elapsed_us,
                        detail: Some(req.summary.clone()),
                        cached: false,
                    });
                    return match self.decider.decide(cx, req).await {
                        Verdict::Allow(r) => self.terminate(Action::Allow, r, evidence),
                        Verdict::Deny(r) => self.terminate(Action::Deny, r, evidence),
                        // A decider that cannot decide is a denial; deferring forever is not
                        // an option once the request is in flight.
                        _ => self.terminate(
                            Action::Deny,
                            Reason::new(
                                layer.name(),
                                "approval_indeterminate",
                                "the approval decider returned no terminal verdict",
                            ),
                            evidence,
                        ),
                    };
                }
            }
        }

        // Every layer passed.
        let (action, code, message) = match self.default_action {
            Decision::Deny => (
                Action::Deny,
                "default_deny",
                format!(
                    "no policy layer in profile `{}` permitted this request, and the profile \
                     defaults to deny",
                    self.profile
                ),
            ),
            Decision::Allow => (
                Action::Allow,
                "default_allow",
                format!("profile `{}` defaults to allow", self.profile),
            ),
        };
        self.terminate(action, Reason::new("default_action", code, message), evidence)
    }

    fn terminate(&self, action: Action, reason: Reason, evidence: Evidence) -> Outcome {
        Outcome { action, reason, evidence }
    }
}

fn outcome_of(layer: &str, verdict: &str, duration_us: u64, reason: &Reason) -> LayerOutcome {
    LayerOutcome {
        layer: layer.to_owned(),
        verdict: verdict.to_owned(),
        duration_us,
        detail: Some(reason.code.clone()),
        cached: reason.cached,
    }
}
