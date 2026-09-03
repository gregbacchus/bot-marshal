//! Egress credential scanning: the inverse of secret injection.
//!
//! Injection stops the agent from *holding* a real credential. This stops it from *sending*
//! one it obtained some other way — scraped from a config file, printed by a build tool,
//! pasted into a prompt. Destination filtering cannot help here, because exfiltration through
//! a host the allowlist legitimately permits looks exactly like ordinary work.

use marshal_config::layer::Outcome;
use marshal_core::{
    BodyHandle, BodyRequirement, CostClass, Evidence, PolicyLayer, Reason, RequestContext, Result,
    Verdict,
};

use crate::patterns::Pattern;

/// What to do when a body is larger than the layer will buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oversize {
    /// Refuse. Correct when the layer is load-bearing: an unscanned body is exactly where a
    /// credential would hide.
    Deny,
    /// Forward unscanned, and say so in the audit trail.
    PassUnscanned,
}

#[derive(Debug)]
pub struct Dlp {
    patterns: Vec<Pattern>,
    scan_request: bool,
    on_match: Outcome,
    annotate: Vec<String>,
    body_cap: usize,
    oversize: Oversize,
}

impl Dlp {
    pub fn new(
        patterns: Vec<Pattern>,
        scan_request: bool,
        on_match: Outcome,
        annotate: Vec<String>,
        body_cap: usize,
        oversize: Oversize,
    ) -> Self {
        Self { patterns, scan_request, on_match, annotate, body_cap, oversize }
    }

    fn scan(&self, text: &str) -> Option<&Pattern> {
        self.patterns.iter().find(|p| p.is_match(text))
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Dlp {
    fn name(&self) -> &str {
        "dlp"
    }

    fn needs_request(&self) -> bool {
        true
    }

    fn cost(&self) -> CostClass {
        CostClass::Moderate
    }

    fn body_requirement(&self) -> BodyRequirement {
        if self.scan_request {
            BodyRequirement::Buffered { cap: self.body_cap }
        } else {
            BodyRequirement::Streaming
        }
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        let mut ev = ev.clone();

        // Headers and the query string are always scanned: they cost nothing and are where a
        // credential most often ends up.
        let mut hit = None;
        for (name, value) in cx.headers.iter() {
            if let Ok(text) = value.to_str()
                && let Some(p) = self.scan(text)
            {
                hit = Some((p, format!("header:{name}")));
                break;
            }
        }
        if hit.is_none()
            && let Some(q) = cx.uri.query()
            && let Some(p) = self.scan(q)
        {
            hit = Some((p, "query".to_string()));
        }

        if hit.is_none() && self.scan_request {
            match &cx.body {
                BodyHandle::Buffered(bytes) => {
                    if let Ok(text) = std::str::from_utf8(bytes)
                        && let Some(p) = self.scan(text)
                    {
                        hit = Some((p, "body".to_string()));
                    }
                }
                BodyHandle::Streaming | BodyHandle::OverLimit { .. } => {
                    // The runner could not materialise the body within the cap. Whether that
                    // is fatal is a configured choice, never a silent pass.
                    ev.flag("BodyNotScanned");
                    ev.record("dlp.body_scanned", false);
                    if self.oversize == Oversize::Deny {
                        return Ok(Verdict::Deny(Reason::new(
                            "dlp",
                            "body_too_large_to_scan",
                            format!(
                                "the request body exceeds the {} byte scan cap and this \
                                 profile refuses unscanned bodies",
                                self.body_cap
                            ),
                        )));
                    }
                }
                BodyHandle::Empty => {}
            }
        }

        let Some((pattern, location)) = hit else {
            return Ok(Verdict::Pass(ev));
        };

        // The finding names the pattern and where it was, never the matched text — writing
        // the credential into the audit trail would be the exfiltration this layer prevents.
        ev.record("dlp.matched", pattern.name);
        ev.record("dlp.location", location.clone());
        for flag in &self.annotate {
            ev.flag(flag.as_str());
        }

        let reason = Reason::new(
            "dlp",
            "credential_in_request",
            format!(
                "a value matching `{}` ({}) was found in the {location} of a request to `{}`. \
                 Credentials must not leave through the proxy; use a placeholder and let \
                 bot-marshal inject the real value.",
                pattern.name, pattern.description, cx.authority.host
            ),
        )
        .with_rule(pattern.name);

        Ok(match self.on_match {
            Outcome::Deny => Verdict::Deny(reason),
            Outcome::Allow => Verdict::Allow(reason),
            Outcome::Pass => Verdict::Pass(ev),
        })
    }
}
