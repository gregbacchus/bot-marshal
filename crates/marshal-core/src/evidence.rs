//! Evidence: structured findings passed forward through the policy chain.
//!
//! Evidence is what makes the chain more than a list of independent checks — a cheap layer
//! can record *why* it could not decide, and an expensive layer downstream reasons over that
//! rather than re-deriving it.

use std::collections::{BTreeMap, BTreeSet};

/// A typed fact recorded by a layer, e.g. `domain.bundle = "github"`.
pub type Fact = serde_json::Value;

/// A named boolean observation, e.g. `WriteOperation`, `PossibleSecretInBody`.
///
/// Flags are free-form strings rather than an enum so layers defined in configuration
/// (CEL rules, DLP patterns) can contribute their own without a code change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Flag(pub String);

impl From<&str> for Flag {
    fn from(s: &str) -> Self {
        Flag(s.to_owned())
    }
}

/// One layer's contribution to the audit trail.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LayerOutcome {
    pub layer: String,
    /// `"allow"`, `"deny"`, `"pass"`, `"defer"`, or `"error"`.
    pub verdict: String,
    pub duration_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// True when the verdict was served from the layer's cache.
    #[serde(default)]
    pub cached: bool,
}

/// Accumulated findings. **Append-only**: a layer adds facts and flags but never mutates or
/// removes another layer's, so the trail always reconstructs the decision after the fact.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub facts: BTreeMap<String, Fact>,
    pub flags: BTreeSet<Flag>,
    pub trail: Vec<LayerOutcome>,
}

impl Evidence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fact. Returns `false` and leaves the existing value untouched if the key was
    /// already set by an earlier layer — append-only is enforced, not merely documented.
    pub fn record(&mut self, key: impl Into<String>, value: impl Into<Fact>) -> bool {
        match self.facts.entry(key.into()) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(value.into());
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        }
    }

    pub fn flag(&mut self, flag: impl Into<Flag>) {
        self.flags.insert(flag.into());
    }

    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.contains(&Flag(flag.to_owned()))
    }

    pub fn fact(&self, key: &str) -> Option<&Fact> {
        self.facts.get(key)
    }

    pub fn push_outcome(&mut self, outcome: LayerOutcome) {
        self.trail.push(outcome);
    }

    /// Fold another `Evidence` into this one, append-only.
    ///
    /// The policy chain and the request transforms accumulate into *different* `Evidence`
    /// values — the chain works from a clone, because layers see evidence read-only, while
    /// transforms mutate the request context's own. Both halves belong in the audit record,
    /// so one has to be folded into the other before it is emitted.
    ///
    /// Append-only is preserved exactly as [`Evidence::record`] defines it: a key already set
    /// here keeps its value, so absorbing can never rewrite what an earlier layer observed.
    pub fn absorb(&mut self, other: Evidence) {
        for (key, value) in other.facts {
            self.facts.entry(key).or_insert(value);
        }
        self.flags.extend(other.flags);
        self.trail.extend(other.trail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_are_append_only() {
        let mut ev = Evidence::new();
        assert!(ev.record("domain.bundle", "github"));
        assert!(!ev.record("domain.bundle", "npm"));
        assert_eq!(ev.fact("domain.bundle").unwrap(), "github");
    }

    #[test]
    fn absorbing_merges_without_rewriting_what_was_already_observed() {
        let mut chain = Evidence::new();
        chain.record("allowlist.matched", "github");
        chain.flag("WriteOperation");
        chain.push_outcome(LayerOutcome {
            layer: "allowlist".into(),
            verdict: "allow".into(),
            duration_us: 1,
            detail: None,
            cached: false,
        });

        let mut transforms = Evidence::new();
        transforms.record("secrets.injected.GIT_TOKEN", true);
        // A key the chain already set: append-only means the chain's value survives.
        transforms.record("allowlist.matched", "npm");
        transforms.flag("CredentialInjected");

        chain.absorb(transforms);

        assert_eq!(chain.fact("allowlist.matched").unwrap(), "github");
        assert_eq!(chain.fact("secrets.injected.GIT_TOKEN").unwrap(), &true);
        assert!(chain.has_flag("WriteOperation") && chain.has_flag("CredentialInjected"));
        assert_eq!(chain.trail.len(), 1);
    }

    #[test]
    fn flags_round_trip() {
        let mut ev = Evidence::new();
        ev.flag("WriteOperation");
        assert!(ev.has_flag("WriteOperation"));
        assert!(!ev.has_flag("Reviewed"));
    }
}
