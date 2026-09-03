//! Scrubbing real secret values out of anything the proxy emits.
//!
//! Boundary secret injection only works if the real credential never leaves the boundary —
//! and an audit trail is a way out of the boundary just as much as a network socket is. A
//! proxy that swaps in a real token and then writes it to a log has moved the secret from one
//! place the agent could read to another.
//!
//! Redaction is therefore applied at the emission boundary rather than trusted to every call
//! site, because "remember not to log the secret" is the kind of rule that holds until someone
//! adds a field.
//!
//! # Why the set changes at runtime
//!
//! The set used to be fixed at startup, which was sound while every secret came from an
//! environment variable or a file: resolve them all once, build the redactor, done. A minted
//! credential — an OAuth2 access token — does not exist until the request that needs it, so a
//! redactor sealed at startup has a permanent hole exactly where the short-lived credentials
//! are. [`Redactor::learn`] closes it, and the sharing is why: every clone of a `Redactor`
//! points at the same set, so teaching it once reaches every sink already holding one.
//!
//! There is still a window, and it is worth naming: between minting a value and learning it,
//! the value is not redacted. Callers must learn *before* the value can reach any sink. See
//! ADR-0030.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, RwLock};

/// How many superseded values one label keeps.
///
/// Not one: a token that has just been refreshed can still appear in a record for a request
/// that started before the refresh, and forgetting the old value the instant a new one
/// arrives would leak precisely during rotation. Not unbounded either — a process running for
/// weeks would otherwise accumulate every token it ever held, in memory, forever.
const LEARNED_PER_LABEL: usize = 4;

/// The shortest value worth redacting. Replacing a one- or two-character "secret" would
/// mangle unrelated output for no security benefit.
const MIN_LENGTH: usize = 4;

#[derive(Default)]
struct Inner {
    /// Values known at construction: config-sized, so never evicted.
    pinned: BTreeSet<String>,
    /// Values learned since, per label, most-recent-last and bounded.
    learned: BTreeMap<String, VecDeque<String>>,
    /// Everything above, deduplicated and sorted longest-first, so a secret that contains
    /// another is replaced whole. Rebuilt on mutation, which is rare; read on every emission,
    /// which is not.
    sorted: Vec<String>,
}

impl Inner {
    fn rebuild(&mut self) {
        let all: BTreeSet<&String> =
            self.pinned.iter().chain(self.learned.values().flatten()).collect();
        let mut values: Vec<String> = all.into_iter().cloned().collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        self.sorted = values;
    }
}

/// Holds the real secret values currently in play, so they can be removed from output.
///
/// Cloning shares the set rather than snapshotting it — see the module docs.
#[derive(Default, Clone)]
pub struct Redactor {
    inner: Arc<RwLock<Inner>>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.read().map(|i| i.sorted.len()).unwrap_or(0);
        f.debug_struct("Redactor").field("values", &n).finish()
    }
}

/// What a redacted value is replaced with.
pub const PLACEHOLDER: &str = "«redacted»";

impl Redactor {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        let mut inner = Inner {
            pinned: values.into_iter().filter(|v| v.len() >= MIN_LENGTH).collect(),
            ..Default::default()
        };
        inner.rebuild();
        Self { inner: Arc::new(RwLock::new(inner)) }
    }

    /// Add a value obtained after startup, under the label that owns it.
    ///
    /// The label is what makes the bound safe: each one keeps its few most recent values, so
    /// a credential that refreshes every hour does not grow the set without limit, and a
    /// value that has just been superseded is still redacted for as long as a request that
    /// used it might still be being written out.
    ///
    /// Must be called before the value can reach any sink, not after.
    pub fn learn(&self, label: impl Into<String>, value: &str) {
        if value.len() < MIN_LENGTH {
            return;
        }
        let mut inner = match self.inner.write() {
            Ok(guard) => guard,
            // A poisoned lock means a panic while mutating. Refusing to learn would silently
            // stop redacting a live secret, which is the worse of the two failures.
            Err(poisoned) => poisoned.into_inner(),
        };
        let ring = inner.learned.entry(label.into()).or_default();
        if ring.iter().any(|v| v == value) {
            return;
        }
        ring.push_back(value.to_owned());
        while ring.len() > LEARNED_PER_LABEL {
            ring.pop_front();
        }
        inner.rebuild();
    }

    fn values(&self) -> Vec<String> {
        match self.inner.read() {
            Ok(inner) => inner.sorted.clone(),
            Err(poisoned) => poisoned.into_inner().sorted.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self.inner.read() {
            Ok(inner) => inner.sorted.is_empty(),
            Err(poisoned) => poisoned.into_inner().sorted.is_empty(),
        }
    }

    /// Replace every known secret in `input`.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_owned();
        for v in self.values() {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), PLACEHOLDER);
            }
        }
        out
    }

    /// Walk a JSON document, redacting every string in it — keys included, since a secret
    /// used as a map key would otherwise survive.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        let values = self.values();
        if values.is_empty() {
            return;
        }
        self.redact_json_with(&values, value);
    }

    fn redact_json_with(&self, values: &[String], value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                if values.iter().any(|v| s.contains(v.as_str())) {
                    *s = self.redact(s);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_json_with(values, item);
                }
            }
            serde_json::Value::Object(map) => {
                let needs_key_rewrite =
                    map.keys().any(|k| values.iter().any(|v| k.contains(v.as_str())));
                if needs_key_rewrite {
                    let rebuilt: serde_json::Map<String, serde_json::Value> = std::mem::take(map)
                        .into_iter()
                        .map(|(k, v)| (self.redact(&k), v))
                        .collect();
                    *map = rebuilt;
                }
                for (_, v) in map.iter_mut() {
                    self.redact_json_with(values, v);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_every_occurrence() {
        let r = Redactor::new(["sk-live-secret".to_string()]);
        assert_eq!(
            r.redact("Bearer sk-live-secret and again sk-live-secret"),
            format!("Bearer {PLACEHOLDER} and again {PLACEHOLDER}")
        );
    }

    #[test]
    fn longer_secrets_are_replaced_before_shorter_ones_they_contain() {
        // Replacing the short one first would leave the tail of the long one in the output.
        let r = Redactor::new(["abcd".to_string(), "abcd1234".to_string()]);
        assert_eq!(r.redact("abcd1234"), PLACEHOLDER);
    }

    #[test]
    fn very_short_values_are_ignored() {
        // Redacting a one- or two-character "secret" would corrupt unrelated output for no
        // security benefit.
        let r = Redactor::new(["ab".to_string()]);
        assert_eq!(r.redact("a table"), "a table");
        r.learn("tiny", "ab");
        assert_eq!(r.redact("a table"), "a table");
    }

    #[test]
    fn walks_nested_json_including_keys() {
        let r = Redactor::new(["topsecret".to_string()]);
        let mut v = serde_json::json!({
            "headers": { "authorization": "Bearer topsecret" },
            "list": ["topsecret", {"nested": "x topsecret y"}],
            "topsecret": "as a key",
        });
        r.redact_json(&mut v);

        let text = serde_json::to_string(&v).unwrap();
        assert!(!text.contains("topsecret"), "{text}");
        assert_eq!(text.matches(PLACEHOLDER).count(), 4);
    }

    #[test]
    fn a_learned_value_reaches_clones_taken_before_it_was_learned() {
        // This is the whole point: sinks clone the redactor at startup and keep it for the
        // life of the process. A minted token learned later has to reach those clones, or it
        // is redacted nowhere that matters.
        let r = Redactor::new([]);
        let sink_copy = r.clone();
        assert!(sink_copy.is_empty());

        r.learn("SERVICE", "minted-access-token");

        assert_eq!(sink_copy.redact("Bearer minted-access-token"), format!("Bearer {PLACEHOLDER}"));
    }

    #[test]
    fn a_refreshed_credential_keeps_redacting_the_value_it_replaced() {
        // A request that started before the refresh can still be written out after it. The
        // superseded token must not reappear in that record in the clear.
        let r = Redactor::new([]);
        r.learn("SERVICE", "token-one");
        r.learn("SERVICE", "token-two");
        assert_eq!(
            r.redact("token-one then token-two"),
            format!("{PLACEHOLDER} then {PLACEHOLDER}")
        );
    }

    #[test]
    fn one_label_cannot_grow_the_set_without_bound() {
        let r = Redactor::new([]);
        for i in 0..100 {
            r.learn("SERVICE", &format!("token-{i:03}"));
        }
        assert_eq!(r.values().len(), LEARNED_PER_LABEL);
        // The most recent survive; the ancient ones are gone.
        assert_eq!(r.redact("token-099"), PLACEHOLDER);
        assert_eq!(r.redact("token-000"), "token-000");
    }

    #[test]
    fn labels_are_bounded_independently() {
        let r = Redactor::new([]);
        for i in 0..10 {
            r.learn("A", &format!("a-token-{i}"));
            r.learn("B", &format!("b-token-{i}"));
        }
        assert_eq!(r.values().len(), LEARNED_PER_LABEL * 2);
    }

    #[test]
    fn relearning_the_same_value_does_not_consume_a_slot() {
        // A cached token resolves many times; each resolution learns it again.
        let r = Redactor::new([]);
        for _ in 0..50 {
            r.learn("SERVICE", "steady-token");
        }
        r.learn("SERVICE", "next-token");
        assert_eq!(r.values().len(), 2);
        assert_eq!(r.redact("steady-token"), PLACEHOLDER);
    }

    #[test]
    fn pinned_startup_values_are_never_evicted_by_learning() {
        let r = Redactor::new(["from-the-env-file".to_string()]);
        for i in 0..100 {
            r.learn("SERVICE", &format!("token-{i:03}"));
        }
        assert_eq!(r.redact("from-the-env-file"), PLACEHOLDER);
    }
}
