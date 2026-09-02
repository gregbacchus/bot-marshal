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

use std::collections::BTreeSet;

/// Holds the real secret values currently in play, so they can be removed from output.
#[derive(Default, Clone)]
pub struct Redactor {
    /// Sorted longest-first, so a secret that contains another is replaced whole.
    values: Vec<String>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor").field("values", &self.values.len()).finish()
    }
}

/// What a redacted value is replaced with.
pub const PLACEHOLDER: &str = "«redacted»";

impl Redactor {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        // Deduplicate, drop anything too short to be a meaningful secret (redacting a
        // one-character value would mangle unrelated output), then longest-first.
        let unique: BTreeSet<String> = values.into_iter().filter(|v| v.len() >= 4).collect();
        let mut values: Vec<String> = unique.into_iter().collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        Self { values }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Replace every known secret in `input`.
    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_owned();
        for v in &self.values {
            if out.contains(v.as_str()) {
                out = out.replace(v.as_str(), PLACEHOLDER);
            }
        }
        out
    }

    /// Walk a JSON document, redacting every string in it — keys included, since a secret
    /// used as a map key would otherwise survive.
    pub fn redact_json(&self, value: &mut serde_json::Value) {
        if self.values.is_empty() {
            return;
        }
        match value {
            serde_json::Value::String(s) => {
                if self.values.iter().any(|v| s.contains(v.as_str())) {
                    *s = self.redact(s);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    self.redact_json(item);
                }
            }
            serde_json::Value::Object(map) => {
                let needs_key_rewrite =
                    map.keys().any(|k| self.values.iter().any(|v| k.contains(v.as_str())));
                if needs_key_rewrite {
                    let rebuilt: serde_json::Map<String, serde_json::Value> = std::mem::take(map)
                        .into_iter()
                        .map(|(k, v)| (self.redact(&k), v))
                        .collect();
                    *map = rebuilt;
                }
                for (_, v) in map.iter_mut() {
                    self.redact_json(v);
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
}
