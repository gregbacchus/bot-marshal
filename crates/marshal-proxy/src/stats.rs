//! Counters.
//!
//! Two audiences. `/v1/sessions` answers "what is this agent doing", which is the question an
//! operator asks when an agent misbehaves. `/v1/metrics` answers "is the proxy healthy", which
//! is what gets scraped.
//!
//! Both must count *requests*, not connections. Once TLS is intercepted a single CONNECT
//! carries many requests, and counting tunnels would understate an agent's activity by
//! whatever its connection reuse happens to be.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use marshal_core::SessionId;

#[derive(Debug, Default)]
pub struct Counters {
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    /// Allowed only because the profile is in warn mode.
    pub would_deny: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.allowed.load(Ordering::Relaxed),
            self.denied.load(Ordering::Relaxed),
            self.would_deny.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug, Default)]
pub struct SessionStats {
    sessions: Mutex<HashMap<SessionId, std::sync::Arc<Counters>>>,
    profiles: Mutex<HashMap<String, std::sync::Arc<Counters>>>,
}

/// One session's totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub key: String,
    pub allowed: u64,
    pub denied: u64,
    pub would_deny: u64,
}

impl SessionStats {
    /// Record one *request*. Called from every path that produces an audit record, so the
    /// two can never disagree about what happened.
    pub fn record(&self, session: &SessionId, profile: &str, allowed: bool, would_deny: bool) {
        for counters in
            [entry(&self.sessions, session.clone()), entry(&self.profiles, profile.to_owned())]
        {
            if allowed {
                counters.allowed.fetch_add(1, Ordering::Relaxed);
            } else {
                counters.denied.fetch_add(1, Ordering::Relaxed);
            }
            if would_deny {
                counters.would_deny.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn by_session(&self) -> Vec<Row> {
        rows(&self.sessions, |s: &SessionId| s.to_string())
    }

    pub fn by_profile(&self) -> Vec<Row> {
        rows(&self.profiles, |p: &String| p.clone())
    }

    /// Prometheus text exposition format.
    ///
    /// Hand-rolled rather than pulled in: the whole surface is three counters, and a metrics
    /// library would be more dependency than the thing it formats.
    pub fn prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP marshal_requests_total Requests by outcome and profile.\n");
        out.push_str("# TYPE marshal_requests_total counter\n");
        for row in self.by_profile() {
            let profile = escape(&row.key);
            out.push_str(&format!(
                "marshal_requests_total{{profile=\"{profile}\",action=\"allow\"}} {}\n",
                row.allowed
            ));
            out.push_str(&format!(
                "marshal_requests_total{{profile=\"{profile}\",action=\"deny\"}} {}\n",
                row.denied
            ));
        }

        out.push_str(
            "# HELP marshal_would_deny_total Requests forwarded only because the profile is \
             in warn mode.\n",
        );
        out.push_str("# TYPE marshal_would_deny_total counter\n");
        for row in self.by_profile() {
            out.push_str(&format!(
                "marshal_would_deny_total{{profile=\"{}\"}} {}\n",
                escape(&row.key),
                row.would_deny
            ));
        }

        out.push_str("# HELP marshal_session_requests_total Requests by session.\n");
        out.push_str("# TYPE marshal_session_requests_total counter\n");
        for row in self.by_session() {
            let session = escape(&row.key);
            out.push_str(&format!(
                "marshal_session_requests_total{{session=\"{session}\",action=\"allow\"}} {}\n",
                row.allowed
            ));
            out.push_str(&format!(
                "marshal_session_requests_total{{session=\"{session}\",action=\"deny\"}} {}\n",
                row.denied
            ));
        }
        out
    }
}

fn entry<K: std::hash::Hash + Eq + Clone>(
    map: &Mutex<HashMap<K, std::sync::Arc<Counters>>>,
    key: K,
) -> std::sync::Arc<Counters> {
    map.lock().expect("stats lock").entry(key).or_default().clone()
}

fn rows<K: std::hash::Hash + Eq>(
    map: &Mutex<HashMap<K, std::sync::Arc<Counters>>>,
    render: impl Fn(&K) -> String,
) -> Vec<Row> {
    let map = map.lock().expect("stats lock");
    let mut out: Vec<Row> = map
        .iter()
        .map(|(k, c)| {
            let (allowed, denied, would_deny) = c.snapshot();
            Row { key: render(k), allowed, denied, would_deny }
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Escape a Prometheus label value. A profile name is operator-supplied, and an unescaped
/// quote would produce output no scraper can parse.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_session_and_by_profile() {
        let stats = SessionStats::default();
        let a = SessionId::new("agent-a");
        let b = SessionId::new("agent-b");

        stats.record(&a, "coding", true, false);
        stats.record(&a, "coding", true, false);
        stats.record(&a, "coding", false, false);
        stats.record(&b, "llm", false, false);

        assert_eq!(
            stats.by_session(),
            vec![
                Row { key: "agent-a".into(), allowed: 2, denied: 1, would_deny: 0 },
                Row { key: "agent-b".into(), allowed: 0, denied: 1, would_deny: 0 },
            ]
        );
        assert_eq!(
            stats.by_profile(),
            vec![
                Row { key: "coding".into(), allowed: 2, denied: 1, would_deny: 0 },
                Row { key: "llm".into(), allowed: 0, denied: 1, would_deny: 0 },
            ]
        );
    }

    #[test]
    fn warn_mode_requests_count_as_allowed_and_as_would_deny() {
        // Both, deliberately: the request *was* forwarded, and policy *did* disagree.
        // Counting it only as allowed would hide the rollout signal.
        let stats = SessionStats::default();
        stats.record(&SessionId::new("s"), "rollout", true, true);

        let row = &stats.by_profile()[0];
        assert_eq!(row.allowed, 1);
        assert_eq!(row.denied, 0);
        assert_eq!(row.would_deny, 1);
    }

    #[test]
    fn prometheus_output_is_well_formed() {
        let stats = SessionStats::default();
        stats.record(&SessionId::new("agent-a"), "coding", true, false);

        let text = stats.prometheus();
        assert!(text.contains("# TYPE marshal_requests_total counter"));
        assert!(text.contains(r#"marshal_requests_total{profile="coding",action="allow"} 1"#));
        assert!(text.contains(r#"marshal_requests_total{profile="coding",action="deny"} 0"#));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn label_values_are_escaped() {
        // Profile names come from config; an unescaped quote produces output no scraper can
        // parse, which silently loses every metric rather than just the offending one.
        let stats = SessionStats::default();
        stats.record(&SessionId::new(r#"we"ird"#), r#"pro"file"#, true, false);

        let text = stats.prometheus();
        assert!(text.contains(r#"profile="pro\"file""#), "{text}");
        assert!(text.contains(r#"session="we\"ird""#), "{text}");
    }
}
