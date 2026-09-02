//! Per-session counters.
//!
//! Groundwork for budgets: once a session is a first-class thing, "how much has this agent
//! done" becomes answerable, which is what a request or token quota needs.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use marshal_core::SessionId;

#[derive(Debug, Default)]
pub struct SessionCounters {
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
}

#[derive(Debug, Default)]
pub struct SessionStats {
    inner: Mutex<HashMap<SessionId, std::sync::Arc<SessionCounters>>>,
}

impl SessionStats {
    pub fn record(&self, session: &SessionId, allowed: bool) {
        let counters = {
            let mut map = self.inner.lock().expect("session stats lock");
            map.entry(session.clone()).or_default().clone()
        };
        if allowed {
            counters.allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `(session, allowed, denied)` for every session seen.
    pub fn snapshot(&self) -> Vec<(SessionId, u64, u64)> {
        let map = self.inner.lock().expect("session stats lock");
        let mut out: Vec<_> = map
            .iter()
            .map(|(s, c)| {
                (s.clone(), c.allowed.load(Ordering::Relaxed), c.denied.load(Ordering::Relaxed))
            })
            .collect();
        out.sort_by_key(|(session, _, _)| session.to_string());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_per_session() {
        let stats = SessionStats::default();
        let a = SessionId::new("agent-a");
        let b = SessionId::new("agent-b");

        stats.record(&a, true);
        stats.record(&a, true);
        stats.record(&a, false);
        stats.record(&b, false);

        let snap = stats.snapshot();
        assert_eq!(snap, vec![(a, 2, 1), (b, 0, 1)]);
    }
}
