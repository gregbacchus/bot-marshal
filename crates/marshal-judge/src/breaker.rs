//! A circuit breaker over consecutive judge failures.
//!
//! Every other policy layer is a pure function with no state between calls. This one needs
//! state, because the judge is the one layer whose failure mode is "a third-party network
//! call stopped answering" — and hammering that endpoint once it is unhealthy only makes the
//! outage longer and the proxy's own request latency worse for every request in scope.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    cooldown: Duration,
    consecutive_failures: AtomicU32,
    opened_at: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            threshold: threshold.max(1),
            cooldown,
            consecutive_failures: AtomicU32::new(0),
            opened_at: Mutex::new(None),
        }
    }

    /// Whether a call should be attempted at all right now.
    ///
    /// Checking and then calling is inherently racy under concurrency — several callers can
    /// all see the breaker closed and all dispatch at once — but the failure mode of that race
    /// is "a few extra calls during the transition", not a correctness problem, and adding a
    /// lock held across the network call to close it would cost far more than it buys.
    pub fn allows_call(&self) -> bool {
        let mut opened_at = self.opened_at.lock().expect("breaker lock");
        match *opened_at {
            Some(at) if at.elapsed() < self.cooldown => false,
            Some(_) => {
                // Cooldown elapsed: half-open. Let one round of calls through and judge the
                // outcome on their own merits rather than staying open forever.
                *opened_at = None;
                true
            }
            None => true,
        }
    }

    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.opened_at.lock().expect("breaker lock") = None;
    }

    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.threshold {
            *self.opened_at.lock().expect("breaker lock") = Some(Instant::now());
        }
    }

    #[cfg(test)]
    pub fn is_open_for_test(&self) -> bool {
        self.opened_at.lock().expect("breaker lock").is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_the_configured_number_of_consecutive_failures() {
        let b = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(b.allows_call());

        b.record_failure();
        b.record_failure();
        assert!(b.allows_call(), "not yet at the threshold");

        b.record_failure();
        assert!(!b.allows_call(), "should be open now");
    }

    #[test]
    fn a_success_resets_the_streak() {
        let b = CircuitBreaker::new(3, Duration::from_secs(60));
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        // Two failures since the reset: still under threshold.
        assert!(b.allows_call());
    }

    #[test]
    fn a_half_open_probe_that_fails_reopens_the_breaker() {
        let b = CircuitBreaker::new(1, Duration::from_millis(10));
        b.record_failure();
        assert!(!b.allows_call());

        std::thread::sleep(Duration::from_millis(20));
        assert!(b.allows_call(), "cooldown elapsed; the probe should be let through");

        // The probe itself fails: back to open immediately, not another full streak.
        b.record_failure();
        assert!(!b.allows_call());
    }

    #[test]
    fn a_half_open_probe_that_succeeds_closes_the_breaker() {
        let b = CircuitBreaker::new(1, Duration::from_millis(10));
        b.record_failure();
        std::thread::sleep(Duration::from_millis(20));
        assert!(b.allows_call(), "cooldown elapsed; the probe should be let through");

        b.record_success();
        assert!(b.allows_call());
        assert!(!b.is_open_for_test());
    }
}
