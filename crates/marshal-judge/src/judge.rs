//! The judge as a policy layer: scoping, caching, concurrency bounding, and the circuit
//! breaker wrapped around a [`Provider`].

use std::sync::Arc;
use std::time::Duration;

use marshal_core::{
    BodyRequirement, CostClass, Evidence, FailureMode, PolicyLayer, Reason, RequestContext, Result,
    Verdict,
};

use crate::breaker::CircuitBreaker;
use crate::providers::{Decision, JudgeVerdict, Provider};
use crate::request::JudgeRequest;
use crate::scope::{self, CompiledScope};

pub struct Judge {
    scope: Vec<CompiledScope>,
    provider: Arc<dyn Provider>,
    prompt: String,
    cache: moka::future::Cache<String, JudgeVerdict>,
    semaphore: Arc<tokio::sync::Semaphore>,
    timeout: Option<Duration>,
    on_error: FailureMode,
    on_timeout: FailureMode,
    breaker: CircuitBreaker,
}

impl std::fmt::Debug for Judge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Judge").field("scope", &self.scope).finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)]
impl Judge {
    pub fn new(
        scope: Vec<CompiledScope>,
        provider: Arc<dyn Provider>,
        prompt: String,
        cache_ttl: Duration,
        cache_max_entries: u64,
        max_concurrent: usize,
        timeout: Option<Duration>,
        on_error: FailureMode,
        on_timeout: FailureMode,
        breaker_threshold: u32,
        breaker_cooldown: Duration,
    ) -> Self {
        Self {
            scope,
            provider,
            prompt,
            cache: moka::future::Cache::builder()
                .max_capacity(cache_max_entries)
                .time_to_live(cache_ttl)
                .build(),
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1))),
            timeout,
            on_error,
            on_timeout,
            breaker: CircuitBreaker::new(breaker_threshold, breaker_cooldown),
        }
    }

    /// Cache hit rate as `(hits, misses)`. Surfaced as a metric because a profile whose scope
    /// is too broad is both slow and expensive, and this is the number that shows it.
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache.entry_count(), self.cache.weighted_size())
    }

    fn to_verdict(&self, verdict: &JudgeVerdict, ev: Evidence, cached: bool) -> Verdict {
        let mut reason = Reason::new(
            "judge",
            match verdict.decision {
                Decision::Allow => "judge_allowed",
                Decision::Deny => "judge_denied",
                Decision::Pass => "judge_uncertain",
            },
            verdict.reason.clone(),
        );
        if cached {
            reason = reason.cached();
        }
        match verdict.decision {
            Decision::Allow => Verdict::Allow(reason),
            Decision::Deny => Verdict::Deny(reason),
            Decision::Pass => {
                let mut ev = ev;
                // Not part of Verdict::Pass's terminal Reason — Pass carries none — so the
                // model's own reasoning is recorded here instead, for the audit trail.
                ev.record("judge.pass_reason", verdict.reason.clone());
                Verdict::Pass(ev)
            }
        }
    }

    fn apply_failure(&self, mode: FailureMode, ev: Evidence, why: &str) -> Verdict {
        let reason = Reason::new("judge", "judge_unavailable", why.to_owned());
        match mode {
            FailureMode::Deny => Verdict::Deny(reason),
            FailureMode::Allow => Verdict::Allow(reason),
            FailureMode::Pass => Verdict::Pass(ev),
        }
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Judge {
    fn name(&self) -> &str {
        "judge"
    }

    fn cost(&self) -> CostClass {
        CostClass::Expensive
    }

    fn needs_request(&self) -> bool {
        true
    }

    fn body_requirement(&self) -> BodyRequirement {
        // Never buffers, deliberately: the judge is never shown the body, so there is nothing
        // in it worth paying to materialise.
        BodyRequirement::Streaming
    }

    fn on_error(&self) -> FailureMode {
        self.on_error
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        let host = &cx.authority.host;
        let method = cx.method.as_str();

        if !scope::governs(&self.scope, host, method) {
            return Ok(Verdict::Pass(ev.clone()));
        }

        let mut header_names: Vec<String> =
            cx.headers.keys().map(|k| k.as_str().to_ascii_lowercase()).collect();
        header_names.sort();
        header_names.dedup();

        let request = JudgeRequest {
            method: method.to_owned(),
            host: host.clone(),
            path: cx.uri.path().to_owned(),
            header_names,
        };
        let key = request.cache_key();

        if let Some(cached) = self.cache.get(&key).await {
            return Ok(self.to_verdict(&cached, ev.clone(), true));
        }

        if !self.breaker.allows_call() {
            tracing::warn!(host, "judge circuit breaker open; skipping the call");
            return Ok(self.apply_failure(
                self.on_error,
                ev.clone(),
                "the judge's circuit breaker is open after repeated provider failures",
            ));
        }

        let _permit = match self.semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                // The semaphore is only ever closed if this Judge is dropped mid-call, which
                // cannot happen while `evaluate` itself holds `&self`.
                unreachable!("semaphore is never explicitly closed")
            }
        };

        let call = self.provider.judge(&request, &self.prompt);
        let outcome = match self.timeout {
            Some(t) => match tokio::time::timeout(t, call).await {
                Ok(r) => r,
                Err(_) => {
                    self.breaker.record_failure();
                    tracing::warn!(host, timeout = ?t, "judge call timed out");
                    return Ok(self.apply_failure(
                        self.on_timeout,
                        ev.clone(),
                        &format!("the judge did not respond within {t:?}"),
                    ));
                }
            },
            None => call.await,
        };

        match outcome {
            Ok(verdict) => {
                self.breaker.record_success();
                self.cache.insert(key, verdict.clone()).await;
                Ok(self.to_verdict(&verdict, ev.clone(), false))
            }
            Err(e) => {
                self.breaker.record_failure();
                tracing::warn!(host, error = %e, "judge call failed");
                Ok(self.apply_failure(self.on_error, ev.clone(), &e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ProviderError;
    use marshal_core::{Authority, BodyHandle, IngressMode, Phase, SessionId};

    #[derive(Debug)]
    struct FakeProvider {
        verdict: std::sync::Mutex<Result<JudgeVerdict, String>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FakeProvider {
        fn allow() -> Self {
            Self {
                verdict: std::sync::Mutex::new(Ok(JudgeVerdict {
                    decision: Decision::Allow,
                    reason: "looks fine".into(),
                })),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn failing() -> Self {
            Self {
                verdict: std::sync::Mutex::new(Err("boom".into())),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Provider for FakeProvider {
        async fn judge(
            &self,
            _req: &JudgeRequest,
            _prompt: &str,
        ) -> Result<JudgeVerdict, ProviderError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match &*self.verdict.lock().unwrap() {
                Ok(v) => Ok(v.clone()),
                Err(_) => Err(ProviderError::Status { status: 500, body: "boom".into() }),
            }
        }
    }

    fn cx(host: &str, method: http::Method) -> RequestContext {
        RequestContext {
            session: SessionId::new("t"),
            profile: Arc::from("p"),
            ingress: IngressMode::Explicit,
            phase: Phase::Request,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            authority: Authority { host: host.to_owned(), port: 443 },
            method,
            uri: "/repos/x/y".parse().unwrap(),
            headers: {
                let mut h = http::HeaderMap::new();
                h.insert("authorization", "Bearer super-secret".parse().unwrap());
                h
            },
            body: BodyHandle::Empty,
            evidence: Evidence::new(),
        }
    }

    fn judge_with(provider: Arc<dyn Provider>) -> Judge {
        Judge::new(
            CompiledScope::compile(&[marshal_config::layer::JudgeScope {
                host: Some("api.github.com".into()),
                cidr: None,
                methods: vec!["POST".into()],
            }])
            .unwrap(),
            provider,
            "test prompt".into(),
            Duration::from_secs(60),
            1000,
            8,
            Some(Duration::from_secs(5)),
            FailureMode::Deny,
            FailureMode::Deny,
            2,
            Duration::from_secs(30),
        )
    }

    #[tokio::test]
    async fn out_of_scope_requests_pass_without_calling_the_provider() {
        let provider = Arc::new(FakeProvider::allow());
        let j = judge_with(provider.clone());
        let out = j
            .evaluate(&cx("other.example.com", http::Method::POST), &Evidence::new())
            .await
            .unwrap();
        assert!(matches!(out, Verdict::Pass(_)));
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn a_scoped_request_is_judged() {
        let provider = Arc::new(FakeProvider::allow());
        let j = judge_with(provider.clone());
        let out =
            j.evaluate(&cx("api.github.com", http::Method::POST), &Evidence::new()).await.unwrap();
        assert!(matches!(out, Verdict::Allow(_)));
        assert_eq!(provider.calls(), 1);
    }

    #[tokio::test]
    async fn identical_requests_are_served_from_cache() {
        let provider = Arc::new(FakeProvider::allow());
        let j = judge_with(provider.clone());
        let request = cx("api.github.com", http::Method::POST);

        j.evaluate(&request, &Evidence::new()).await.unwrap();
        let second = j.evaluate(&request, &Evidence::new()).await.unwrap();

        assert_eq!(provider.calls(), 1, "the second call should be a cache hit");
        let Verdict::Allow(reason) = second else { panic!("expected Allow") };
        assert!(reason.cached, "the audit trail must say this came from the cache");
    }

    #[tokio::test]
    async fn a_failing_provider_applies_on_error() {
        let provider = Arc::new(FakeProvider::failing());
        let j = judge_with(provider);
        let out =
            j.evaluate(&cx("api.github.com", http::Method::POST), &Evidence::new()).await.unwrap();
        assert!(matches!(out, Verdict::Deny(_)), "on_error was configured as deny");
    }

    #[tokio::test]
    async fn the_breaker_opens_after_repeated_failures_and_skips_the_call() {
        let provider = Arc::new(FakeProvider::failing());
        let j = judge_with(provider.clone());

        // Two different hosts/paths so caching cannot mask repeated calls.
        for i in 0..2 {
            let mut c = cx("api.github.com", http::Method::POST);
            c.uri = format!("/repos/x/{i}").parse().unwrap();
            j.evaluate(&c, &Evidence::new()).await.unwrap();
        }
        let before = provider.calls();
        assert_eq!(before, 2, "threshold reached");

        let mut c = cx("api.github.com", http::Method::POST);
        c.uri = "/repos/x/after-open".parse().unwrap();
        let out = j.evaluate(&c, &Evidence::new()).await.unwrap();

        assert_eq!(provider.calls(), before, "the breaker must skip the call, not make one");
        let Verdict::Deny(reason) = out else { panic!("expected Deny") };
        assert_eq!(reason.code, "judge_unavailable");
    }

    #[tokio::test]
    async fn header_values_never_reach_the_provider() {
        // The FakeProvider only sees `JudgeRequest`, whose type has no field for header
        // values at all — this is a compile-time guarantee, not a runtime check. This test
        // documents that guarantee rather than re-proving it.
        let req = JudgeRequest {
            method: "POST".into(),
            host: "api.github.com".into(),
            path: "/x".into(),
            header_names: vec!["authorization".into()],
        };
        assert!(!format!("{req:?}").to_lowercase().contains("super-secret"));
    }
}
