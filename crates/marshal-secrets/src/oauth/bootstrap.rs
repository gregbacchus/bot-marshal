//! Bootstrap capture: learning a credential from a login somebody else performed.
//!
//! [`super::broker`] handles the case where marshal knows a provider's OAuth application
//! already — its `client_id`, its authorization and token endpoints — and an untrusted agent
//! must be prevented from ever holding a real token. This handles the opposite case: marshal
//! knows *nothing* about the provider, and a human is deliberately performing a real login in
//! order to seed a credential.
//!
//! # Why the token endpoint, and not the redirect
//!
//! The broker intercepts the authorization redirect, which requires it to know the
//! authorization endpoint in advance *and* requires whoever made that request to be behind the
//! proxy. For a CLI that hands off to the operator's own desktop browser, neither holds: the
//! endpoint is the vendor's own undisclosed registration, and the browser is a separate process
//! that never sees the proxy environment the CLI was given.
//!
//! But whatever route the code takes, the client's **own process** must eventually POST the
//! token endpoint to redeem it — that is the only way it obtains anything usable. That request
//! goes out over the client's own network stack, which `HTTPS_PROXY` (or, properly, a network
//! namespace) does control. And it carries everything worth knowing: `code`, `code_verifier`,
//! `client_id`, `redirect_uri`, and — as its own destination — the token endpoint itself.
//!
//! So this needs no prior configuration at all, and never has to see a browser.
//!
//! # The trade it makes
//!
//! [`CaptureMode::Observe`] lets the real exchange complete, so the client ends up holding a
//! working credential too. That is a genuine departure from the rest of this crate, where the
//! whole point is that it does not — and it is deliberate: this runs in the foreground, once,
//! because a human asked for it. [`CaptureMode::Steal`] is there for anyone who wants the
//! stricter behaviour anyway.
//!
//! See ADR-0033.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use marshal_core::{
    BodyRequirement, Error, RequestContext, RequestResponder, RequestTransform, ResponseParts,
    ResponseTransform, Result, SynthesizedResponse,
};
use marshal_http::UpstreamGuard;

use super::form::{find, parse_pairs};
use super::store::{StoredGrant, TokenStore, now_unix};
use super::token::{TokenResponse, describe_error};

/// A token exchange is a form body of a few hundred bytes and a JSON reply not much larger.
/// Capped because both are read into memory, and a client or provider sending megabytes here
/// has nothing to say that this needs to hear.
const BODY_CAP: usize = 64 * 1024;

/// The grants worth bootstrapping from — the two that represent somebody having just logged in.
///
/// `refresh_token` is deliberately absent even though it would also yield a usable credential:
/// capturing one means capturing a client that was *already* enrolled somewhere else, and under
/// [`CaptureMode::Steal`] that would break a working tool the operator never meant to touch.
const BOOTSTRAPPABLE: [&str; 2] =
    ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Forward the request untouched and keep a copy of what comes back. The client's own
    /// login succeeds normally.
    Observe,
    /// Redeem out of band and answer the client with a sentinel, so it never holds a working
    /// credential — at the cost of its login appearing to fail.
    Steal,
}

/// What a completed capture learned. Carries configuration, never a credential.
#[derive(Debug, Clone)]
pub struct Bootstrapped {
    pub token_endpoint: String,
    pub grant_type: String,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    /// Whether a refresh token was issued and therefore persisted. A provider that returns
    /// only an access token leaves nothing that survives a restart.
    pub enrolled: bool,
}

pub struct BootstrapCapture {
    /// The storage key under `state_dir`. Not a reference to any configured swap — bootstrap
    /// runs precisely when no such swap exists yet.
    name: String,
    mode: CaptureMode,
    /// Optional narrowing, for the rare session where more than one thing is in flight.
    host_filter: Option<String>,
    store: Arc<TokenStore>,
    tls: Arc<rustls::ClientConfig>,
    guard: Option<Arc<UpstreamGuard>>,
    redactor: marshal_core::Redactor,
    timeout: Duration,
    /// Fires once, on the first exchange that actually yields a token. Taken, not cloned, so a
    /// second capture cannot signal twice.
    done: Mutex<Option<tokio::sync::oneshot::Sender<Bootstrapped>>>,
}

impl std::fmt::Debug for BootstrapCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapCapture")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("host_filter", &self.host_filter)
            .finish_non_exhaustive()
    }
}

impl BootstrapCapture {
    /// Returns the capture object and the channel that fires when it succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        mode: CaptureMode,
        host_filter: Option<String>,
        store: Arc<TokenStore>,
        tls: Arc<rustls::ClientConfig>,
        guard: Option<Arc<UpstreamGuard>>,
        redactor: marshal_core::Redactor,
        timeout: Duration,
    ) -> (Arc<Self>, tokio::sync::oneshot::Receiver<Bootstrapped>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let capture = Arc::new(Self {
            name: name.into(),
            mode,
            host_filter,
            store,
            tls,
            guard,
            redactor,
            timeout,
            done: Mutex::new(Some(tx)),
        });
        (capture, rx)
    }

    /// The form parameters of a token exchange worth capturing, or `None`.
    ///
    /// Matched on the *shape* of the request rather than a configured host and path, because
    /// bootstrap by definition does not know the host or the path yet. That is safe here in a
    /// way it would not be for a standing transform: this listener exists for one purpose, for
    /// minutes, with somebody watching.
    fn interesting(&self, cx: &RequestContext) -> Option<Vec<(String, String)>> {
        if cx.method != http::Method::POST {
            return None;
        }
        if let Some(host) = &self.host_filter
            && !cx.authority.host.eq_ignore_ascii_case(host)
        {
            return None;
        }
        // Streaming here means nothing declared the request body buffered — a wiring mistake,
        // since this type declares it on two of its three impls.
        let body = cx.body.as_bytes()?;
        let params = parse_pairs(&String::from_utf8_lossy(body));
        let grant = find(&params, "grant_type")?;
        BOOTSTRAPPABLE.contains(&grant).then_some(params)
    }

    fn token_endpoint(&self, cx: &RequestContext) -> String {
        // Rebuilt rather than taken from any config: the request's own destination *is* the
        // token endpoint, which is the entire reason bootstrap needs nothing configured.
        //
        // The port is part of that destination whenever it is not the scheme's default —
        // dropping it would report the wrong endpoint, and in `Steal` mode would send the
        // redemption to port 443 of a provider listening somewhere else entirely.
        if cx.authority.port == 443 {
            format!("https://{}{}", cx.authority.host, cx.uri.path())
        } else {
            format!("https://{}:{}{}", cx.authority.host, cx.authority.port, cx.uri.path())
        }
    }

    /// Everything that must happen once a real token has been seen, in the order it must happen.
    fn record(
        &self,
        cx: &RequestContext,
        params: &[(String, String)],
        response: &TokenResponse,
    ) -> Result<Bootstrapped> {
        // Learn first. Nothing below may run before the redactor knows these values — the
        // window between obtaining a credential and learning it is the caller's to close
        // (ADR-0029), and everything after this point logs.
        self.redactor.learn(&self.name, response.access_token.expose());
        if let Some(rt) = &response.refresh_token {
            self.redactor.learn(format!("{}.refresh_token", self.name), rt.expose());
        }

        let enrolled = match &response.refresh_token {
            Some(rt) => {
                self.store.put_grant(
                    &self.name,
                    StoredGrant {
                        refresh_token: rt.clone(),
                        obtained_at: now_unix(),
                        scope: response.scope.clone(),
                    },
                )?;
                true
            }
            None => false,
        };

        let learned = Bootstrapped {
            token_endpoint: self.token_endpoint(cx),
            grant_type: find(params, "grant_type").unwrap_or_default().to_owned(),
            client_id: find(params, "client_id").map(str::to_owned),
            redirect_uri: find(params, "redirect_uri").map(str::to_owned),
            scope: response.scope.clone(),
            enrolled,
        };

        tracing::info!(
            secret = %self.name,
            token_endpoint = %learned.token_endpoint,
            grant = %learned.grant_type,
            enrolled,
            "captured an oauth2 credential from an observed exchange"
        );

        // Take the sender: the first exchange that actually yields a token ends the session,
        // and a later one must not signal again.
        if let Some(tx) = self.done.lock().expect("bootstrap signal lock").take() {
            let _ = tx.send(learned.clone());
        }
        Ok(learned)
    }
}

// -------------------------------------------------------------------------------------------
// Observe: declare the request body, then read the real response.
// -------------------------------------------------------------------------------------------

/// Declares the request body buffered, and does nothing else.
///
/// It exists because `MitmHandler::body_requirement` folds request transforms and responders
/// but not response transforms — so a response transform that needs to read what the *request*
/// carried has no way to say so, and would find `cx.body` still streaming.
#[async_trait::async_trait]
impl RequestTransform for BootstrapCapture {
    fn name(&self) -> &str {
        "oauth2.bootstrap.buffer"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Buffered { cap: BODY_CAP }
    }

    async fn apply(&self, _cx: &mut RequestContext) -> Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl ResponseTransform for BootstrapCapture {
    fn name(&self) -> &str {
        "oauth2.bootstrap"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Buffered { cap: BODY_CAP }
    }

    async fn apply(&self, cx: &RequestContext, resp: &mut ResponseParts) -> Result<()> {
        if self.mode != CaptureMode::Observe {
            return Ok(());
        }
        let Some(params) = self.interesting(cx) else { return Ok(()) };
        let Some(body) = resp.body.as_bytes() else { return Ok(()) };
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else { return Ok(()) };

        // A device-code flow polls, and almost every poll answers `authorization_pending`
        // rather than a token. Signalling on the *request* would end the session on the first
        // poll and never see the one that succeeds, so the trigger is a response that actually
        // carries a token.
        if json.get("access_token").and_then(|v| v.as_str()).is_none_or(str::is_empty) {
            return Ok(());
        }

        let response = TokenResponse::parse(&json)?;
        self.record(cx, &params, &response)?;
        // Deliberately no change to `resp`: the client's own login completes normally. That is
        // what `Observe` means, and the cost it accepts.
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------
// Steal: redeem it ourselves, and answer with a sentinel.
// -------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl RequestResponder for BootstrapCapture {
    fn name(&self) -> &str {
        "oauth2.bootstrap.steal"
    }

    fn body_requirement(&self) -> BodyRequirement {
        BodyRequirement::Buffered { cap: BODY_CAP }
    }

    async fn respond(&self, cx: &mut RequestContext) -> Result<Option<SynthesizedResponse>> {
        if self.mode != CaptureMode::Steal {
            return Ok(None);
        }
        let Some(params) = self.interesting(cx) else { return Ok(None) };

        // Replay the client's own body verbatim rather than rebuilding one. It already carries
        // whatever shape this provider wants — parameter order, vendor extras, the exact
        // `code_verifier` that matches the challenge the provider recorded — and reconstructing
        // it would mean guessing at all of that.
        let form =
            cx.body.as_bytes().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
        let (endpoint, path) = marshal_http::Endpoint::parse_with_path(&self.token_endpoint(cx))
            .map_err(|e| Error::Config(format!("the observed token endpoint: {e}")))?;

        // Carry the client's own authentication through, for a confidential client that
        // authenticates with a header rather than in the body.
        let auth = cx
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let headers: Vec<(&str, &str)> =
            auth.as_deref().map(|a| vec![("authorization", a)]).unwrap_or_default();

        let call = marshal_http::post_form(
            &endpoint,
            &self.tls,
            self.guard.as_deref(),
            &path,
            &headers,
            &form,
        );
        let (status, json) = match tokio::time::timeout(self.timeout, call).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                return Err(Error::Config(format!(
                    "redeeming the observed exchange at {}: {e}",
                    self.token_endpoint(cx)
                )));
            }
            Err(_) => {
                return Err(Error::Config(format!(
                    "redeeming the observed exchange at {}: no response within {:?}",
                    self.token_endpoint(cx),
                    self.timeout
                )));
            }
        };

        if !status.is_success() {
            // Pass the provider's own refusal through rather than inventing one: the client is
            // about to be told its login failed, and the true reason is more useful than ours.
            return Err(Error::Config(format!(
                "redeeming the observed exchange at {}: {}",
                self.token_endpoint(cx),
                describe_error(status, &json)
            )));
        }

        // Same guard as observe: a pending poll is not a failure and not a capture.
        if json.get("access_token").and_then(|v| v.as_str()).is_none_or(str::is_empty) {
            let body = serde_json::to_vec(&json).unwrap_or_default();
            return Ok(Some(SynthesizedResponse {
                status: status.as_u16(),
                headers: vec![("content-type".into(), "application/json".into())],
                body: bytes::Bytes::from(body),
                code: "oauth2_bootstrap_pending".into(),
                message: format!("relayed a pending `{}` poll while bootstrapping", self.name),
            }));
        }

        let response = TokenResponse::parse(&json)?;
        self.record(cx, &params, &response)?;

        let sentinel = serde_json::json!({
            "access_token": format!("marshal-managed-token-{}", self.name),
            "token_type": "Bearer",
            "expires_in": 3600,
        });
        Ok(Some(SynthesizedResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("cache-control".to_owned(), "no-store".to_owned()),
            ],
            body: bytes::Bytes::from(serde_json::to_vec(&sentinel).expect("serialises")),
            code: "oauth2_bootstrap_captured".to_owned(),
            message: format!(
                "marshal redeemed this exchange itself and holds the `{}` credential",
                self.name
            ),
        }))
    }
}
