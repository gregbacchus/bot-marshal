//! In-band capture: the agent runs the OAuth dance, and ends up holding nothing.
//!
//! Not "holds a credential it cannot use" — never receives one. Three hooks on one object,
//! because they are three views of a single state machine and splitting them across
//! independent transforms sharing a table would make the ordering invisible:
//!
//! 1. [`RequestTransform`] on the authorization request. Marshal generates its own PKCE
//!    verifier and **replaces** the agent's `code_challenge` with the challenge derived from
//!    it. From this point the code the provider will issue is redeemable only by marshal —
//!    not because the agent is prevented from trying, but because it does not hold the
//!    verifier that matches the challenge the provider recorded.
//!
//! 2. [`ResponseTransform`] on the redirect. The provider answers with
//!    `302 Location: <redirect_uri>?code=…&state=…`. Marshal lifts the code out, completes the
//!    exchange itself — a direct call to the token endpoint, out of band, nothing forwarded —
//!    and rewrites `Location` so the code the agent receives is an inert sentinel. The real
//!    code never reaches the agent at all.
//!
//! 3. [`RequestResponder`] on the token endpoint. The agent's own exchange is **answered
//!    locally and never forwarded**: a well-formed token response carrying a sentinel. The
//!    agent's state machine completes normally, on nothing.
//!
//! The sentinel does not resurrect the placeholder model ADR-0027 removed. Nothing matches on
//! it and nothing depends on the agent presenting it: injection is unconditional, so whatever
//! the agent sends to the API is overwritten with the real token regardless.
//!
//! See [ADR-0032](../../../../docs/adr/0032-marshal-owns-the-pkce-verifier.md).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use marshal_core::{
    RequestContext, RequestResponder, RequestTransform, ResponseParts, ResponseTransform, Result,
    SynthesizedResponse, form_urlencode,
};

use super::pkce::Pkce;
use super::source::{AuthCodeFlow, Oauth2Source};

/// How long an authorization flow may stay open.
///
/// Long enough for a human to log in, approve, and clear an MFA prompt; short enough that a
/// verifier for an abandoned flow does not sit in memory for the life of the process.
const FLOW_TTL: Duration = Duration::from_secs(600);

/// How many flows may be open at once, per swap.
///
/// A bound rather than a map, because the table is filled by whatever the agent chooses to
/// request: an agent that hits the authorization endpoint in a loop must not be able to grow
/// marshal's memory. Oldest is evicted first, so a real flow can only be pushed out by
/// [`MAX_PENDING`] newer ones inside the TTL.
const MAX_PENDING: usize = 32;

/// What the agent gets instead of a credential.
///
/// Deliberately self-describing: this value can end up in an agent's log or its own token
/// cache, and "marshal-managed" is a far better thing to find there than a random opaque
/// string somebody spends an afternoon trying to trace.
fn sentinel(name: &str, kind: &str) -> String {
    format!("marshal-managed-{kind}-{name}")
}

struct Pending {
    /// The agent's `state`, unchanged — it is what the provider will echo back, and what the
    /// agent's own CSRF check expects to see.
    state: String,
    flow: AuthCodeFlow,
    started: Instant,
}

pub struct Oauth2Broker {
    name: String,
    source: Arc<Oauth2Source>,
    /// `(host, path)` of the authorization endpoint.
    authorize: (String, String),
    /// `(host, path)` of the token endpoint.
    token: (String, String),
    pending: Mutex<VecDeque<Pending>>,
}

impl std::fmt::Debug for Oauth2Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oauth2Broker")
            .field("name", &self.name)
            .field("authorize", &self.authorize)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl Oauth2Broker {
    pub fn new(
        name: impl Into<String>,
        source: Arc<Oauth2Source>,
        authorize_url: &str,
        token_url: &str,
    ) -> Result<Self> {
        Ok(Self {
            name: name.into(),
            source,
            authorize: split_host_path(authorize_url)?,
            token: split_host_path(token_url)?,
            pending: Mutex::new(VecDeque::new()),
        })
    }

    fn matches(&self, cx: &RequestContext, (host, path): &(String, String)) -> bool {
        // Host and path both, and the path exactly: an authorization *server* commonly hosts
        // unrelated endpoints, and matching on the host alone would rewrite requests that have
        // nothing to do with this flow.
        cx.authority.host.eq_ignore_ascii_case(host) && cx.uri.path() == path
    }

    fn remember(&self, pending: Pending) {
        let mut table = self.pending.lock().expect("pending flow lock");
        table.retain(|p| p.started.elapsed() < FLOW_TTL);
        while table.len() >= MAX_PENDING {
            table.pop_front();
        }
        table.push_back(pending);
    }

    fn take(&self, state: &str) -> Option<AuthCodeFlow> {
        let mut table = self.pending.lock().expect("pending flow lock");
        table.retain(|p| p.started.elapsed() < FLOW_TTL);
        // Constant-time compare via the flow's own check, so this does not become the one
        // place `state` is matched with a short-circuiting `==`.
        let at = table
            .iter()
            .position(|p| p.state.len() == state.len() && p.flow.state_matches(state))?;
        table.remove(at).map(|p| p.flow)
    }
}

/// Split `scheme://host[:port]/path` into `(host, path)`.
fn split_host_path(url: &str) -> Result<(String, String)> {
    let (endpoint, path) = marshal_http::Endpoint::parse_with_path(url)
        .map_err(|e| marshal_core::Error::Config(format!("{url}: {e}")))?;
    Ok((endpoint.host, path))
}

/// Parse a query string into pairs, percent-decoding both halves.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                    16,
                ) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

// -------------------------------------------------------------------------------------------
// 1. The authorization request: substitute the challenge.
// -------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl RequestTransform for Oauth2Broker {
    fn name(&self) -> &str {
        "oauth2.authorize"
    }

    async fn apply(&self, cx: &mut RequestContext) -> Result<()> {
        if !self.matches(cx, &self.authorize) {
            return Ok(());
        }
        let query = cx.uri.query().unwrap_or("");
        let mut params = parse_query(query);

        // Only an authorization-code request. A provider's authorize endpoint also serves
        // `response_type=token` (the implicit flow) and plain GETs of its login page, and
        // rewriting either would break them for no benefit.
        if find(&params, "response_type") != Some("code") {
            return Ok(());
        }
        let Some(state) = find(&params, "state").map(str::to_owned) else {
            // Without `state` there is nothing to correlate the redirect back to, so the code
            // could not be captured even after substituting the challenge — and substituting
            // it anyway would break the agent's flow while capturing nothing.
            cx.evidence.record(format!("oauth2.{}.not_captured.no_state", self.name), true);
            tracing::warn!(
                secret = %self.name,
                "an authorization request carried no `state`, so its redirect cannot be \
                 correlated; leaving it alone rather than breaking a flow this cannot capture"
            );
            return Ok(());
        };
        let Some(redirect_uri) = find(&params, "redirect_uri").map(str::to_owned) else {
            cx.evidence.record(format!("oauth2.{}.not_captured.no_redirect_uri", self.name), true);
            return Ok(());
        };

        let pkce = Pkce::generate()?;

        // Replace rather than append, and set the method explicitly: an agent that sent
        // `plain` (or nothing) must not end up with a challenge marshal cannot satisfy.
        params.retain(|(k, _)| k != "code_challenge" && k != "code_challenge_method");
        params.push(("code_challenge".to_owned(), pkce.challenge.clone()));
        params.push(("code_challenge_method".to_owned(), "S256".to_owned()));

        let rebuilt = form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let mut parts = cx.uri.clone().into_parts();
        parts.path_and_query = format!("{}?{rebuilt}", cx.uri.path()).parse().ok();
        if let Ok(uri) = http::Uri::from_parts(parts) {
            cx.uri = uri;
        }

        self.remember(Pending {
            state: state.clone(),
            flow: AuthCodeFlow::intercepted(cx.uri.to_string(), state, pkce.verifier, redirect_uri),
            started: Instant::now(),
        });

        cx.evidence.record(format!("oauth2.{}.challenge_substituted", self.name), true);
        tracing::info!(
            secret = %self.name,
            "substituted marshal's PKCE challenge into an authorization request; the code \
             this produces is redeemable only by marshal"
        );
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------
// 2. The redirect: take the code, exchange it, hand back a sentinel.
// -------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl ResponseTransform for Oauth2Broker {
    fn name(&self) -> &str {
        "oauth2.capture"
    }

    /// The code is in a header, so nothing here needs the body. Saying so keeps in-band
    /// capture compatible with a streaming profile (ADR-0007).
    fn supports_streaming(&self) -> bool {
        true
    }

    /// Matched on the `Location` header rather than on the request, deliberately.
    ///
    /// The redirect carrying the code does not necessarily come from the authorization
    /// endpoint: a provider typically serves a login page there, and issues the redirect from
    /// whatever URL the login form posts to. Keying on "a `Location` whose `state` is one
    /// marshal issued" catches it wherever it originates, and cannot fire on anything else.
    async fn apply(&self, _cx: &RequestContext, resp: &mut ResponseParts) -> Result<()> {
        let Some(location) = resp.headers.get(http::header::LOCATION) else { return Ok(()) };
        let Ok(location) = location.to_str() else { return Ok(()) };
        let Some((base, query)) = location.split_once('?') else { return Ok(()) };

        let mut params = parse_query(query);
        let Some(state) = find(&params, "state") else { return Ok(()) };
        let Some(flow) = self.take(state) else { return Ok(()) };
        let Some(code) = find(&params, "code").map(str::to_owned) else {
            // The provider refused. Nothing to capture; let the agent see its own error.
            return Ok(());
        };

        // The real code is replaced whether or not the exchange below succeeds. If marshal
        // cannot redeem it, the agent must not be handed the chance either — a failure here
        // has to surface as a refused API request naming the cause, not as an agent that
        // quietly authenticated itself.
        let inert = sentinel(&self.name, "code");
        for (k, v) in params.iter_mut() {
            if k == "code" {
                *v = inert.clone();
            }
        }
        let rebuilt = form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        if let Ok(value) = http::HeaderValue::from_str(&format!("{base}?{rebuilt}")) {
            resp.headers.insert(http::header::LOCATION, value);
        }

        match self.source.complete_authorization_code(&code, &flow).await {
            Ok(enrolled) => {
                tracing::info!(
                    secret = %self.name,
                    scope = enrolled.scope.as_deref().unwrap_or("<unstated>"),
                    "captured an authorization code in band and exchanged it; the agent \
                     received a sentinel"
                );
            }
            Err(e) => {
                // Loud, because the agent's flow will appear to have succeeded and the
                // failure will otherwise only show up as refused API requests later.
                tracing::error!(
                    secret = %self.name,
                    error = %e,
                    "captured an authorization code but could not exchange it; the code was \
                     still withheld from the agent, so requests needing this credential will \
                     be refused until it is enrolled"
                );
            }
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------
// 3. The token endpoint: answer, never forward.
// -------------------------------------------------------------------------------------------

#[async_trait::async_trait]
impl RequestResponder for Oauth2Broker {
    fn name(&self) -> &str {
        "oauth2.token"
    }

    async fn respond(&self, cx: &mut RequestContext) -> Result<Option<SynthesizedResponse>> {
        if cx.method != http::Method::POST || !self.matches(cx, &self.token) {
            return Ok(None);
        }

        // Every token request in scope, not only the one redeeming marshal's sentinel code.
        // Within a swap's host scope marshal owns the credential outright (ADR-0027), so the
        // agent has no business at the token endpoint at all — and a client that later tries
        // to refresh its sentinel needs the same well-formed answer as one exchanging a code.
        let body = serde_json::json!({
            "access_token": sentinel(&self.name, "token"),
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": sentinel(&self.name, "refresh"),
        });

        cx.evidence.record(format!("oauth2.{}.token_request_answered", self.name), true);
        tracing::info!(
            secret = %self.name,
            "answered a token request locally; the real exchange was completed by marshal and \
             the agent received a sentinel"
        );

        Ok(Some(SynthesizedResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("cache-control".to_owned(), "no-store".to_owned()),
            ],
            body: bytes::Bytes::from(serde_json::to_vec(&body).expect("serialises")),
            code: "oauth2_terminated".to_owned(),
            message: format!(
                "marshal completed this OAuth2 exchange itself and holds the `{}` credential; \
                 the client received a sentinel it does not need to use",
                self.name
            ),
        }))
    }
}
