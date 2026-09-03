//! OAuth2 as a secret source: a credential marshal *obtains*, rather than one it is given.
//!
//! Every other source in this crate reads a value somebody else produced. This one talks to a
//! token endpoint, which makes it the first source that can fail because a third party is
//! down, and the first whose value did not exist when the process started. Both of those have
//! consequences the rest of the module is shaped around — see [ADR-0030](../../../../docs/adr/0030-oauth2-is-a-secret-source.md).
//!
//! It is a source and not an injection kind because OAuth2 is about *obtaining* a credential;
//! `bearer` and `header` already cover presenting one. A configuration is therefore
//! `source: { type: oauth2, ... }` composed with `inject: { type: bearer }`, and every
//! injection kind works with it for free.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use marshal_core::{
    Error, Redactor, Result, SecretSource, SecretValue, base64_encode, form_urlencode,
    percent_encode,
};
use marshal_http::{Endpoint, UpstreamGuard};

use super::jwt::{Algorithm, Claims, sign};
use super::pkce::{Pkce, random_urlsafe};

use super::store::{StoredGrant, TokenStore, now_unix};
use super::token::{CachedToken, TokenResponse, describe_error};

/// Split `scheme://host[:port][/path]` into its scheme and bare host.
///
/// Bracketed IPv6 is unwrapped, so `http://[::1]:7777/cb` yields `("http", "::1")` and the
/// loopback check does not have to know about brackets.
fn split_redirect(uri: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = uri.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host = match authority.strip_prefix('[') {
        Some(after) => after.split_once(']')?.0,
        None => authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority),
    };
    if host.is_empty() { None } else { Some((scheme, host)) }
}

/// The three things one poll of a device-code flow can mean.
///
/// A type rather than an error, because two of the three are not failures: RFC 8628 §3.5 sends
/// "still waiting" and "slow down" as *error* responses, and a caller that treated every error
/// as fatal would abandon the flow on its very first poll.
#[derive(Debug)]
pub enum DevicePoll {
    /// The operator has not finished authorising. Poll again after the interval.
    Pending,
    /// Polling too fast. Lengthen the interval by 5 seconds and poll again.
    SlowDown,
    Done(Enrolled),
}

/// An authorization-code flow in progress: what to open, and what must survive until the
/// browser comes back.
pub struct AuthCodeFlow {
    /// The URL to open in a browser.
    pub url: String,
    /// CSRF binding. The callback must echo this exactly.
    pub state: String,
    /// Never sent in the authorization request — only in the exchange. Debug-redacted, since
    /// holding it is equivalent to being able to redeem the code.
    verifier: String,
    pub redirect_uri: String,
}

impl std::fmt::Debug for AuthCodeFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is as good as the credential during the flow's lifetime.
        f.debug_struct("AuthCodeFlow")
            .field("url", &self.url)
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

impl AuthCodeFlow {
    /// A flow marshal did not start, but has taken over.
    ///
    /// In-band capture substitutes marshal's PKCE challenge into an authorization request the
    /// *agent* built, so the state and the redirect URI are the agent's — they have to be, or
    /// the agent's own state check fails and the provider rejects a redirect_uri it never saw.
    /// Only the verifier is marshal's, and that is the half that decides who can redeem the
    /// code.
    pub(crate) fn intercepted(
        url: String,
        state: String,
        verifier: String,
        redirect_uri: String,
    ) -> Self {
        Self { url, state, verifier, redirect_uri }
    }

    /// Check a callback's `state` against the one issued, in constant time.
    ///
    /// Not because a timing attack on a CSRF token is likely against a loopback listener that
    /// lives for one exchange — but a comparison that short-circuits is a habit worth not
    /// having in credential code.
    pub fn state_matches(&self, candidate: &str) -> bool {
        let (a, b) = (self.state.as_bytes(), candidate.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// What an enrolment produced, for reporting. Deliberately carries no token.
#[derive(Debug)]
pub struct Enrolled {
    pub scope: Option<String>,
    pub expires_in: Option<Duration>,
}

/// RFC 8628 §3.2: what the operator has to be shown, and how to poll.
#[derive(Debug)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// The same URI with the code already in it, when the provider offers one — worth using,
    /// because it saves the operator typing the code by hand.
    pub verification_uri_complete: Option<String>,
    pub expires_in: Duration,
    pub interval: Duration,
}

impl DeviceAuthorization {
    fn parse(body: &serde_json::Value) -> Result<Self> {
        let field = |name: &str| -> Result<String> {
            body.get(name).and_then(|v| v.as_str()).map(str::to_owned).ok_or_else(|| {
                Error::Config(format!("the device authorization response has no `{name}`"))
            })
        };
        Ok(Self {
            device_code: field("device_code")?,
            user_code: field("user_code")?,
            verification_uri: field("verification_uri")
                // Google spells it `verification_url`. Accepting both costs one line and
                // saves an operator an inexplicable failure.
                .or_else(|_| field("verification_url"))?,
            verification_uri_complete: body
                .get("verification_uri_complete")
                .or_else(|| body.get("verification_url_complete"))
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            // RFC 8628 §3.2 makes both optional with these defaults.
            expires_in: Duration::from_secs(
                body.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(1800),
            ),
            interval: Duration::from_secs(
                body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5),
            ),
        })
    }
}

/// A signing key and how to use it. Shared by the two RFC 7523 flows, which differ only in
/// what the assertion claims and where it is sent.
#[derive(Debug)]
pub struct AssertionKey {
    pub source: Arc<dyn SecretSource>,
    pub algorithm: Algorithm,
    /// The `kid` header. Required by providers that publish more than one key.
    pub key_id: Option<String>,
    /// How long the assertion is valid. Short by default: an assertion is used once,
    /// immediately, and a long-lived one is a bearer credential sitting in a log somewhere.
    pub lifetime: Duration,
}

/// How marshal proves it is the client it says it is.
#[derive(Debug)]
pub enum ClientAuth {
    /// A public client. Legitimate for a device-code or PKCE flow where the client secret
    /// would be in an agent's reach anyway and the provider is configured accordingly.
    None,
    /// `Authorization: Basic base64(client_id:client_secret)`. The default, and what
    /// [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) says a server
    /// MUST support.
    ClientSecretBasic { secret: Arc<dyn SecretSource> },
    /// The same credential in the form body instead. Some providers only accept this.
    ClientSecretPost { secret: Arc<dyn SecretSource> },
    /// A signed assertion instead of a shared secret
    /// ([RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523#section-2.2)). Composes with
    /// any grant, and means there is no client secret to rotate or to leak.
    PrivateKeyJwt { key: AssertionKey },
}

/// Which OAuth2 grant mints the access token.
#[derive(Debug)]
pub enum Grant {
    /// Machine-to-machine: the client credential *is* the identity. No user, no enrolment.
    ClientCredentials,
    /// A long-lived refresh token that something outside marshal manages and puts in an env
    /// var or a file. Rotation is refused rather than mishandled — see [`Oauth2Source::mint`].
    RefreshToken { source: Arc<dyn SecretSource> },
    /// A refresh token marshal obtained itself, by enrolment, and keeps in its own store.
    /// This is where `authorization_code` and `device_code` end up: both are interactive ways
    /// of getting a refresh token, and once one exists the runtime behaviour is identical.
    Enrolled,
    /// A signed assertion *is* the grant
    /// ([RFC 7523 §2.1](https://www.rfc-editor.org/rfc/rfc7523#section-2.1)) — how a Google
    /// service account, Salesforce, or Snowflake authenticates a workload with a key rather
    /// than a password. Nothing to enrol and nothing to refresh: every mint signs a fresh
    /// assertion.
    JwtBearer {
        key: AssertionKey,
        /// `iss`. The service account's own identity.
        issuer: String,
        /// `sub`. Equals `issuer` unless the provider supports impersonation — Google's
        /// domain-wide delegation puts the impersonated user here.
        subject: String,
        /// `aud`. The token endpoint, unless the provider names something else.
        audience: String,
    },
}

impl Grant {
    fn label(&self) -> &'static str {
        match self {
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken { .. } => "refresh_token",
            Self::Enrolled => "enrolled",
            Self::JwtBearer { .. } => "jwt_bearer",
        }
    }
}

#[derive(Debug)]
pub struct Oauth2Config {
    pub token_endpoint: String,
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub grant: Grant,
    pub scope: Vec<String>,
    pub audience: Option<String>,
    /// Anything a provider wants that is not in the RFC — `resource`, a tenant id, a vendor
    /// flag. Sent verbatim, so it is also the escape hatch for a provider this does not
    /// otherwise model.
    pub extra_params: BTreeMap<String, String>,
    /// Subtracted from the provider's stated lifetime, so a token cannot expire in flight.
    pub expiry_skew: Duration,
    /// Where the browser is sent to authorise. `authorization_code` only.
    pub authorization_endpoint: Option<String>,
    /// Where the provider sends the browser back with the code. Must be loopback:
    /// `marshal secrets oauth login` binds it, and a redirect anywhere else would deliver the
    /// code to something other than marshal. `authorization_code` only.
    pub redirect_uri: Option<String>,
    /// RFC 8628 device authorization endpoint. `device_code` only.
    pub device_authorization_endpoint: Option<String>,
}

pub struct Oauth2Source {
    /// The swap name. Doubles as the store key and the redactor label, so a credential's
    /// history is bounded per swap rather than globally.
    name: String,
    cfg: Oauth2Config,
    endpoint: Endpoint,
    path: String,
    store: Arc<TokenStore>,
    tls: Arc<rustls::ClientConfig>,
    /// The token endpoint comes from config and points at a third party, so it goes behind
    /// the guard: a config that names a link-local address is an SSRF, not a feature.
    guard: Option<Arc<UpstreamGuard>>,
    redactor: Redactor,
    /// Serialises minting for this swap, so a burst of requests arriving on an expired token
    /// makes one call to the token endpoint rather than one per request. Some providers
    /// invalidate the previous refresh token on every use, which turns a concurrent double
    /// refresh into a broken credential rather than merely a wasted round trip.
    ///
    /// Per-source, not per-store: a config reload builds a new source with a new mutex, so two
    /// sources can briefly overlap across a reload. That is a wasted mint, not a correctness
    /// problem, and the alternative — a lock outliving the thing it protects — is worse.
    minting: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Oauth2Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oauth2Source")
            .field("name", &self.name)
            .field("grant", &self.cfg.grant.label())
            .field("token_endpoint", &self.cfg.token_endpoint)
            .finish_non_exhaustive()
    }
}

impl Oauth2Source {
    pub fn new(
        name: impl Into<String>,
        cfg: Oauth2Config,
        store: Arc<TokenStore>,
        tls: Arc<rustls::ClientConfig>,
        guard: Option<Arc<UpstreamGuard>>,
        redactor: Redactor,
    ) -> Result<Self> {
        let (endpoint, path) = Endpoint::parse_with_path(&cfg.token_endpoint)
            .map_err(|e| Error::Config(format!("token_endpoint: {e}")))?;
        Ok(Self {
            name: name.into(),
            cfg,
            endpoint,
            path,
            store,
            tls,
            guard,
            redactor,
            minting: tokio::sync::Mutex::new(()),
        })
    }

    /// The token already held for this swap, if it is still good. Used to seed the redactor at
    /// startup without minting anything.
    pub fn cached(&self) -> Option<SecretValue> {
        self.store.cached_access(&self.name).map(|t| t.value)
    }

    /// The refresh token this grant will present, and where it came from.
    async fn refresh_token(&self) -> Result<Option<(SecretValue, bool)>> {
        match &self.cfg.grant {
            Grant::ClientCredentials | Grant::JwtBearer { .. } => Ok(None),
            Grant::RefreshToken { source } => Ok(Some((source.resolve().await?, false))),
            Grant::Enrolled => match self.store.grant(&self.name)? {
                Some(g) => Ok(Some((g.refresh_token, true))),
                None => Err(Error::Config(format!(
                    "the `{}` credential has not been enrolled: run `marshal secrets oauth \
                     login {}` to authorise it once, then this swap works unattended",
                    self.name, self.name
                ))),
            },
        }
    }

    /// Client authentication, as `(extra form params, extra headers)`.
    ///
    /// Split from the grant parameters because every flow needs it identically — minting,
    /// exchanging an authorization code, polling a device code — and getting it subtly wrong
    /// in one of those places is exactly the bug that only shows up on one provider.
    async fn client_auth(&self) -> Result<(Vec<(String, String)>, Vec<(String, String)>)> {
        let mut params: Vec<(String, String)> = Vec::new();
        let mut headers: Vec<(String, String)> = Vec::new();
        match &self.cfg.client_auth {
            ClientAuth::None => {
                params.push(("client_id".into(), self.cfg.client_id.clone()));
            }
            ClientAuth::ClientSecretPost { secret } => {
                params.push(("client_id".into(), self.cfg.client_id.clone()));
                params.push(("client_secret".into(), secret.resolve().await?.expose().to_owned()));
            }
            ClientAuth::PrivateKeyJwt { key } => {
                // RFC 7521 §4.2: `client_id` is optional here, but enough providers require it
                // that omitting it fails more often than including it does.
                params.push(("client_id".into(), self.cfg.client_id.clone()));
                params.push((
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
                params.push((
                    "client_assertion".into(),
                    self.assertion(
                        key,
                        &self.cfg.client_id,
                        &self.cfg.client_id,
                        &self.cfg.token_endpoint,
                        // A `jti` is what lets the provider reject a replayed assertion. Only
                        // meaningful for client authentication, which is why it is set here
                        // and not in the jwt_bearer grant.
                        true,
                        None,
                    )
                    .await?,
                ));
            }
            ClientAuth::ClientSecretBasic { secret } => {
                // RFC 6749 §2.3.1: both halves are form-urlencoded *before* being joined and
                // base64'd. Skipping that step works right up until a client secret contains
                // a `:` or a non-ASCII byte, which is exactly the kind of bug that shows up
                // only after a rotation.
                let secret = secret.resolve().await?;
                let pair = format!(
                    "{}:{}",
                    percent_encode(self.cfg.client_id.as_bytes()),
                    percent_encode(secret.expose().as_bytes())
                );
                headers.push((
                    "authorization".into(),
                    format!("Basic {}", base64_encode(pair.as_bytes())),
                ));
            }
        }
        Ok((params, headers))
    }

    /// The grant-specific half of a routine (non-enrolment) token request.
    async fn grant_params(&self) -> Result<Vec<(String, String)>> {
        let mut params: Vec<(String, String)> = Vec::new();
        if let Grant::JwtBearer { key, issuer, subject, audience } = &self.cfg.grant {
            params
                .push(("grant_type".into(), "urn:ietf:params:oauth:grant-type:jwt-bearer".into()));
            // Scope goes in the assertion as well as the form. RFC 7523 §2.1 permits it in the
            // form; Google reads it only from the assertion. Sending both is the union of what
            // providers accept, and neither spec forbids the other's placement.
            let scope = (!self.cfg.scope.is_empty()).then(|| self.cfg.scope.join(" "));
            params.push((
                "assertion".into(),
                self.assertion(key, issuer, subject, audience, false, scope).await?,
            ));
            if !self.cfg.scope.is_empty() {
                params.push(("scope".into(), self.cfg.scope.join(" ")));
            }
            return Ok(params);
        }
        match self.refresh_token().await? {
            None => params.push(("grant_type".into(), "client_credentials".into())),
            Some((token, _)) => {
                params.push(("grant_type".into(), "refresh_token".into()));
                params.push(("refresh_token".into(), token.expose().to_owned()));
            }
        }
        if !self.cfg.scope.is_empty() {
            params.push(("scope".into(), self.cfg.scope.join(" ")));
        }
        if let Some(audience) = &self.cfg.audience {
            params.push(("audience".into(), audience.clone()));
        }
        Ok(params)
    }

    /// Build and sign one assertion.
    ///
    /// The private key is resolved through an ordinary [`SecretSource`], so it can come from a
    /// file, an environment variable, or a JSON field in one — a Google service-account key
    /// file is JSON with the PEM in `private_key`, which `{ type: file, json_key: private_key }`
    /// reads without any special case here.
    async fn assertion(
        &self,
        key: &AssertionKey,
        issuer: &str,
        subject: &str,
        audience: &str,
        with_jti: bool,
        scope: Option<String>,
    ) -> Result<String> {
        let pem = key.source.resolve().await?;
        let jti = if with_jti { Some(random_urlsafe(16)?) } else { None };
        sign(
            &pem,
            key.algorithm,
            key.key_id.as_deref(),
            &Claims {
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                audience: audience.to_owned(),
                scope,
                jti,
                lifetime_secs: key.lifetime.as_secs(),
                extra: Vec::new(),
            },
        )
    }

    /// Everything a token request looks like on the wire, for one set of grant parameters.
    #[cfg(test)]
    async fn token_request(&self) -> Result<(String, Vec<(String, String)>)> {
        let grant = self.grant_params().await?;
        let (auth_params, headers) = self.client_auth().await?;
        Ok((self.form_body(grant, auth_params), headers))
    }

    fn form_body(
        &self,
        mut params: Vec<(String, String)>,
        auth_params: Vec<(String, String)>,
    ) -> String {
        params.extend(auth_params);
        for (k, v) in &self.cfg.extra_params {
            params.push((k.clone(), v.clone()));
        }
        form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }

    /// POST the token endpoint with `params` plus client authentication, and parse the reply.
    ///
    /// Every token this credential ever holds comes through here, which is what makes this the
    /// one place that has to teach the redactor. A second path to the token endpoint that
    /// forgot to would be silently unredacted (ADR-0029).
    ///
    /// `what` names the operation for the error message: "minting", "exchanging the
    /// authorization code". An operator reading a failure needs to know which step failed.
    async fn post_token(&self, what: &str, params: Vec<(String, String)>) -> Result<TokenResponse> {
        let (auth_params, headers) = self.client_auth().await?;
        let form = self.form_body(params, auth_params);
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let (status, body) = marshal_http::post_form(
            &self.endpoint,
            &self.tls,
            self.guard.as_deref(),
            &self.path,
            &header_refs,
            &form,
        )
        .await
        .map_err(|e| {
            Error::Config(format!(
                "{what} the `{}` credential at {}: {e}",
                self.name, self.cfg.token_endpoint
            ))
        })?;

        if !status.is_success() {
            return Err(Error::Config(format!(
                "{what} the `{}` credential at {}: {}",
                self.name,
                self.cfg.token_endpoint,
                describe_error(status, &body)
            )));
        }

        let response = TokenResponse::parse(&body)?;

        // Learn before anything else can see the value. The redactor is the only thing
        // standing between a token and the audit log, and every path out of here leads
        // somewhere that writes.
        self.redactor.learn(&self.name, response.access_token.expose());
        if let Some(rt) = &response.refresh_token {
            self.redactor.learn(&self.name, rt.expose());
        }
        Ok(response)
    }

    /// One round trip to the token endpoint for an ordinary request-path mint.
    async fn mint(&self) -> Result<SecretValue> {
        let params = self.grant_params().await?;
        let response = self.post_token("minting", params).await?;

        self.persist_rotation(&response)?;
        self.cache(&response);

        tracing::info!(
            secret = %self.name,
            grant = self.cfg.grant.label(),
            expires_in_secs = response.expires_in.map(|d| d.as_secs()),
            "minted an oauth2 access token"
        );
        Ok(response.access_token)
    }

    fn cache(&self, response: &TokenResponse) {
        self.store.put_access(
            &self.name,
            CachedToken::new(
                response.access_token.clone(),
                response.expires_in,
                self.cfg.expiry_skew,
            ),
        );
    }

    // ---------------------------------------------------------------------------------
    // Enrolment. Never reached from the request path: these are driven by
    // `marshal secrets oauth login`, once, by a human.
    // ---------------------------------------------------------------------------------

    /// Begin an authorization-code flow: the URL to open, and the secrets that must survive
    /// until the browser comes back.
    ///
    /// `state` and the PKCE verifier are both generated here and never leave marshal. The
    /// verifier is what makes an intercepted code useless to anyone else; `state` is what makes
    /// a callback marshal did not initiate recognisable as somebody else's.
    pub fn begin_authorization_code(&self) -> Result<AuthCodeFlow> {
        let authorize = self.cfg.authorization_endpoint.as_deref().ok_or_else(|| {
            Error::Config(format!(
                "`{}` uses `grant: authorization_code` but sets no `authorization_endpoint`",
                self.name
            ))
        })?;
        let redirect_uri = self.redirect_uri()?.to_owned();

        let pkce = Pkce::generate()?;
        let state = random_urlsafe(24)?;

        let mut params = vec![
            ("response_type", "code"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("state", state.as_str()),
            ("code_challenge", pkce.challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        let scope = self.cfg.scope.join(" ");
        if !scope.is_empty() {
            params.push(("scope", scope.as_str()));
        }
        if let Some(audience) = &self.cfg.audience {
            params.push(("audience", audience.as_str()));
        }
        let extras: Vec<(&str, &str)> =
            self.cfg.extra_params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        params.extend(extras);

        // The endpoint may already carry a query of its own — a tenant id, an API version.
        let separator = if authorize.contains('?') { '&' } else { '?' };
        Ok(AuthCodeFlow {
            url: format!("{authorize}{separator}{}", form_urlencode(params)),
            state,
            verifier: pkce.verifier,
            redirect_uri,
        })
    }

    /// Redeem an authorization code and store the grant it yields.
    pub async fn complete_authorization_code(
        &self,
        code: &str,
        flow: &AuthCodeFlow,
    ) -> Result<Enrolled> {
        let params = vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), code.to_owned()),
            ("redirect_uri".to_owned(), flow.redirect_uri.clone()),
            ("code_verifier".to_owned(), flow.verifier.clone()),
        ];
        let response = self.post_token("exchanging the authorization code for", params).await?;
        self.store_enrolment(response)
    }

    /// Ask the provider for a device code, and the instructions to show the operator.
    pub async fn begin_device_authorization(&self) -> Result<DeviceAuthorization> {
        let url = self.cfg.device_authorization_endpoint.as_deref().ok_or_else(|| {
            Error::Config(format!(
                "`{}` uses `grant: device_code` but sets no `device_authorization_endpoint`",
                self.name
            ))
        })?;
        let (endpoint, path) = Endpoint::parse_with_path(url)
            .map_err(|e| Error::Config(format!("device_authorization_endpoint: {e}")))?;

        let (auth_params, headers) = self.client_auth().await?;
        let mut params = auth_params;
        if !self.cfg.scope.is_empty() {
            params.push(("scope".into(), self.cfg.scope.join(" ")));
        }
        // RFC 8628 §3.1 requires `client_id` here even for a client that authenticates
        // another way, so add it when `client_auth` did not.
        if !params.iter().any(|(k, _)| k == "client_id") {
            params.push(("client_id".into(), self.cfg.client_id.clone()));
        }
        let form = form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let (status, body) = marshal_http::post_form(
            &endpoint,
            &self.tls,
            self.guard.as_deref(),
            &path,
            &header_refs,
            &form,
        )
        .await
        .map_err(|e| Error::Config(format!("requesting a device code from {url}: {e}")))?;

        if !status.is_success() {
            return Err(Error::Config(format!(
                "requesting a device code from {url}: {}",
                describe_error(status, &body)
            )));
        }
        DeviceAuthorization::parse(&body)
    }

    /// One poll of the token endpoint for a device-code grant.
    pub async fn poll_device_token(&self, device_code: &str) -> Result<DevicePoll> {
        let (auth_params, headers) = self.client_auth().await?;
        let mut params = auth_params;
        params.push(("grant_type".into(), "urn:ietf:params:oauth:grant-type:device_code".into()));
        params.push(("device_code".into(), device_code.to_owned()));
        if !params.iter().any(|(k, _)| k == "client_id") {
            params.push(("client_id".into(), self.cfg.client_id.clone()));
        }
        let form = form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let header_refs: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let (status, body) = marshal_http::post_form(
            &self.endpoint,
            &self.tls,
            self.guard.as_deref(),
            &self.path,
            &header_refs,
            &form,
        )
        .await
        .map_err(|e| Error::Config(format!("polling for the device token: {e}")))?;

        if status.is_success() {
            let response = TokenResponse::parse(&body)?;
            self.redactor.learn(&self.name, response.access_token.expose());
            if let Some(rt) = &response.refresh_token {
                self.redactor.learn(&self.name, rt.expose());
            }
            return self.store_enrolment(response).map(DevicePoll::Done);
        }

        match body.get("error").and_then(|v| v.as_str()) {
            Some("authorization_pending") => Ok(DevicePoll::Pending),
            Some("slow_down") => Ok(DevicePoll::SlowDown),
            // `access_denied` and `expired_token` are the two that really are terminal, along
            // with anything that means the request itself is wrong.
            _ => Err(Error::Config(format!(
                "polling for the device token: {}",
                describe_error(status, &body)
            ))),
        }
    }

    /// Persist what an enrolment produced, and cache the access token that came with it.
    fn store_enrolment(&self, response: TokenResponse) -> Result<Enrolled> {
        let refresh_token = response.refresh_token.clone().ok_or_else(|| {
            Error::Config(format!(
                "the provider completed the flow for `{}` but issued no refresh token, so \
                 nothing can be kept and every restart would need authorising again. Ask for \
                 offline access — most providers want `scope: [offline_access]`, or Google's \
                 `access_type=offline` in `extra_params`.",
                self.name
            ))
        })?;

        self.store.put_grant(
            &self.name,
            StoredGrant { refresh_token, obtained_at: now_unix(), scope: response.scope.clone() },
        )?;
        self.cache(&response);
        Ok(Enrolled { scope: response.scope, expires_in: response.expires_in })
    }

    fn redirect_uri(&self) -> Result<&str> {
        let uri = self.cfg.redirect_uri.as_deref().ok_or_else(|| {
            Error::Config(format!(
                "`{}` uses `grant: authorization_code` but sets no `redirect_uri`",
                self.name
            ))
        })?;
        let (scheme, host) = split_redirect(uri).ok_or_else(|| {
            Error::Config(format!("`{}`: redirect_uri `{uri}` is not a URL", self.name))
        })?;

        // Loopback first, because it is the more useful thing to be told: an operator who
        // wrote a real hostname has a different problem from one who wrote `https`.
        if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
            return Err(Error::Config(format!(
                "`{}`: redirect_uri must point at loopback (127.0.0.1 or localhost), not \
                 `{host}` — marshal binds it itself to receive the authorization code, and a \
                 redirect anywhere else would hand the code to something that is not marshal",
                self.name
            )));
        }
        if scheme != "http" {
            return Err(Error::Config(format!(
                "`{}`: redirect_uri must be `http://` on loopback, not `{scheme}://` — the \
                 listener marshal binds for the redirect is plain HTTP, which is what every \
                 provider expects for a loopback redirect",
                self.name
            )));
        }
        Ok(uri)
    }

    /// Persist a rotated refresh token, before the access token it arrived with is used.
    ///
    /// A provider that rotates invalidates the old refresh token the instant it issues the
    /// new one. Handing back the access token first and persisting after would mean a crash
    /// in between costs the whole credential — for an enrolled grant, that is a human at a
    /// browser, again.
    fn persist_rotation(&self, response: &TokenResponse) -> Result<()> {
        let Some(new_rt) = &response.refresh_token else { return Ok(()) };
        match &self.cfg.grant {
            Grant::ClientCredentials | Grant::JwtBearer { .. } => Ok(()),
            Grant::Enrolled => self.store.put_grant(
                &self.name,
                StoredGrant {
                    refresh_token: new_rt.clone(),
                    obtained_at: now_unix(),
                    scope: response.scope.clone(),
                },
            ),
            Grant::RefreshToken { source } => {
                // The refresh token came from a file or an environment variable that marshal
                // does not own and must not rewrite. If the provider rotated it, the value in
                // that source is now dead and the next mint will fail — so say so now, loudly,
                // while the error still names the cause, rather than in an hour as an
                // inexplicable `invalid_grant`.
                tracing::warn!(
                    secret = %self.name,
                    source = source.name(),
                    "the provider rotated this refresh token, but it comes from a source \
                     marshal does not own, so the new value cannot be saved; the configured \
                     one is now invalid. Use an `enrolled` grant, or point the source at \
                     something that tracks rotation."
                );
                Ok(())
            }
        }
    }
}

#[async_trait::async_trait]
impl SecretSource for Oauth2Source {
    fn name(&self) -> &str {
        // The swap name and the token endpoint, never a value.
        &self.name
    }

    async fn resolve(&self) -> Result<SecretValue> {
        if let Some(token) = self.store.cached_access(&self.name) {
            return Ok(token.value);
        }

        let _minting = self.minting.lock().await;
        // Whoever held the lock may have just minted the token this request needs.
        if let Some(token) = self.store.cached_access(&self.name) {
            return Ok(token.value);
        }

        self.mint().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::EnvSource;
    use std::path::PathBuf;

    /// A source returning a fixed value, for shaping token requests without any environment.
    #[derive(Debug)]
    struct Fixed(&'static str);

    #[async_trait::async_trait]
    impl SecretSource for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        async fn resolve(&self) -> Result<SecretValue> {
            Ok(SecretValue::new(self.0))
        }
    }

    fn interactive(grant: Grant, dir: Option<PathBuf>) -> Oauth2Source {
        Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: "https://auth.example.com/oauth2/token".into(),
                client_id: "marshal".into(),
                client_auth: ClientAuth::None,
                grant,
                scope: vec!["offline_access".into(), "read:things".into()],
                audience: None,
                extra_params: BTreeMap::new(),
                expiry_skew: Duration::from_secs(60),
                authorization_endpoint: Some("https://auth.example.com/oauth2/authorize".into()),
                redirect_uri: Some("http://127.0.0.1:7777/callback".into()),
                device_authorization_endpoint: Some("https://auth.example.com/device".into()),
            },
            Arc::new(TokenStore::new(dir)),
            marshal_http::default_tls_config(),
            None,
            Redactor::default(),
        )
        .unwrap()
    }

    fn source(grant: Grant, client_auth: ClientAuth) -> Oauth2Source {
        Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: "https://auth.example.com/oauth2/token".into(),
                client_id: "marshal".into(),
                client_auth,
                grant,
                scope: vec!["read:things".into(), "write:things".into()],
                audience: None,
                extra_params: BTreeMap::new(),
                expiry_skew: Duration::from_secs(60),
                authorization_endpoint: None,
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(None)),
            marshal_http::default_tls_config(),
            None,
            Redactor::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn client_credentials_sends_the_grant_type_and_scope() {
        let s = source(
            Grant::ClientCredentials,
            ClientAuth::ClientSecretBasic { secret: Arc::new(Fixed("sh")) },
        );
        let (form, _) = s.token_request().await.unwrap();
        assert!(form.contains("grant_type=client_credentials"), "{form}");
        // Scope is space-separated per RFC 6749, so the separator percent-encodes to %20.
        assert!(form.contains("scope=read%3Athings%20write%3Athings"), "{form}");
    }

    #[tokio::test]
    async fn client_secret_basic_puts_the_credential_in_a_header_not_the_body() {
        let s = source(
            Grant::ClientCredentials,
            ClientAuth::ClientSecretBasic { secret: Arc::new(Fixed("s3cret")) },
        );
        let (form, headers) = s.token_request().await.unwrap();
        assert!(!form.contains("s3cret"), "the secret must not be in the form body: {form}");
        assert!(!form.contains("client_id"), "basic auth carries the id too: {form}");
        assert_eq!(headers[0].0, "authorization");
        // base64("marshal:s3cret")
        assert_eq!(headers[0].1, "Basic bWFyc2hhbDpzM2NyZXQ=");
    }

    #[tokio::test]
    async fn client_secret_basic_urlencodes_each_half_before_joining_them() {
        // RFC 6749 §2.3.1. A secret containing `:` would otherwise be indistinguishable from
        // the separator once decoded.
        let s = source(
            Grant::ClientCredentials,
            ClientAuth::ClientSecretBasic { secret: Arc::new(Fixed("a:b c")) },
        );
        let (_, headers) = s.token_request().await.unwrap();
        // base64("marshal:a%3Ab%20c")
        assert_eq!(headers[0].1, format!("Basic {}", base64_encode(b"marshal:a%3Ab%20c")));
    }

    #[tokio::test]
    async fn client_secret_post_puts_the_credential_in_the_body_and_sets_no_header() {
        let s = source(
            Grant::ClientCredentials,
            ClientAuth::ClientSecretPost { secret: Arc::new(Fixed("s3cret")) },
        );
        let (form, headers) = s.token_request().await.unwrap();
        assert!(headers.is_empty());
        assert!(form.contains("client_id=marshal"), "{form}");
        assert!(form.contains("client_secret=s3cret"), "{form}");
    }

    #[tokio::test]
    async fn a_public_client_sends_its_id_and_no_secret() {
        let s = source(Grant::ClientCredentials, ClientAuth::None);
        let (form, headers) = s.token_request().await.unwrap();
        assert!(headers.is_empty());
        assert!(form.contains("client_id=marshal"), "{form}");
        assert!(!form.contains("client_secret"), "{form}");
    }

    #[tokio::test]
    async fn the_refresh_grant_sends_the_token_from_its_configured_source() {
        let s = source(
            Grant::RefreshToken { source: Arc::new(Fixed("rt-configured")) },
            ClientAuth::ClientSecretPost { secret: Arc::new(Fixed("s3cret")) },
        );
        let (form, _) = s.token_request().await.unwrap();
        assert!(form.contains("grant_type=refresh_token"), "{form}");
        assert!(form.contains("refresh_token=rt-configured"), "{form}");
    }

    /// The same throwaway key the jwt module's tests use, reached through a source.
    #[derive(Debug)]
    struct KeyFile;

    #[async_trait::async_trait]
    impl SecretSource for KeyFile {
        fn name(&self) -> &str {
            "SERVICE_KEY"
        }
        async fn resolve(&self) -> Result<SecretValue> {
            Ok(SecretValue::new(super::super::jwt::tests_support::TEST_RSA_PKCS8))
        }
    }

    fn assertion_key() -> AssertionKey {
        AssertionKey {
            source: Arc::new(KeyFile),
            algorithm: Algorithm::Rs256,
            key_id: Some("key-1".into()),
            lifetime: Duration::from_secs(3600),
        }
    }

    /// Read a JWT's payload without trusting the encoder that produced it.
    fn payload_of(jwt: &str) -> serde_json::Value {
        let part = jwt.split('.').nth(1).expect("a JWT has three parts");
        let mut bytes = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in part.chars() {
            let v = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '-' => 62,
                '_' => 63,
                _ => panic!("bad base64url in {part}"),
            };
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                bytes.push((acc >> bits) as u8);
            }
        }
        serde_json::from_slice(&bytes).expect("the payload is JSON")
    }

    fn form_value(form: &str, name: &str) -> String {
        let prefix = format!("{name}=");
        let raw = form
            .split('&')
            .find_map(|p| p.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("no `{name}` in {form}"));
        // Only the characters an assertion can contain need decoding here.
        raw.replace("%2E", ".").replace("%2D", "-").replace("%5F", "_")
    }

    #[tokio::test]
    async fn jwt_bearer_sends_an_assertion_as_the_grant() {
        let s = Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: "https://oauth2.googleapis.com/token".into(),
                client_id: "unused".into(),
                client_auth: ClientAuth::None,
                grant: Grant::JwtBearer {
                    key: assertion_key(),
                    issuer: "svc@project.iam.gserviceaccount.com".into(),
                    subject: "svc@project.iam.gserviceaccount.com".into(),
                    audience: "https://oauth2.googleapis.com/token".into(),
                },
                scope: vec!["https://www.googleapis.com/auth/cloud-platform".into()],
                audience: None,
                extra_params: BTreeMap::new(),
                expiry_skew: Duration::from_secs(60),
                authorization_endpoint: None,
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(None)),
            marshal_http::default_tls_config(),
            None,
            Redactor::default(),
        )
        .unwrap();

        let (form, headers) = s.token_request().await.unwrap();
        assert!(headers.is_empty(), "the assertion is the credential; no header auth");
        assert!(
            form.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"),
            "{form}"
        );

        let claims = payload_of(&form_value(&form, "assertion"));
        assert_eq!(claims["iss"], "svc@project.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        // Google reads scope from the assertion; RFC 7523 permits it in the form. Both.
        assert_eq!(claims["scope"], "https://www.googleapis.com/auth/cloud-platform");
        assert!(form.contains("scope=https"), "{form}");
        // A grant assertion is not replay-scoped the way client authentication is.
        assert!(claims.get("jti").is_none(), "{claims}");
    }

    #[tokio::test]
    async fn jwt_bearer_carries_an_impersonated_subject_when_one_is_configured() {
        // Google's domain-wide delegation: the key belongs to the service account, the access
        // is granted as a user.
        let mut s = source(Grant::ClientCredentials, ClientAuth::None);
        s.cfg.grant = Grant::JwtBearer {
            key: assertion_key(),
            issuer: "svc@project.iam.gserviceaccount.com".into(),
            subject: "user@example.com".into(),
            audience: "https://oauth2.googleapis.com/token".into(),
        };
        let (form, _) = s.token_request().await.unwrap();
        let claims = payload_of(&form_value(&form, "assertion"));
        assert_eq!(claims["iss"], "svc@project.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], "user@example.com");
    }

    #[tokio::test]
    async fn private_key_jwt_authenticates_the_client_and_composes_with_any_grant() {
        let mut s = source(Grant::ClientCredentials, ClientAuth::None);
        s.cfg.client_auth = ClientAuth::PrivateKeyJwt { key: assertion_key() };
        let (form, headers) = s.token_request().await.unwrap();

        assert!(headers.is_empty(), "nothing goes in a header for private_key_jwt");
        assert!(form.contains("grant_type=client_credentials"), "the grant is unchanged: {form}");
        assert!(
            form.contains(
                "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
            ),
            "{form}"
        );
        assert!(form.contains("client_id=marshal"), "{form}");

        let claims = payload_of(&form_value(&form, "client_assertion"));
        // RFC 7523 §3: for client authentication, iss and sub are both the client id, and aud
        // is the token endpoint.
        assert_eq!(claims["iss"], "marshal");
        assert_eq!(claims["sub"], "marshal");
        assert_eq!(claims["aud"], "https://auth.example.com/oauth2/token");
        // The replay defence. Without it a captured assertion is reusable until it expires.
        assert!(claims["jti"].is_string(), "{claims}");
    }

    #[tokio::test]
    async fn two_client_assertions_do_not_share_a_jti() {
        let mut s = source(Grant::ClientCredentials, ClientAuth::None);
        s.cfg.client_auth = ClientAuth::PrivateKeyJwt { key: assertion_key() };
        let (a, _) = s.token_request().await.unwrap();
        let (b, _) = s.token_request().await.unwrap();
        assert_ne!(
            payload_of(&form_value(&a, "client_assertion"))["jti"],
            payload_of(&form_value(&b, "client_assertion"))["jti"]
        );
    }

    #[tokio::test]
    async fn an_unenrolled_grant_says_how_to_enrol_rather_than_failing_obscurely() {
        // This error reaches an agent as a 403 body. "no such credential" would leave an
        // operator with nothing to do about it.
        let s = source(Grant::Enrolled, ClientAuth::None);
        let err = s.token_request().await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("marshal secrets oauth login SERVICE"), "{msg}");
    }

    #[tokio::test]
    async fn extra_params_reach_the_form_body() {
        let mut cfg_extra = BTreeMap::new();
        cfg_extra.insert("resource".to_owned(), "https://api.example.com".to_owned());
        let s = Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: "https://auth.example.com/token".into(),
                client_id: "marshal".into(),
                client_auth: ClientAuth::None,
                grant: Grant::ClientCredentials,
                scope: vec![],
                audience: Some("https://api.example.com".into()),
                extra_params: cfg_extra,
                expiry_skew: Duration::from_secs(60),
                authorization_endpoint: None,
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(None)),
            marshal_http::default_tls_config(),
            None,
            Redactor::default(),
        )
        .unwrap();
        let (form, _) = s.token_request().await.unwrap();
        assert!(form.contains("audience=https%3A%2F%2Fapi.example.com"), "{form}");
        assert!(form.contains("resource=https%3A%2F%2Fapi.example.com"), "{form}");
    }

    #[test]
    fn the_authorization_url_carries_pkce_state_and_everything_configured() {
        let s = interactive(Grant::Enrolled, None);
        let flow = s.begin_authorization_code().unwrap();

        assert!(flow.url.starts_with("https://auth.example.com/oauth2/authorize?"), "{}", flow.url);
        assert!(flow.url.contains("response_type=code"), "{}", flow.url);
        assert!(flow.url.contains("client_id=marshal"), "{}", flow.url);
        assert!(flow.url.contains("code_challenge_method=S256"), "{}", flow.url);
        assert!(
            flow.url.contains(&format!("code_challenge={}", flow_challenge(&flow))),
            "{}",
            flow.url
        );
        assert!(flow.url.contains(&format!("state={}", flow.state)), "{}", flow.url);
        assert!(flow.url.contains("scope=offline_access%20read%3Athings"), "{}", flow.url);
        assert!(
            flow.url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A7777%2Fcallback"),
            "{}",
            flow.url
        );
    }

    /// The challenge that must appear in the URL, derived independently of what built it.
    fn flow_challenge(flow: &AuthCodeFlow) -> String {
        super::super::pkce::challenge_s256(&flow.verifier)
    }

    #[test]
    fn the_verifier_never_appears_in_the_authorization_url() {
        // If it did, PKCE would protect nothing: whoever saw the request could redeem the code.
        let s = interactive(Grant::Enrolled, None);
        let flow = s.begin_authorization_code().unwrap();
        assert!(!flow.url.contains(&flow.verifier), "{}", flow.url);
        assert!(!format!("{flow:?}").contains(&flow.verifier), "Debug must not print it");
    }

    #[test]
    fn two_flows_do_not_share_a_verifier_or_a_state() {
        let s = interactive(Grant::Enrolled, None);
        let (a, b) = (s.begin_authorization_code().unwrap(), s.begin_authorization_code().unwrap());
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.state, b.state);
    }

    #[test]
    fn a_callback_carrying_someone_elses_state_is_rejected() {
        let s = interactive(Grant::Enrolled, None);
        let flow = s.begin_authorization_code().unwrap();
        assert!(flow.state_matches(&flow.state));
        assert!(!flow.state_matches("not-the-state"));
        assert!(!flow.state_matches(""));
        // A prefix must not pass — the comparison is length-checked first.
        assert!(!flow.state_matches(&flow.state[..flow.state.len() - 1]));
    }

    #[test]
    fn a_redirect_uri_that_is_not_loopback_is_refused_with_the_reason() {
        let mut s = interactive(Grant::Enrolled, None);
        s.cfg.redirect_uri = Some("https://example.com/callback".into());
        let err = s.begin_authorization_code().unwrap_err();
        assert!(format!("{err}").contains("loopback"), "{err}");
    }

    #[test]
    fn localhost_and_ipv6_loopback_are_both_accepted() {
        for uri in
            ["http://localhost:7777/callback", "http://[::1]:7777/cb", "http://127.0.0.1:9/x"]
        {
            let mut s = interactive(Grant::Enrolled, None);
            s.cfg.redirect_uri = Some(uri.into());
            assert!(s.begin_authorization_code().is_ok(), "{uri}");
        }
    }

    #[test]
    fn an_authorization_code_grant_with_no_authorization_endpoint_says_which_key_is_missing() {
        let mut s = interactive(Grant::Enrolled, None);
        s.cfg.authorization_endpoint = None;
        let err = s.begin_authorization_code().unwrap_err();
        assert!(format!("{err}").contains("authorization_endpoint"), "{err}");
    }

    #[test]
    fn an_authorization_endpoint_with_its_own_query_gets_the_right_separator() {
        let mut s = interactive(Grant::Enrolled, None);
        s.cfg.authorization_endpoint =
            Some("https://auth.example.com/authorize?tenant=acme".into());
        let flow = s.begin_authorization_code().unwrap();
        assert!(
            flow.url.starts_with("https://auth.example.com/authorize?tenant=acme&"),
            "{}",
            flow.url
        );
    }

    #[test]
    fn an_https_loopback_redirect_says_the_scheme_is_the_problem() {
        // Distinct from the non-loopback message: this operator has the right host and the
        // wrong scheme, and being told "must be loopback" would send them the wrong way.
        let mut s = interactive(Grant::Enrolled, None);
        s.cfg.redirect_uri = Some("https://127.0.0.1:7777/callback".into());
        let err = s.begin_authorization_code().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("http://"), "{msg}");
        assert!(!msg.contains("must point at loopback"), "{msg}");
    }

    #[test]
    fn split_redirect_unwraps_bracketed_ipv6_and_optional_ports() {
        assert_eq!(split_redirect("http://127.0.0.1:7777/cb"), Some(("http", "127.0.0.1")));
        assert_eq!(split_redirect("http://localhost/cb"), Some(("http", "localhost")));
        assert_eq!(split_redirect("http://[::1]:7777/cb"), Some(("http", "::1")));
        assert_eq!(split_redirect("http://[::1]"), Some(("http", "::1")));
        assert_eq!(split_redirect("https://example.com"), Some(("https", "example.com")));
        assert_eq!(split_redirect("not a url"), None);
    }

    #[test]
    fn a_device_authorization_response_is_parsed_with_the_rfc_defaults() {
        let body = serde_json::json!({
            "device_code": "dc-1",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
        });
        let d = DeviceAuthorization::parse(&body).unwrap();
        assert_eq!(d.device_code, "dc-1");
        assert_eq!(d.user_code, "WDJB-MJHT");
        // RFC 8628 §3.2 defaults when the provider omits them.
        assert_eq!(d.interval, Duration::from_secs(5));
        assert_eq!(d.expires_in, Duration::from_secs(1800));
        assert!(d.verification_uri_complete.is_none());
    }

    #[test]
    fn googles_verification_url_spelling_is_accepted() {
        // Google sends `verification_url`, not the RFC's `verification_uri`. Rejecting it
        // would fail with "no verification_uri" against a very common provider.
        let body = serde_json::json!({
            "device_code": "dc-1",
            "user_code": "ABCD",
            "verification_url": "https://www.google.com/device",
            "verification_url_complete": "https://www.google.com/device?user_code=ABCD",
            "interval": 10,
            "expires_in": 600,
        });
        let d = DeviceAuthorization::parse(&body).unwrap();
        assert_eq!(d.verification_uri, "https://www.google.com/device");
        assert_eq!(
            d.verification_uri_complete.as_deref(),
            Some("https://www.google.com/device?user_code=ABCD")
        );
        assert_eq!(d.interval, Duration::from_secs(10));
    }

    #[test]
    fn a_device_response_missing_the_user_code_is_an_error() {
        let body = serde_json::json!({"device_code": "dc", "verification_uri": "https://x"});
        assert!(DeviceAuthorization::parse(&body).is_err());
    }

    #[test]
    fn an_enrolment_that_yields_no_refresh_token_says_to_ask_for_offline_access() {
        // The most common first-attempt failure: the provider completes the flow but issues
        // only an access token, so nothing survives a restart. "no refresh_token" alone would
        // leave an operator with nowhere to go.
        let dir = std::env::temp_dir().join(format!("marshal-enrol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = interactive(Grant::Enrolled, Some(dir));
        let response = TokenResponse::parse(&serde_json::json!({
            "access_token": "at-1", "expires_in": 3600
        }))
        .unwrap();
        let err = s.store_enrolment(response).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("offline"), "{msg}");
    }

    #[test]
    fn a_completed_enrolment_stores_the_refresh_token_and_caches_the_access_token() {
        let dir = std::env::temp_dir().join(format!(
            "marshal-enrol-ok-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let s = interactive(Grant::Enrolled, Some(dir.clone()));
        let response = TokenResponse::parse(&serde_json::json!({
            "access_token": "at-1",
            "refresh_token": "rt-1",
            "expires_in": 3600,
            "scope": "offline_access read:things",
        }))
        .unwrap();
        let enrolled = s.store_enrolment(response).unwrap();
        assert_eq!(enrolled.scope.as_deref(), Some("offline_access read:things"));

        // Survives a restart, which is the whole reason it went to disk.
        let restarted = TokenStore::new(Some(dir));
        assert_eq!(restarted.grant("SERVICE").unwrap().unwrap().refresh_token.expose(), "rt-1");
        // And the access token that came with it is usable immediately, no second round trip.
        assert_eq!(s.cached().unwrap().expose(), "at-1");
    }

    #[test]
    fn a_token_endpoint_that_is_not_a_url_is_refused_at_construction() {
        let err = Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: "auth.example.com/token".into(),
                client_id: "marshal".into(),
                client_auth: ClientAuth::None,
                grant: Grant::ClientCredentials,
                scope: vec![],
                audience: None,
                extra_params: BTreeMap::new(),
                expiry_skew: Duration::from_secs(60),
                authorization_endpoint: None,
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(None)),
            marshal_http::default_tls_config(),
            None,
            Redactor::default(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("token_endpoint"), "{err}");
    }

    #[test]
    fn the_source_name_is_the_swap_name_and_never_a_value() {
        let s = source(Grant::ClientCredentials, ClientAuth::None);
        assert_eq!(SecretSource::name(&s), "SERVICE");
        let debug = format!("{s:?}");
        assert!(debug.contains("SERVICE"));
        assert!(debug.contains("client_credentials"));
        // Nothing in Debug should be able to carry a resolved value.
        let _ = EnvSource::new("UNUSED");
    }
}
