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

use super::store::{StoredGrant, TokenStore, now_unix};
use super::token::{CachedToken, TokenResponse, describe_error};

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
}

impl Grant {
    fn label(&self) -> &'static str {
        match self {
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken { .. } => "refresh_token",
            Self::Enrolled => "enrolled",
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
            Grant::ClientCredentials => Ok(None),
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

    /// Build the form body and the client-authentication header for one token request.
    async fn token_request(&self) -> Result<(String, Vec<(String, String)>)> {
        let mut params: Vec<(String, String)> = Vec::new();
        let refresh = self.refresh_token().await?;

        match &refresh {
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

        let mut headers: Vec<(String, String)> = Vec::new();
        match &self.cfg.client_auth {
            ClientAuth::None => {
                params.push(("client_id".into(), self.cfg.client_id.clone()));
            }
            ClientAuth::ClientSecretPost { secret } => {
                params.push(("client_id".into(), self.cfg.client_id.clone()));
                params.push(("client_secret".into(), secret.resolve().await?.expose().to_owned()));
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

        for (k, v) in &self.cfg.extra_params {
            params.push((k.clone(), v.clone()));
        }

        let form = form_urlencode(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        Ok((form, headers))
    }

    /// One round trip to the token endpoint, and everything that must happen before the
    /// resulting access token is allowed to escape this function.
    async fn mint(&self) -> Result<SecretValue> {
        let (form, headers) = self.token_request().await?;
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
                "minting the `{}` credential from {}: {e}",
                self.name, self.cfg.token_endpoint
            ))
        })?;

        if !status.is_success() {
            return Err(Error::Config(format!(
                "minting the `{}` credential from {}: {}",
                self.name,
                self.cfg.token_endpoint,
                describe_error(status, &body)
            )));
        }

        let response = TokenResponse::parse(&body)?;

        // Learn before anything else can see the value. The redactor is the only thing
        // standing between a minted token and the audit log, and every path out of this
        // function leads somewhere that writes.
        self.redactor.learn(&self.name, response.access_token.expose());
        if let Some(rt) = &response.refresh_token {
            self.redactor.learn(&self.name, rt.expose());
        }

        self.persist_rotation(&response)?;

        let token = CachedToken::new(
            response.access_token.clone(),
            response.expires_in,
            self.cfg.expiry_skew,
        );
        let cacheable = token.is_live();
        self.store.put_access(&self.name, token);

        tracing::info!(
            secret = %self.name,
            grant = self.cfg.grant.label(),
            expires_in_secs = response.expires_in.map(|d| d.as_secs()),
            cached = cacheable,
            "minted an oauth2 access token"
        );

        Ok(response.access_token)
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
            Grant::ClientCredentials => Ok(()),
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
