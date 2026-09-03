//! What a token endpoint says, and what marshal keeps of it.

use std::time::{Duration, Instant};

use marshal_core::{Error, Result, SecretValue};

/// The success shape of an OAuth2 token response
/// ([RFC 6749 §5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1)), normalised.
#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: SecretValue,
    pub expires_in: Option<Duration>,
    /// Present when the grant issues one, and *replaced* rather than added to when a provider
    /// rotates it. Losing this value on rotation kills the credential permanently, which is
    /// why the store persists it before the token it came with is ever returned.
    pub refresh_token: Option<SecretValue>,
    /// What was actually granted, which can be narrower than what was asked for.
    pub scope: Option<String>,
}

impl TokenResponse {
    /// Parse a `200` body from a token endpoint.
    ///
    /// `token_type` is deliberately not enforced. It is `Bearer` in every case this supports,
    /// providers spell it inconsistently (`bearer`, `Bearer`, occasionally absent), and how
    /// the credential is presented is the injection kind's business, not this parser's.
    pub fn parse(body: &serde_json::Value) -> Result<Self> {
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::Config(
                    "the token endpoint returned 200 with no `access_token` field".to_owned(),
                )
            })?;

        // `expires_in` is seconds, and is optional: a provider that omits it is saying the
        // token does not self-describe its lifetime, not that it lives forever.
        let expires_in = body.get("expires_in").and_then(|v| v.as_u64()).map(Duration::from_secs);

        Ok(Self {
            access_token: SecretValue::new(access_token),
            expires_in,
            refresh_token: body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(SecretValue::new),
            scope: body.get("scope").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }
}

/// The error shape ([RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.2)),
/// rendered for an operator.
///
/// Worth its own function because `error_description` is very often the only thing that says
/// what is actually wrong — "invalid_client" alone does not distinguish a typo'd client id
/// from an expired secret.
pub fn describe_error(status: http::StatusCode, body: &serde_json::Value) -> String {
    match body.get("error").and_then(|v| v.as_str()) {
        Some(code) => match body.get("error_description").and_then(|v| v.as_str()) {
            Some(desc) => format!("{status}: {code}: {desc}"),
            None => format!("{status}: {code}"),
        },
        None => format!("{status}"),
    }
}

/// An access token held in memory, with the moment it stops being usable.
///
/// `Instant`, not a wall clock: expiry is a duration from when the token was issued, and a
/// monotonic clock is the only one a step change in system time cannot make wrong in the
/// direction that matters (believing an expired token is still live).
#[derive(Debug, Clone)]
pub struct CachedToken {
    pub value: SecretValue,
    /// `None` when the provider gave no `expires_in`. Such a token is used once and never
    /// cached — see [`CachedToken::is_live`].
    pub expires_at: Option<Instant>,
}

impl CachedToken {
    /// Build from a response, subtracting `skew` from the stated lifetime.
    ///
    /// The skew is what stops a token expiring in flight: a token with three seconds left
    /// passes any check made before the request is sent and is still refused by the API by
    /// the time it arrives. Subtracting a margin turns that race into an early refresh.
    pub fn new(value: SecretValue, expires_in: Option<Duration>, skew: Duration) -> Self {
        let expires_at = expires_in.map(|ttl| Instant::now() + ttl.saturating_sub(skew));
        Self { value, expires_at }
    }

    /// Whether this token can still be handed out.
    ///
    /// A token with no stated expiry is never live *as a cache entry*. Treating it as
    /// immortal would mean a revoked or rotated credential is never re-fetched, and the
    /// failure mode is invisible: every request 401s and nothing re-mints. Minting again is
    /// the cheap, correct answer.
    pub fn is_live(&self) -> bool {
        match self.expires_at {
            Some(at) => Instant::now() < at,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_token_response() {
        let body = serde_json::json!({"access_token": "at-1", "token_type": "Bearer"});
        let t = TokenResponse::parse(&body).unwrap();
        assert_eq!(t.access_token.expose(), "at-1");
        assert!(t.expires_in.is_none());
        assert!(t.refresh_token.is_none());
    }

    #[test]
    fn parses_expiry_and_a_rotated_refresh_token() {
        let body = serde_json::json!({
            "access_token": "at-2",
            "expires_in": 3600,
            "refresh_token": "rt-new",
            "scope": "read write",
        });
        let t = TokenResponse::parse(&body).unwrap();
        assert_eq!(t.expires_in, Some(Duration::from_secs(3600)));
        assert_eq!(t.refresh_token.unwrap().expose(), "rt-new");
        assert_eq!(t.scope.as_deref(), Some("read write"));
    }

    #[test]
    fn a_200_with_no_access_token_is_an_error_not_an_empty_credential() {
        // Injecting `Authorization: Bearer ` would be worse than failing: the request goes
        // out, gets a 401, and nothing says why.
        let body = serde_json::json!({"token_type": "Bearer"});
        assert!(TokenResponse::parse(&body).is_err());
        let empty = serde_json::json!({"access_token": ""});
        assert!(TokenResponse::parse(&empty).is_err());
    }

    #[test]
    fn a_token_type_this_does_not_recognise_is_not_rejected() {
        let body = serde_json::json!({"access_token": "at", "token_type": "MAC"});
        assert!(TokenResponse::parse(&body).is_ok());
    }

    #[test]
    fn error_descriptions_carry_the_detail_an_operator_needs() {
        let body =
            serde_json::json!({"error": "invalid_client", "error_description": "bad secret"});
        assert_eq!(
            describe_error(http::StatusCode::BAD_REQUEST, &body),
            "400 Bad Request: invalid_client: bad secret"
        );
        let bare = serde_json::json!({"error": "invalid_grant"});
        assert_eq!(
            describe_error(http::StatusCode::BAD_REQUEST, &bare),
            "400 Bad Request: invalid_grant"
        );
        assert_eq!(
            describe_error(http::StatusCode::BAD_GATEWAY, &serde_json::json!({})),
            "502 Bad Gateway"
        );
    }

    #[test]
    fn the_skew_expires_a_token_before_the_provider_does() {
        let t = CachedToken::new(
            SecretValue::new("at"),
            Some(Duration::from_secs(30)),
            Duration::from_secs(60),
        );
        // 30s lifetime, 60s skew: already past it, so never handed out.
        assert!(!t.is_live());
    }

    #[test]
    fn a_token_with_a_real_lifetime_is_live() {
        let t = CachedToken::new(
            SecretValue::new("at"),
            Some(Duration::from_secs(3600)),
            Duration::from_secs(60),
        );
        assert!(t.is_live());
    }

    #[test]
    fn a_token_with_no_stated_expiry_is_never_cached() {
        let t = CachedToken::new(SecretValue::new("at"), None, Duration::from_secs(60));
        assert!(!t.is_live());
    }
}
