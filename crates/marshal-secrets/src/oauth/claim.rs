//! A secret sourced from another OAuth2 swap's ID token, not its access token.
//!
//! Most providers put everything a resource server needs in the access token itself, so
//! `scope: bearer` on the OAuth2 source is the whole story. Some do not: OpenAI's ChatGPT
//! sign-in issues an access token that authenticates *a session*, and expects a second header —
//! `ChatGPT-Account-ID` — naming which of that account's workspaces the request is for, taken
//! from a claim in the ID token the same response carried. A resource server that only sees the
//! bearer token 401s with "missing scopes" even though the token itself is perfectly live,
//! because from its side there is no scope to grant until it knows which account.
//!
//! This is not specific to that one provider's shape, so it is not hard-coded to it: the claim
//! path is configuration, and any provider that hands out routing information this way — in a
//! second token, addressed by a claim path rather than a top-level field — is the same shape.

use std::sync::Arc;

use marshal_core::{Error, Result, SecretSource, SecretValue};

use super::source::Oauth2Source;

/// Reads a string out of an ID token's claims, at a dotted path of object keys.
///
/// A path, not a single key, because the provider that motivated this — see the module doc —
/// nests the value inside a claim namespaced by a URL (`https://api.openai.com/auth` →
/// `chatgpt_account_id`). A list of keys sidesteps the escaping a single dotted string or a
/// JSON Pointer would need for a key that itself contains `.` or `/`.
#[derive(Debug)]
pub struct OauthClaimSource {
    name: String,
    of: Arc<Oauth2Source>,
    claim_path: Vec<String>,
    redactor: marshal_core::Redactor,
}

impl OauthClaimSource {
    pub fn new(
        name: impl Into<String>,
        of: Arc<Oauth2Source>,
        claim_path: Vec<String>,
        redactor: marshal_core::Redactor,
    ) -> Self {
        Self { name: name.into(), of, claim_path, redactor }
    }
}

/// Walk `path` into `claims`, erroring with the exact key that had nothing under it — an
/// operator who copied a claim path wrong needs to know which segment, not just that lookup
/// failed somewhere in it.
fn walk<'a>(
    claims: &'a serde_json::Value,
    of: &str,
    path: &[String],
) -> Result<&'a serde_json::Value> {
    let mut value = claims;
    let mut walked = Vec::with_capacity(path.len());
    for key in path {
        walked.push(key.as_str());
        value = value.get(key).ok_or_else(|| {
            Error::Config(format!("`{of}`'s ID token has no claim at `{}`", walked.join(".")))
        })?;
    }
    Ok(value)
}

impl OauthClaimSource {
    /// Shared by `resolve` and `preload`: given the claims object, walk to the configured path,
    /// require a string, and teach the redactor. The only difference between the two callers is
    /// *how* they got the claims — a real mint for `resolve`, only what is already cached for
    /// `preload`.
    fn extract(&self, claims: &serde_json::Value) -> Result<SecretValue> {
        let value = walk(claims, self.of.name(), &self.claim_path)
            .map_err(|e| Error::Config(format!("`{}`: {e}", self.name)))?;
        let found = value.as_str().ok_or_else(|| {
            Error::Config(format!(
                "`{}`: the claim at `{}` in `{}`'s ID token is not a string",
                self.name,
                self.claim_path.join("."),
                self.of.name()
            ))
        })?;

        // Not the credential itself, but it identifies an account, and this is the one place
        // it is ever read out of a token — the same reasoning as every other value the
        // redactor learns at runtime (ADR-0029).
        self.redactor.learn(&self.name, found);
        Ok(SecretValue::new(found))
    }
}

#[async_trait::async_trait]
impl SecretSource for OauthClaimSource {
    fn name(&self) -> &str {
        &self.name
    }

    /// Only what `of` already has cached — never mints. `of`'s own `preload` exists for exactly
    /// this reason (ADR-0030): without this override, the trait's default (`resolve`) would
    /// mint `of`'s credential at startup just to seed this source's, the moment either is
    /// registered in the same injector.
    async fn preload(&self) -> Result<Option<SecretValue>> {
        let Some(claims) = self.of.cached_id_token_claim()? else { return Ok(None) };
        Ok(Some(self.extract(&claims)?))
    }

    async fn resolve(&self) -> Result<SecretValue> {
        let claims = self.of.id_token_claim().await?.ok_or_else(|| {
            Error::Config(format!(
                "`{}` reads a claim from `{}`'s ID token, but that swap's provider issued no \
                 `id_token` alongside its access token",
                self.name,
                self.of.name()
            ))
        })?;
        self.extract(&claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_a_nested_namespaced_claim() {
        let claims = serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "acct-123" }
        });
        let path = vec!["https://api.openai.com/auth".to_owned(), "chatgpt_account_id".to_owned()];
        let found = walk(&claims, "CODEX_SUBSCRIPTION", &path).unwrap();
        assert_eq!(found.as_str(), Some("acct-123"));
    }

    #[test]
    fn a_missing_segment_names_exactly_the_path_walked_so_far() {
        let claims = serde_json::json!({
            "https://api.openai.com/auth": { "chatgpt_user_id": "u-1" }
        });
        let path = vec!["https://api.openai.com/auth".to_owned(), "chatgpt_account_id".to_owned()];
        let err = walk(&claims, "CODEX_SUBSCRIPTION", &path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("https://api.openai.com/auth.chatgpt_account_id"), "{msg}");
    }

    #[test]
    fn a_missing_first_segment_does_not_walk_past_it() {
        let claims = serde_json::json!({ "email": "a@example.com" });
        let path = vec!["https://api.openai.com/auth".to_owned(), "chatgpt_account_id".to_owned()];
        let err = walk(&claims, "CODEX_SUBSCRIPTION", &path).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("https://api.openai.com/auth"), "{msg}");
        assert!(!msg.contains("chatgpt_account_id"), "{msg}");
    }
}
