# ADR 0039: OAuth2 can exchange a token before caching it

* **Status:** Accepted
* **Date:** 2026-09-06

## Context

[ADR-0038](0038-a-second-source-can-read-another-swaps-id-token.md) fixed one gap in OpenAI's
ChatGPT sign-in — a second header derived from an ID token claim — and it was not enough. The
grant's own access token, obtained by an ordinary `refresh_token` exchange, still 401s against
`api.openai.com` with a missing-scope error, even with that header attached, because the access
token itself is the wrong credential. [Codex CLI's own login server](https://github.com/openai/codex/blob/main/codex-rs/login/src/server.rs#L1137)
shows why: after the OAuth exchange, it makes a *second* call, an
[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) token exchange —

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=<client_id>
&requested_token=openai-api-key
&subject_token=<id_token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
```

— and stores *that* response's `access_token` as `openai_api_key`
([`manager.rs`](https://github.com/openai/codex/blob/main/codex-rs/login/src/auth/manager.rs#L309)), which
is what every subsequent API call actually presents. The grant's own access token authenticates
a ChatGPT session; the exchanged token is what the resource server checks scopes against. No
amount of header injection changes which token is in the `Authorization` header, and this
codebase had no way to say "mint, then hand the result to one more request before using it."

The failure mode this produces is worth naming, because it looks exactly like a scope
misconfiguration and is not one: a token that is live, correctly obtained, and would work fine
against the identity provider itself, refused by the resource server for a reason invisible
from marshal's side without knowing this second hop exists.

## Decision

`Oauth2Config` gains an optional `token_exchange: Option<TokenExchange>`. When set,
`Oauth2Source::mint` performs the ordinary grant as before, then immediately exchanges one of
its resulting tokens (`subject: id_token` or `subject: access_token`, `id_token` being what
OpenAI's flow needs) for a different one, and it is the *exchanged* token — not the grant's own
access token — that gets cached and handed to injection:

```yaml
source:
  type: oauth2
  grant: authorization_code
  token_endpoint: https://auth.openai.com/oauth/token
  client_id: app_EMoamEEZ73f0CkXaXp7hrann
  redirect_uri: https://auth.openai.com/deviceauth/callback
  client_auth: none
  token_exchange:
    subject: id_token
    extra_params: { requested_token: "openai-api-key" }
```

The exchange request reuses the same `client_auth` and the same `post_token` path as every
other token-endpoint call — same client authentication, same redaction, same timeout and
error-shape guarantees — because it is not a different kind of request, only a different
`grant_type` sent to the same endpoint. `extra_params` on the exchange (distinct from
`Oauth2Config`'s own `extra_params`, which apply to the *first* call) is the escape hatch for
providers, like this one, whose exchange deviates from the RFC's own `requested_token_type`
field.

The original response's `id_token` survives onto the cached, exchanged result rather than being
discarded — an [ADR-0038](0038-a-second-source-can-read-another-swaps-id-token.md) claim source
reads the session's claims, which have no reason to reappear in an API-key exchange response,
so losing them here would silently break that ADR's mechanism for any provider that also needs
this one.

## Alternatives considered

**Model this as a distinct grant type (`grant: token_exchange`) rather than a post-processing
step on every grant.** Rejected: the exchange is not itself how the initial credential was
obtained, it runs *after* whichever grant (`enrolled`, `refresh_token`, `client_credentials`,
...) produced a token — the two are orthogonal, and folding them into one grant would mean a
provider using `authorization_code` and one using `refresh_token`, both needing the same
exchange afterward, would need two near-duplicate grant variants that differ only in the step
this ADR adds.

**Do the exchange once, at enrolment, and persist the result like a refresh token.** Attractive
because it looks like OpenAI's own model — `codex login` exchanges once and stores
`openai_api_key` indefinitely. Rejected for now: nothing here establishes that the exchanged
token does not itself expire or rotate independently of the session token, and treating it as
mint-once would silently start serving a stale exchanged token the moment it does. Running the
exchange on every mint costs one extra request only as often as the underlying session token is
re-minted (governed by its own `expires_in` and the cache), which is the conservative default;
revisit if evidence shows the exchanged token is safe to treat as longer-lived than that.

**Hard-code the OpenAI shape into `Oauth2Source` instead of a general RFC 8693 hop.** Same
objection as ADR-0038's rejection of hard-coding the account-id header: the next provider that
issues a session token and expects an exchanged one is the same shape under a different
`requested_token` value, and a general mechanism costs no more code than a specific one here.

## Consequences

**Minting a credential with `token_exchange` set now costs two round trips to the token
endpoint, not one**, every time the cache misses. Both are bounded by the same `timeout` and
both fail closed the same way, but the first-request-after-expiry latency ADR-0030 already
accepted is now roughly doubled for any swap using this.

**A `token_exchange` failure and a grant failure look identical to whatever called `mint`** —
both surface as the swap's ordinary "could not obtain credential" refusal. An operator
diagnosing a 403 has to read which of the two `post_token` calls actually failed from the error
text (`"requesting"` vs `"exchanging the id token for"`), rather than from a distinct error
class.

**The exchanged token is what gets redacted and audited, the grant's own access token is not
kept anywhere past the exchange call.** This is the intended behaviour — the grant's own token
is not the credential in use — but it means a `marshal secrets oauth status` or similar
diagnostic showing "this swap's token" is showing the exchanged one, and an operator expecting
to see the session token (to debug the *first* call, say) has to know to look at the raw request
log instead.
