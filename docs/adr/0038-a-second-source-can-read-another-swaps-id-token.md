# ADR 0038: A second source can read another swap's ID token

* **Status:** Accepted
* **Date:** 2026-09-06

## Context

[ADR-0030](0030-oauth2-is-a-secret-source.md) settled OAuth2 on the assumption that everything
a resource server needs travels in the access token. Most providers satisfy that assumption.
OpenAI's ChatGPT sign-in does not: its access token authenticates *a session*, and the resource
server additionally requires a `ChatGPT-Account-ID` header naming which of that session's
workspaces a request is for. That value is not in the access token, in `scope`, or anywhere
`TokenResponse` previously parsed — it is a claim (`chatgpt_account_id`, nested under a claim
namespaced `https://api.openai.com/auth`) inside a separate `id_token` the same token response
carries, which marshal discarded entirely.

Without it, a swap injecting only `Authorization: Bearer` produces a request the resource
server 401s with "missing scopes" — a response that reads exactly like a scope problem with the
access token itself, and is not: the token is live, current, and was minted correctly. The
actual failure is downstream of anything an OAuth2 source models today. This was diagnosed by
comparing marshal's request against [the real client's own auth code](https://github.com/openai/codex/blob/main/codex-rs/model-provider/src/bearer_auth_provider.rs),
which sends the account id as a second header derived from exactly this claim.

This is not one provider's idiosyncrasy to special-case. Any provider that hands out routing
information this way — a second token, addressed by a claim path rather than a top-level
field — has the identical shape, and a resource server checking for it will fail exactly the
same way regardless of which provider issued the claim.

## Decision

`TokenResponse` now parses `id_token` when the provider sends one, and `CachedToken` carries it
alongside the access token it arrived with — same lifetime, same cache entry, because it is not
separately re-derivable once the access token it came with is gone.

A new `SecretSource`, `OauthClaimSource` (`type: oauth2_claim` in config), reads a value out of
another `oauth2` swap's cached ID token rather than minting a credential of its own. It composes
with `Injection::Header` — or any other kind — exactly like every other source, which is what
makes the second header an ordinary swap rather than a special case bolted onto `Oauth2Source`:

```yaml
- name: CODEX_ACCOUNT_ID
  source:
    type: oauth2_claim
    of: CODEX_SUBSCRIPTION
    claim: ["https://api.openai.com/auth", "chatgpt_account_id"]
  inject: { type: header, name: ChatGPT-Account-ID }
  rules: [{ host: "api.openai.com" }]
```

`claim` is a list of object keys, not a dotted string or a JSON Pointer — the claim namespace
here is itself a URL, and a list sidesteps the escaping either alternative would need for a key
containing `.` or `/`. `of` must name a swap earlier in `secrets:`: config is built top to
bottom, and the claim source holds an `Arc` to the *same* `Oauth2Source` instance the other swap
built, so reading the claim triggers that swap's own mint-and-cache path rather than an
independent one. Two swaps needing the same provider now share one token lifecycle instead of
each minting (and separately rotating) their own copy of it.

The ID token's signature is not verified. There is nothing to verify it against that matters
here: it was not presented by a client asking marshal to trust it, it came back from the
provider's own token endpoint over the TLS connection marshal itself just made. Reading one
field out of it needs a base64 decode, not a signature check — a genuine relaxation from every
other place this codebase touches a JWT ([`marshal-secrets/src/oauth/jwt.rs`](../../crates/marshal-secrets/src/oauth/jwt.rs) both signs and
verifies), justified only because the trust boundary here is "did the provider's TLS connection
say this," not "did the presenting party prove possession."

## Alternatives considered

**Hard-code `chatgpt_account_id` and a `ChatGPT-Account-ID` header directly into
`Oauth2Source`/`Injection::Bearer`.** Fixes the one case in hand fastest. Rejected: it puts a
single provider's claim shape into a general-purpose credential mechanism, and the next
provider with the same shape under a different claim name and header would need its own
special case rather than reusing this one.

**Extend `Injection::Bearer` to carry an optional companion header sourced from the same
`oauth2` config.** Keeps everything on one swap instead of two. Rejected: it conflates "how a
credential is presented" with "where a second, unrelated value comes from," which is exactly
the source/kind split ADR-0030 exists to preserve, and it would not compose with providers that
want the claim in a query parameter or a different injection kind entirely.

**A JSON Pointer for `claim` instead of a list of keys.** More standard, and reuses an existing
RFC rather than inventing a shape. Rejected because the claim namespace this needed to express —
`https://api.openai.com/auth` — contains both `.` and `/`, and RFC 6901 requires escaping `/` as
`~1`; a config author copying a claim name out of provider documentation would have to know to
mangle it first. A list of plain strings needs no escaping for any key.

## Consequences

**A claim source depends on ordering in `secrets:`.** Unlike every other source, `oauth2_claim`
is invalid if the swap it names has not been built yet, and the error names the ordering
requirement rather than something more generic like "swap not found" — but it is still a
new failure mode a config author has to learn, one that does not exist for `env` or `file`.

**One more thing a resource server's `401` can mean.** ADR-0031 already established that "did
not reach the upstream" is not one thing; this adds "an otherwise-correct token is missing a
claim-derived header the resource server silently requires," indistinguishable from an
actual scope problem in the response body without knowing this mechanism exists.

**The ID token is now something the redactor must learn, and the audit trail must never
show.** It carries an email address and other identifying claims in this provider's case, not
only the account id — a second surface for the same class of leak `TokenResponse` already
guards for the access and refresh tokens, now duplicated for a token most providers never even
issue.
