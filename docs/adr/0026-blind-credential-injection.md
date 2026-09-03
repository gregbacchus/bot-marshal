# ADR 0026: Blind credential injection, for a client that presents nothing

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

[ADR-0011](0011-secrets-are-injected-at-the-boundary.md) chose a placeholder model over blind
injection specifically because blind injection is strictly weaker: the proxy adding
`Authorization` to every request to a host means any request the agent can be tricked into
making becomes an authenticated one, rather than only ones it specifically constructed to
carry a credential.

That reasoning holds, and doesn't cover every real case. A cooperating client — one written to
send a placeholder somewhere in the request — is the assumption the whole model rests on. Many
of the clients an agent actually shells out to are not cooperating, because they have no idea
authentication is happening at all: an anonymous `git clone`, a `docker pull` against a
registry the image happens to require a token for, an `npm install` against a private
registry the agent was never told needs a credential. There is no placeholder to send because
the tool was never given one to send, and often has no supported way to be told to send one at
a spot the boundary could intercept.

[ADR-0025](0025-basic-auth-aware-secret-injection.md) closed the gap for a client that *does*
send something, just encoded. It does nothing for a client that sends nothing.

## Decision

A second, independent swap mode, `SwapKind::Inject`, alongside — not replacing —
`SwapKind::Placeholder`. Chosen per swap in config, with no ambiguity between the two:

```yaml
request_transforms:
  secrets:
    - name: GIT_TOKEN
      source: { type: env, var: GIT_TOKEN }
      inject: { type: basic, username: "x-access-token" }
      rules: [{ host: "github.com" }]
```

Every request the policy chain allows to `github.com` gets `Authorization: Basic
base64("x-access-token:<secret>")` set unconditionally — overwriting whatever the client sent,
if anything. There is no placeholder, no `match_headers`, no `require`: nothing to match
against, because nothing is being looked for in the request. `git clone
https://github.com/owner/repo`, with no credential in the URL at all, now authenticates.

`inject` and `proxy_value` are mutually exclusive on one swap, and `match_headers`/
`match_body`/`match_query`/`require` are rejected at config-build time if set alongside
`inject` — each would silently do nothing, and a knob that silently does nothing is worse than
one that doesn't parse.

## Alternatives considered

**Only ship `Placeholder`, and document that some clients need a wrapper script to inject a
placeholder into the URL or config file first.** Technically sufficient for git (whose
credential can be embedded in the clone URL) and unworkable for tools with no equivalent hook
— `docker pull` has no field to put a credential in for an anonymous-looking pull, and asking
every profile author to write a wrapper per tool defeats the point of a boundary that is
supposed to need no client cooperation.

**Make `Placeholder` always fall back to blind injection when `require` is set and the
placeholder never shows up.** Rejected: that makes the strength of a swap depend on what a
particular request happened to contain, which is exactly the kind of implicit behaviour this
project avoids elsewhere — a swap's trust model should be legible from its config, not
inferred per-request.

## Consequences

**This is the trade-off ADR-0011 chose against, now available as an explicit opt-in.** Within
an `Inject` swap's host scope, the credential is not conditional on the agent doing anything in
particular — every allowed request gets it. The chain's allowlist for that host is now the
*entire* boundary for who can use the credential, not allowlist-plus-placeholder. An operator
reaching for `inject` is choosing that trade-off for a specific host, deliberately, because the
client genuinely cannot present a placeholder — not as a default or a fallback.

This makes host scoping (`rules`) more load-bearing for an `Inject` swap than for a
`Placeholder` one: get the host list too broad and every request to it is now silently
authenticated, with nothing in the request itself hinting that. Keep `Inject` swaps scoped as
narrowly as the actual credentialed endpoint, not the whole domain a tool happens to talk to.

`Inject` swaps have no placeholder to seed `SecretInjector::proxy_values()` with, so nothing
about them changes what the redactor or the audit trail's placeholder-vs-real distinction does
for `Placeholder` swaps — `secrets.injected.<name>` in the evidence trail is the only trace,
same shape as `secrets.swapped.<name>`, the name only, never the value.
