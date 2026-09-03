# ADR 0027: Secret injection is unconditional injection only

* **Status:** Accepted
* **Date:** 2026-09-03
* **Supersedes:** [ADR-0025](0025-basic-auth-aware-secret-injection.md) entirely, and the
  placeholder half of [ADR-0011](0011-secrets-are-injected-at-the-boundary.md)

## Context

The placeholder model ([ADR-0011](0011-secrets-are-injected-at-the-boundary.md)) needed the
client to cooperate: hold a stand-in value, present it somewhere in the request, and trust the
proxy to find and replace it. [ADR-0025](0025-basic-auth-aware-secret-injection.md) taught that
matching to also decode a `Basic` challenge, because the placeholder is often base64-encoded
before it ever reaches the wire. [ADR-0026](0026-blind-credential-injection.md) then added a
second mode, `Inject`, for the client that presents nothing at all — most of git, package
registries, and container registries in practice — alongside the placeholder model rather than
replacing it.

Once `Inject` existed, scoped by the same `rules` host matcher `Placeholder` used, the
placeholder model's only remaining property was narrower than it first appears: within an
*already-allowed* host, it additionally required the specific request to have tried to
authenticate before the credential was attached. Every actual security boundary — which hosts
can receive the credential at all — was already the chain's allowlist plus `rules`, identical
for both modes. Keeping two modes bought a shrinking benefit (some request-level filtering
within an allowed host) for a large amount of remaining complexity: `MatchSites`, `require`,
the base64 decode/re-encode path, four config fields, and the question of which one to reach
for.

## Decision

`SwapKind::Placeholder` is removed entirely, along with `MatchSites`, `header_contains`,
`replace_in_header`, `decode_basic`, `base64_decode`, and the `proxy_value` /
`match_headers` / `match_body` / `match_query` / `require` config fields. `Injection`
(previously `SwapKind::Inject`'s payload) is the only mode there is — `SecretSwap` now holds
`injection: Injection` directly, not a choice between two kinds:

```yaml
request_transforms:
  secrets:
    - name: GIT_TOKEN
      source: { type: env, var: GIT_TOKEN }
      inject: { type: basic, username: "x-access-token" }
      rules: [{ host: "github.com" }]
```

`inject` is a required field now, not one of two mutually exclusive options — there is only
one thing a swap can mean. Every request the chain allows to a `rules`-matched host gets
`Authorization` set to the configured credential, unconditionally, replacing whatever the
client sent (usually nothing). A config still using `proxy_value` or any of the `match_*`
fields now fails to parse with an unknown-field error, not a silent no-op.

`Injection::Bearer` (`Authorization: Bearer {secret}`) is added alongside `Basic`, covering the
case the old plain-substring placeholder mode handled — a bare API token — so nothing already
expressible is lost.

## Alternatives considered

**Keep both modes.** What existed immediately before this ADR. Rejected on reflection: the
security boundary two modes offered was already provided by `rules` alone in both cases, so
the second mode's cost (config surface, code, the decision of which to reach for) was no
longer buying a proportionate benefit.

**Keep only `Placeholder`, drop `Inject`.** Rejected for the reason ADR-0026 gave in the first
place: most of git, package registries, and container registries never present anything to
swap, so this mode alone cannot express those cases at all.

## Consequences

**Simpler on every axis that matters:** the config schema drops from seven interacting fields
(`proxy_value`, `match_headers`, `match_body`, `match_query`, `require`, plus `inject` chosen
against all of them) to two required ones (`source`, `inject`); `swap.rs` drops from roughly
340 lines to under 150; there is exactly one question to answer when writing a swap — *what*
to inject — not also *how* the client will present it.

**A real, deliberate loss of granularity, accepted as not worth what it cost.** Every allowed
request to a scoped host is now authenticated, with no way to additionally require that the
specific request was trying to authenticate. `rules` is the entire boundary — scope it to the
actual credentialed endpoint, not the whole domain a tool happens to talk to, exactly as
[ADR-0026](0026-blind-credential-injection.md) already required of `Inject` swaps and now
requires of all of them.

**Breaking change.** Any config written against the placeholder model — including this
project's own shipped `config/profiles/coding-agent.yaml`, updated alongside this ADR — must
be rewritten to `inject:`. There is no compatibility shim; `deny_unknown_fields` makes the old
shape fail loudly at config-build time rather than silently doing nothing.
