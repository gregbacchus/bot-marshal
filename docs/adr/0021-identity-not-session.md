# ADR 0021: "Identity", not "session"

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

The original design called the per-agent label a *session*: `SessionId`, `SessionResolver`, a
`sessions:` config block, a `session` field in every audit record.

The name was wrong, and in a way that misleads rather than merely reading oddly. A session, to
anyone arriving from HTTP or from agent frameworks, is **bounded**: it begins, it ends, it may
renew, and the same actor has many of them over time.

None of that describes this value. For `peer_cred`, `proxy_auth`, `source_ip` and
`listener_port`, the label is a fixed string an operator writes in a config file. It never
varies for the same uid, credential or CIDR. It does not begin, end, or renew. It names *the
agent*, permanently.

Only `launched` produces anything per-invocation, and even there the durable part is the
profile and the agent it identifies — the per-launch id is an instance discriminator on a
stable identity, not a session.

The practical cost: it invited the question "does this reset?", and it collided with the
agents' own notion of a session, which is a genuinely different thing this proxy has no view
of.

## Decision

Rename throughout. `SessionId` → `Identity`, `SessionResolver` → `IdentityResolver`,
`SessionRegistry` → `IdentityRegistry`, config `sessions:` → `identities:`, resolver entries'
`session:` → `identity:`.

Applied to every layer including the public interfaces, deliberately rather than by leaving
compatibility shims.

## Alternatives considered

**Keep `session` and document that it is permanent.** Cheapest, and it means every reader
learns the term means something other than what it says. Documentation does not outrun a name
that appears in every audit record.

**Rename internals, keep the config key and audit field.** Avoids the breaking change and
leaves the misleading term in exactly the two places users actually see.

**`principal`, `subject`, `actor`.** All defensible. `principal` and `subject` carry specific
meanings from other authorization systems that would import expectations this does not meet;
`identity` is the plainest description of what the value is.

## Consequences

Breaking changes, all at once and all user-visible:

| interface | before | after |
|---|---|---|
| config key | `sessions:` | `identities:` |
| resolver entry | `session: "agent-a"` | `identity: "agent-a"` |
| audit JSON field | `"session"` | `"identity"` |
| management endpoint | `GET /v1/sessions` | `GET /v1/identities` |
| Prometheus metric | `marshal_session_requests_total{session=...}` | `marshal_identity_requests_total{identity=...}` |

Anything consuming the audit log or scraping the metric breaks and must be updated. This was
accepted deliberately: the project is pre-1.0, and the cost of the rename only grows.

An old config now fails to load with a clear deserialisation error rather than silently
ignoring an unknown key, which is the right failure for a security control.

One `session` remains in the codebase and is correct: the TLS ClientHello's own `session_id`
field in `sniff.rs`, which is a wire-protocol term unrelated to any of this.
