# Architecture decision records

An ADR records **a decision that was hard to make and would be expensive to reverse**, along
with the context that made it the right call and the consequences accepted in taking it.

The point is not to document what the code does — the rest of [docs/](../) does that, and it
stays current as the code changes. The point is to answer *"why is it like this?"* a year
later, so a future change is made knowingly rather than by accident.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions in ADRs | Accepted |
| [0002](0002-workspace-with-a-dependency-free-core.md) | A workspace with a dependency-free core crate | Accepted |
| [0003](0003-policy-as-a-short-circuiting-chain.md) | Policy is an ordered, short-circuiting chain carrying evidence | Accepted |
| [0004](0004-default-deny-lives-in-config.md) | Default-deny lives in config, not in code | Accepted |
| [0005](0005-rustls-and-a-split-http-stack.md) | rustls, and a deliberately split HTTP stack | Accepted |
| [0006](0006-cel-for-the-rules-layer.md) | CEL for the rules layer, not a general scripting language | Accepted |
| [0007](0007-bodies-stream-by-default.md) | Bodies stream by default; buffering must be declared | Accepted |
| [0008](0008-interception-is-mandatory.md) | TLS interception is mandatory, not a fallback | Accepted |
| [0009](0009-identity-is-derived-from-the-connection.md) | Identity is derived from the connection, never asserted | Accepted |
| [0010](0010-resolve-once-connect-to-the-checked-address.md) | Resolve once, check every address, connect to the checked one | Accepted |
| [0011](0011-secrets-are-injected-at-the-boundary.md) | Secrets are injected at the boundary, not held by the agent | Accepted |
| [0012](0012-the-judge-sees-data-never-instructions.md) | The judge sees a reduced request as data, never as instruction | Accepted |
| [0013](0013-mcp-denials-are-protocol-errors.md) | MCP denials are protocol errors, and `tools/list` is filtered | Accepted |
| [0014](0014-netns-isolation-without-cap-net-admin.md) | Network-namespace isolation without `CAP_NET_ADMIN` | Accepted |
| [0015](0015-the-cgroup-name-is-the-registration.md) | The cgroup naming convention *is* the identity registration | Accepted |
| [0016](0016-config-splits-by-convention.md) | Config splits by fixed directory convention, not include globs | Accepted |
| [0017](0017-the-fallback-profile-is-embedded.md) | The fallback profile is embedded, unnamed, and unreferenceable | Accepted |
| [0018](0018-profiles-do-not-inherit.md) | Profiles do not inherit | Accepted |
| [0019](0019-log-detail-sink-and-format-are-independent.md) | Log detail, sink and format are three independent axes | Accepted |
| [0020](0020-reload-builds-everything-before-swapping.md) | Reload builds everything before swapping; a failure changes nothing | Accepted |
| [0021](0021-identity-not-session.md) | "Identity", not "session" | Accepted |
| [0022](0022-remove-transparent-capture.md) | Remove transparent (nftables REDIRECT) capture | Accepted |
| [0023](0023-multi-port-explicit-listeners.md) | Multi-port explicit listeners, to restore `listener_port` identity | Accepted |
| [0024](0024-netns-binds-an-explicit-allowlist.md) | `netns` isolation binds an explicit allowlist, not the whole host root | Accepted |
| [0025](0025-basic-auth-aware-secret-injection.md) | Secret injection understands `Basic` auth, with no new config | Superseded by [0027](0027-secret-injection-is-unconditional-only.md) |
| [0026](0026-blind-credential-injection.md) | Blind credential injection, for a client that presents nothing | Accepted |
| [0027](0027-secret-injection-is-unconditional-only.md) | Secret injection is unconditional injection only | Accepted |

## Writing a new one

Copy [`template.md`](template.md) to `NNNN-a-short-imperative-title.md`, taking the next free
number. Add a row to the index above.

**Write one when:** a choice constrains future work, closes off an obvious alternative, trades
one desirable property for another, or is likely to look wrong to someone who wasn't there.

**Don't write one for:** anything the code or the rest of the docs already states plainly, a
choice with an obvious default and no trade-off, or an implementation detail that could change
next week without anyone noticing.

## Keeping them current

**ADRs are immutable once accepted.** Do not rewrite the reasoning of a decision to match what
you now believe — that erases exactly the history the record exists to preserve.

When a decision changes:

1. Write a **new** ADR describing the new decision, with a `Supersedes: ADR-NNNN` line.
2. Edit the old one's **Status** to `Superseded by ADR-MMMM`, linking to it. That status
   line is the only part of an accepted ADR that may change.
3. Update the index table.

Correcting a typo or a broken link is fine. Changing the Context, Decision or Consequences of
an accepted ADR is not.

If a decision is under discussion but not settled, write it with `Status: Proposed` and say
what would decide it. If it is abandoned before implementation, mark it `Rejected` and keep
it — knowing an option was considered and refused is worth as much as knowing one was taken.

See [AGENTS.md](../../AGENTS.md) for when a change needs an ADR alongside its code.
