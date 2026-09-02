# ADR 0010: Resolve once, check every address, connect to the checked one

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Hostname policy is not address policy. A profile that allows `api.example.com` has said nothing
about where that name points, and the name is resolved by DNS the agent may influence.

The specific attack is DNS rebinding: a name resolves to a public address when policy checks
it, and to `169.254.169.254` — cloud metadata, holding instance credentials — when the
connection is actually made. Nothing in the config is wrong; the check and the connect simply
saw different answers.

The same gap appears without an attacker: a name with several A records can be checked on one
and connected on another.

## Decision

Resolve the hostname **once**. Check **every** resulting address against `upstream.deny_cidrs`
and `allow_private`. Connect **to a checked address**, never to a name.

There is no re-resolution between the check and the connect. This is stated as an invariant in
[AGENTS.md](../../AGENTS.md) because it is easy to reintroduce: any refactor that passes a
hostname to a connect call instead of a `SocketAddr` reopens it.

## Alternatives considered

**Check the hostname, connect by hostname.** The natural way to write it, and the bug.

**Check the first resolved address only.** Works for single-homed hosts and fails for
round-robin DNS, silently and intermittently.

**Rely on `deny_cidrs` at the OS firewall instead.** A sound defence in depth and not a
substitute: it cannot be configured per profile, and it is not present in every deployment.

## Consequences

The guard is genuinely effective against rebinding, and it is the check most likely to be
broken by an innocuous-looking refactor — hence the invariant, and its own test module in
`marshal-proxy`.

Resolution happens in the proxy rather than the connect call, so DNS failures surface as proxy
errors with the guard's own diagnostics rather than as opaque connect errors.

Deployments where the proxy and its clients share a private network need `allow_private: true`,
because the default refuses exactly the addresses such a deployment relies on. The docker
example sets it for that reason.

`marshal run --isolation netns` composes with this well: the agent has no resolver at all, so
every name is resolved by the proxy after policy has run, closing DNS-based exfiltration that
destination filtering never sees.
