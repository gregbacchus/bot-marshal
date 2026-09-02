# ADR 0009: Identity is derived from the connection, never asserted

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Per-agent policy needs to know which agent is connecting. The obvious mechanism is a
credential: `Proxy-Authorization`, a token, a header.

Two problems.

**It does not exist in two of the three capture modes.** Under transparent redirect or DNS
capture the client believes it is talking to the origin server. There is no proxy to
authenticate to, and no place to put a credential.

**It is asserted by the thing being policed.** An agent that can read a token can present it.
The threat model here includes a compromised or prompt-injected agent, and "the agent tells us
which policy to apply to it" is not a boundary — it is a suggestion.

## Decision

Identity is **derived from the connection**. Resolvers are tried in order, first match wins,
and each is documented with its actual strength:

| resolver | basis | forgeable by the agent? |
|---|---|---|
| `peer_cred` | kernel-supplied uid/gid | no |
| `launched` | cgroup path, inherited by children | only by moving between delegated cgroups |
| `source_ip` | network address | only by controlling the network |
| `listener_port` | which listener accepted | only by reaching another port directly |
| `proxy_auth` | client-presented credential | **yes** |

`proxy_auth` remains available and is documented as the weakest, to be listed last. Anything
unresolved gets a synthetic identity, the most restrictive profile, and `attributed: false` in
every audit record.

## Alternatives considered

**Credential-only.** Simple, uniform, unavailable under two capture modes, and trivially
forgeable by the party being restricted.

**Trust a client-supplied header where nothing better is available.** Makes the weakest
mechanism the fallback, so an agent that suppresses every strong signal is upgraded rather than
contained.

**Refuse to run without a strong resolver.** Considered and rejected as too strict for the
common single-developer case, where `unidentified` plus a restrictive fallback profile is a
reasonable posture.

## Consequences

Identity strength is a **deployment property, not a code property**. `peer_cred` only separates
agents running as different users, which means creating those users. `source_ip` collapses the
moment two agents share a namespace. These trust assumptions are documented next to the
resolver config because they are the load-bearing ones.

`listener_port` identity holds only if the agent cannot reach the other listeners directly —
the shipped nftables ruleset must drop direct connections to the proxy ports, or an agent picks
its own profile by choosing a port.

`attributed: false` is a hard signal rather than noise: it means every resolver missed. The
alternative — silently inheriting a permissive profile — is the failure this design exists to
prevent.

Same-uid agents were the gap this left, and closing it produced
[ADR-0015](0015-the-cgroup-name-is-the-registration.md).
