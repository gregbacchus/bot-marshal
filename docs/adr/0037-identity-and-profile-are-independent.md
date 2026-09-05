# ADR 0037: Identity and profile are independent axes of the scope name

* **Status:** Accepted
* **Date:** 2026-09-05
* **Amends:** [ADR-0015](0015-the-cgroup-name-is-the-registration.md)

## Context

[ADR-0015](0015-the-cgroup-name-is-the-registration.md) made the cgroup name the registration:
`marshal run --profile coding-agent` launches into `marshal-coding-agent-<pid>.scope`, and the
`run` resolver reads it back. Two details of that encoding conflated things that are not the
same question.

The identity was `<profile>-<pid>`. That builds the *policy* an agent is governed by into the
*name* of the agent, so two agents that differ only in profile look like different kinds of
thing, and moving an agent to another profile renames it in every audit record.

And `marshal run` with no `--profile` produced `marshal-<pid>.scope`, a shape the resolver
deliberately did not recognise. The agent was launched by marshal, isolated by marshal, and
still came out `unidentified` — not because marshal could not tell who it was, but because
omitting a *profile* was read as declining an *identity*. `--profile` is optional precisely
because a default profile exists; omitting it should select that default, not discard the
attribution marshal already has in hand.

## Decision

The scope name carries the two independently: `marshal-[<profile>-]<pid>.scope`.

* **The pid is the identity.** `pid-4821`, whether or not a profile was named. The profile
  never appears in the identity string.
* **The profile segment is optional.** Present, it names a profile from `profiles/`; absent,
  no profile was named and the embedded `profile:` governs the agent — the ordinary meaning of
  a default.

`Resolved.profile` is therefore `Option<Arc<str>>`, where `None` *is* "the embedded profile",
carrying no name because [it has none](0017-the-fallback-profile-is-embedded.md). It is not a
reserved or sentinel name, and nothing looks one up: the runtime already holds that chain
separately. The string `default` survives only as a display label at the emission boundary,
produced by one accessor and never used as a key.

A `marshal run` agent with no `--profile` is consequently **attributed** — `identity:
pid-4821`, `resolver: run`, `attributed: true` — governed by the default profile.

## Alternatives considered

**A reserved profile name meaning "the default".** Directly contradicts
[ADR-0017](0017-the-fallback-profile-is-embedded.md), which makes the embedded profile
unreferenceable so it cannot be selected by accident, and it would let a stale scope name the
fallback explicitly.

**Leave it: no `--profile` means no identity.** What was there. It makes attribution a
side effect of a policy choice, and it silently discards information — marshal launched the
process and knows exactly which one it is.

**Keep `<profile>-<pid>` as the identity for continuity.** Cheaper, and it preserves the
conflation: an agent's name should not change when its policy does.

## Consequences

`--profile` now does one job — choosing policy — and does not decide whether an agent is
identified at all. Per-agent audit and metrics work for the no-profile case, which is the
common one when trying marshal out.

Identity strings changed shape (`coding-agent-4821` → `pid-4821`). Anything keying on the old
form — a saved query over the audit log, a `rules` layer matching on identity — must be
updated. Nothing published depended on it at the time of this change.

**The pid is only unique while the process lives.** `pid-4821` refers to whichever `marshal
run` currently owns that scope, and pids are reused after it exits. Identity here is a handle
on a live process tree, not a durable key: an audit log spanning a reboot can contain two
unrelated agents under one identity string, distinguishable only by timestamp. The previous
form had the same property — it embedded the same pid — so this is unchanged rather than newly
introduced, but it is now the whole of the name.

The parse gains a small ambiguity rule: a body that is nothing but digits is the no-profile
form. A profile segment is never empty, so the two shapes cannot collide, and the pid is
required to be numeric rather than merely non-empty — which also rejects more junk than
before.
