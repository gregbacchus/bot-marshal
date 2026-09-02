# ADR 0001: Record architecture decisions in ADRs

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

This project makes a number of choices that look arbitrary from the outside and are not:
interception is mandatory rather than optional, default-deny lives in a config field rather
than in code, the policy chain short-circuits rather than evaluating every check. Each was
decided against a specific alternative for a specific reason.

Reasoning like that survives in a commit message for about as long as anyone remembers which
commit to look at. The failure mode is concrete: someone later sees a constraint, reads it as
an oversight, "fixes" it, and removes a guarantee nobody knew was load-bearing.

## Decision

Record architecturally significant decisions as numbered ADRs in `docs/adr/`, using the
format in [`template.md`](template.md): Context, Decision, Alternatives considered,
Consequences.

Accepted ADRs are immutable. A decision that changes gets a new ADR that supersedes the old
one; the old one's Status line is updated and nothing else.

## Alternatives considered

**Commit messages alone.** They already carry much of this reasoning, and they are genuinely
good here. But they are addressable only by hash, not discoverable by topic, and `git log`
cannot tell you which of forty commits holds the reason for a constraint you just noticed.

**A single DECISIONS.md.** Simpler to start, but it grows without structure, invites editing
history in place, and gives no natural unit to supersede.

**Nothing.** The status quo, and the reason the constraints above are currently defensible only
by whoever wrote them.

## Consequences

Substantive decisions now carry a documentation cost, and the index must be kept in step —
[AGENTS.md](../../AGENTS.md) names when this applies.

The immutability rule means the directory accumulates records that no longer describe the
system. That is the intent: a superseded ADR explains why the code once looked different,
which is exactly what someone reading old code needs.

ADRs are not user documentation and must not become it. They answer "why", not "how"; the rest
of [docs/](../) answers "how" and stays current as the code changes.
