# ADR 0003: Policy is an ordered, short-circuiting chain carrying evidence

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

The obvious design for "check a request against several rules" is a set of independent checks
whose results are combined — all must pass, or a deny anywhere wins. It is simple and it is
order-independent, which sounds like a virtue.

It fails on two requirements here.

The first is **precedence**. A denylist must beat an LLM approval. With independent checks
combined at the end, that requires a rule about which check wins, and that rule has to be
maintained separately from the checks themselves.

The second is **cost**. The layers range from microseconds (a domain glob) to hundreds of
milliseconds and a per-call bill (an LLM). Evaluating all of them on every request is not
viable, and "skip the expensive one if a cheap one already decided" is exactly a
short-circuit — just an implicit one.

There is also a third thing a set of independent checks cannot express at all: a cheap layer
noticing something an expensive layer should know. A regex scan that flags "this body looks
like it contains a credential" is not a verdict, but it should reach the judge.

## Decision

Policy is an **ordered chain**. Each layer returns `ALLOW`, `DENY` or `PASS`; the first
terminal verdict wins and the rest of the chain does not run. `PASS` falls through carrying an
`Evidence` value that later layers can read and add to.

`Evidence` is append-only: a layer contributes facts and flags and never mutates or removes
another layer's. It accumulates a `trail` of every layer's verdict and timing, emitted verbatim
in the audit record.

Ordering is therefore **semantic**, and documented as such.

## Alternatives considered

**Independent checks with a combining rule.** Order-independent, but needs explicit precedence
machinery, evaluates expensive checks needlessly, and has nowhere to put evidence.

**A decision tree or rule engine.** More expressive, and far harder to reason about at the only
moment that matters — reading a config and predicting what it will do.

**Priority numbers instead of file order.** Makes precedence explicit but decouples it from
reading order, so the config no longer reads top-to-bottom in the order it executes.

## Consequences

Precedence and cost-ordering both fall out of a single mechanism, with no special cases:
putting `denylist` first *is* giving it precedence.

The cost is that **reordering a config changes its meaning**, which is not obvious to someone
who expects checks to be a set. Two mitigations: each layer declares a `CostClass` and
`marshal config check` warns when an expensive layer precedes a cheap one, and the
consequences of ordering are called out in [docs/concepts.md](../concepts.md).

A subtler trap, hit in practice: an `allowlist` with `on_match: allow` terminates the chain, so
the `dlp` and `judge` layers after it never run for an allowed host. The fix is `on_match:
pass` — "necessary but not sufficient" — which is why that knob exists and why the shipped
profile uses it.

The `trail` makes every decision reconstructable after the fact, which is what turns the audit
log from a record of outcomes into a record of reasoning.
