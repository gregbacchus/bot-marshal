# ADR 0018: Profiles do not inherit

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Profiles share structure. Several want the same denylist, the same header allowlist, the same
core bundles. The obvious response is inheritance, and the original design had it:
`extends: base`, merged base-first.

The trouble is what "merged" means for an **ordered, short-circuiting chain**
([ADR-0003](0003-policy-as-a-short-circuiting-chain.md)). Where does a child's layer go
relative to its parent's? Appending puts a child's `denylist` after the parent's `allowlist`,
which — because the chain short-circuits — means it may never run. Prepending inverts the
parent's careful cost ordering.

The original plan already needed `insert_before: dlp` to express placement, which is the
warning sign: the merge rule was complex enough to need its own sub-language, and the resulting
chain existed in no file. Reading `profiles/coding-agent.yaml` would not tell you what
`coding-agent` did.

For a security control whose ordering is semantic, "the effective policy is not written down
anywhere" is disqualifying.

## Decision

Profiles do not inherit. `extends` was removed. **Each profile file states its complete chain,
in order.**

Sharing happens through composition instead, at the two points where it does not disturb
ordering:

* **[Bundles](../configuration/bundles.md)** — a named domain set referenced by an
  `allowlist` layer, so the shared thing is data inside a layer the profile placed itself.
* **[Named transform bundles](../configuration/transforms.md)** — `transforms: <name>`, since
  transforms are not ordered against each other the way layers are.

## Alternatives considered

**`extends` with append semantics.** Simple rule, and it silently defeats a child's `denylist`
by placing it after a terminal `allowlist`.

**`extends` with explicit placement (`insert_before:`).** What the original plan specified.
Correct and expressive, and the effective chain is then assembled from two files by a merge
rule the reader has to simulate mentally.

**Multiple inheritance / mixins.** Every problem above, once per parent.

## Consequences

**A profile file is the whole truth.** Reading it tells you exactly what the chain does, in
execution order, with nothing merged in from elsewhere. For a control where order is meaning,
this is worth more than the duplication it costs.

The duplication is real: a denylist wanted by four profiles is written four times. Bundles
absorb the common case (shared *domains*), and shared *layers* are genuinely repeated.

If this becomes painful, the answer is probably a named-layer-list mechanism with explicit
placement, not the return of `extends` — the ordering problem is what made inheritance wrong
here, and any solution has to keep the effective chain readable in one place.
