# ADR 0006: CEL for the rules layer, not a general scripting language

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Destination allowlisting cannot express everything worth expressing. "Allow GETs to GitHub but
not writes to workflow files" is about method and path, not host, and belongs in config rather
than in Rust.

That means an expression language evaluated **on the request path**, on input an attacker
partly controls, in a proxy whose latency is every agent's latency.

## Decision

CEL (Common Expression Language), via the `cel` crate, for the `rules` layer.

```yaml
- when: 'req.method in ["POST", "PATCH", "DELETE"]'
  verdict: pass
  annotate: { flags: ["WriteOperation"] }
```

Expressions see `req` (method, host, path, header names) and `ev` (accumulated
[evidence](0003-policy-as-a-short-circuiting-chain.md)), and may either return a verdict or
annotate evidence without deciding.

## Alternatives considered

**Rhai, Lua, or WASM.** General-purpose and far more expressive, and every one of them is
Turing-complete: an expression can loop forever on the request path. Defending that needs a
sandbox with instruction counting and timeouts — a security boundary of its own, in a security
tool, for expressiveness that policy rules do not obviously need.

**Rego (`regorus`).** Purpose-built for policy and the right answer for anyone already running
OPA. Heavier to learn for someone who is not, and awkward to read inline in YAML. Left as a
possible opt-in rather than the default.

**A fixed matcher DSL of our own.** No new dependency and no evaluator to trust, but it grows
one feature at a time until it is a bad programming language with no documentation.

## Consequences

**An expression cannot hang the proxy.** CEL is non-Turing-complete by construction, so there
is no loop to bound and no sandbox to defend. That property is the whole reason for the
choice.

The ceiling is lower than a scripting language's. Something genuinely inexpressible in CEL
needs a Rust layer, not a cleverer expression — an acceptable trade, and the chain design makes
adding a layer additive.

CEL is unfamiliar to many people, though it reads close enough to Python or Go to be guessable.
Its use by Envoy and Kubernetes admission control means the syntax is at least documented
elsewhere.

Rego remains open as an additional layer type. Nothing about this decision forecloses it.
