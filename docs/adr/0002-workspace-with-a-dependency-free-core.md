# ADR 0002: A workspace with a dependency-free core crate

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

The proxy has to hold several concerns at once: TLS interception, an async policy chain,
credential handling, DNS, three capture modes, and a CLI. Built as one crate, the policy chain
would end up reachable only through a socket, and every test of a verdict would need a live
listener and a real upstream.

Policy correctness is the thing this project exists to get right, so it is the thing that most
needs to be cheap to test exhaustively.

## Decision

A Cargo workspace of focused crates. `marshal-core` holds the shared types and traits —
`Verdict`, `PolicyLayer`, `RequestContext`, `Evidence`, `Identity`, `AuditSink` — and
**depends on no other `marshal-*` crate and performs no I/O**. Everything else depends on it.

Layers, transforms and resolvers are trait implementations, so the chain can be assembled from
in-memory fakes and evaluated with no network.

## Alternatives considered

**A single crate with modules.** Less ceremony, and module boundaries would enforce nothing:
`use crate::proxy::...` from inside the policy code compiles fine, and the coupling arrives
without anyone deciding to add it.

**Splitting by layer of the stack rather than by concern.** Would put policy and transport in
the same crate on the grounds that both are "request handling", which is precisely the
coupling being avoided.

## Consequences

The core crate's dependency direction is checkable and CI-enforced by the fact that it simply
does not compile if violated. That is the property worth protecting; if a change appears to
need `marshal-core` to reach into another crate, the design is wrong, not the rule.

The cost is real: a change to a shared type touches every crate, and a trait signature is much
harder to alter than a function call would be. Adding a genuinely cross-cutting concern means
finding a place for it in the type system rather than reaching for it where it is needed.

Eleven crates is more `Cargo.toml` than a single crate needs, and workspace dependency
management (`[workspace.dependencies]`) becomes mandatory rather than optional.
