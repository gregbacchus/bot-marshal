# ADR 0029: The redaction set is learned at runtime, not sealed at startup

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

[ADR-0011](0011-secrets-are-injected-at-the-boundary.md) established that the real credential
must never leave the boundary, and that an audit record is a way out of the boundary just as
much as a socket is. The mechanism is `Redactor`: the proxy resolves every configured secret
once at startup, builds a redactor from the union of those values, and hands a clone to every
audit sink. Nothing that reaches a sink can carry a value the redactor holds.

That worked because of a property of the sources, not of the design: `env` and `file` both
hand back a value that already exists. Resolve them all up front and the set is complete.

OAuth2 breaks the property. A minted access token does not exist until the request that needs
it, and the `Redactor` was immutable once constructed — `values: Vec<String>`, built by
`new()`, never touched again. A token minted at 10:00 for a request at 10:00 was not in the
set built at boot, so it was redacted nowhere. The invariant in `AGENTS.md` — *secrets never
reach a log, an audit record, or the judge* — would have held only for the static sources and
silently not held for the dynamic ones, which is the worst shape a security property can take:
stated unconditionally, true conditionally.

Seeding at startup by minting a token at boot is not a fix. It makes starting the proxy depend
on an auth server being reachable, mints credentials nobody asked for, and still says nothing
about the *next* token, an hour later, after the first expires.

## Decision

`Redactor` holds `Arc<RwLock<_>>` and gains `learn(label, value)`. Cloning shares the set
rather than snapshotting it, so a value learned after a sink took its clone still reaches that
sink. Every code path that obtains a credential at runtime calls `learn` **before** the value
can reach a sink or a socket.

The set has two halves with different lifetimes. Values passed to `new()` are *pinned*: they
come from config, so their count is bounded by the config, and they are never evicted. Values
passed to `learn()` are held per label, most-recent-last, bounded at four per label.

Four rather than one because a credential that has just been refreshed can still appear in a
record for a request that began before the refresh; forgetting the superseded value the
instant a new one arrives would leak precisely during rotation. Four rather than unbounded
because a process running for weeks would otherwise accumulate every token it ever held.

## Alternatives considered

**Keep the redactor immutable; rebuild it on rotation.** Rebuilding means replacing the
redactor every sink already holds, which is the same shared-mutable-state problem one level up
and with a worse failure mode: a sink holding a stale redactor is silently unprotected, and
nothing in the type system says which sinks have been updated.

**Redact structurally instead of by value** — never emit a field known to hold a credential,
rather than searching output for known values. Better in principle, and the audit record
already does this where it can (the judge sees header *names* only). It does not replace
value-matching: a secret can appear in a free-text error message from an upstream, in a URL, or
in a body a transform scanned, and no field-level rule catches all of those.

**Mint every credential at startup to keep the set complete.** Rejected above: it couples
process start to a third party, mints unused credentials, and does not cover refresh anyway.

**One value per label.** Rejected: leaks during rotation, which is the moment the set changes
and therefore the moment most likely to be wrong.

## Consequences

There is now a window in which a value is unredacted: between minting it and learning it. It
is small and it is entirely the caller's responsibility, which is a weaker guarantee than
"sealed at startup, cannot be wrong". Any future code that obtains a credential and forgets to
`learn` it reintroduces exactly the hole this ADR exists to close, and nothing will fail — the
value simply appears in the audit log. That is a real regression in how hard the property is
to break, accepted because the alternative is not having the property at all for dynamic
credentials.

The bound is a second, quieter hole. A credential rotated more than four times while a
long-running request is still being written out can have its value evicted before that record
is emitted. Four is a judgment call, not a measured one; it is comfortably more than the
number of rotations any single request can outlive in practice.

`redact()` now takes a read lock per call, on every emitted record. Uncontended `RwLock` reads
are cheap and the sinks already serialise on a writer mutex, so this is not expected to matter
— but it is a lock on the emission path that was not there before, and a pathological
`learn()` rate would contend with it.

`Redactor` is no longer a plain value: two clones are the same set, not two sets. Code that
relied on cloning to get an independent copy would now be wrong. Nothing did, and nothing
should — the sharing is the point.
