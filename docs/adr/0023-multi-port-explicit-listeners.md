# ADR 0023: Multi-port explicit listeners, to restore `listener_port` identity

* **Status:** Accepted
* **Date:** 2026-09-03
* **Supersedes:** the transparent-capture-backed version of `listener_port` shipped in M6

## Context

Removing transparent capture ([ADR-0022](0022-remove-transparent-capture.md)) removed the only
thing that ever fed the `listener_port` identity resolver more than one port to distinguish:
`ServerConfig.transparent: Vec<String>`, bound alongside the single explicit listener and
steered to by nftables in the now-deleted `deploy/nftables.conf`. With that gone,
`listeners.explicit.listen` was a single `String`, and `conn.local_addr.port()` — what
`listener_port` matches on — could only ever be that one value. The resolver's config schema
and implementation still existed; nothing could exercise them.

That is a narrower problem than it first looks like, though. `listener_port` itself has never
been about redirection — it reads "which listener accepted this connection", a question that
has nothing to do with firewalls or conntrack. It only ever needed *something* to bind more
than one port. Transparent capture happened to be that something, but an agent that
cooperates enough to set `HTTP_PROXY` at all can just as easily be told to point it at one of
several explicit ports directly — no redirect, no nftables, no nat table required.

## Decision

`listeners.explicit.listen` accepts either a single address (unchanged, existing configs keep
working) or a list of addresses:

```yaml
listeners:
  explicit:
    listen: ["127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082"]
```

Every address serves the identical CONNECT/SOCKS5/absolute-form-HTTP pipeline — the *full*
pipeline, unlike transparent capture's raw relay. `Server::run` binds the first address
synchronously (preserving `on_bind`'s test-friendly port-0 semantics and existing startup
logging) and spawns one accept loop per additional address, each calling the same
`serve_connection` the primary listener uses. `listener_port` resolves off
`conn.local_addr.port()`, populated from whichever socket actually accepted the connection —
unchanged from before.

`marshal config check` warns when a `listener_port` map entry names a port
`listeners.explicit.listen` doesn't bind, since that entry could otherwise never match and the
only symptom would be a mysteriously-unattributed connection much later.

## Alternatives considered

**Leave `listener_port` dead, documented as currently unreachable.** Honest, and it throws
away a resolver whose only fault was depending on a mechanism that no longer exists — not
anything wrong with the resolver's own design.

**A dedicated `listeners.explicit.additional_listen` field instead of making `listen` accept a
list.** Marginally more explicit about "one primary, N extras", at the cost of a second field
name to document and a slightly odd asymmetry between the primary and the rest, which are
otherwise identical in every way that matters (same protocol, same pipeline, same identity
mechanism).

**Bring back a firewall-redirect-fed multi-listener mechanism instead.** Would restore
`listener_port` by rebuilding most of what [ADR-0022](0022-remove-transparent-capture.md) just
removed, for no benefit over agents simply pointing at different ports directly.

## Consequences

`listener_port` works again, and works *better* than it did under transparent capture:
every port now gets the same request-level policy, transforms, and interception as the
primary explicit listener, where under transparent capture it never did.

The trust model is unchanged from what the resolver always documented: it is
client-cooperative, not enforced. Nothing in the proxy stops an agent from also dialing another
agent's port directly and picking up its profile — that still needs
[`marshal run --isolation netns`](0014-netns-isolation-without-cap-net-admin.md) or an external
firewall rule where it matters, exactly as it did before.

`ServerConfig.listen` and `--listen`'s override semantics both changed shape (`String` →
`Vec<String>`); `--listen <addr>` now replaces the configured list entirely with that one
address rather than overriding a single scalar, consistent with how `--profile` overrides the
unidentified fallback elsewhere in the CLI.
