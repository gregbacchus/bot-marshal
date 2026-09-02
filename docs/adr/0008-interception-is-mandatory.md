# ADR 0008: TLS interception is mandatory, not a fallback

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

The natural design offers interception as an option: relay `CONNECT` by default, intercept
where a profile asks for it. It avoids the CA trust burden for simple cases and degrades
gracefully.

It does not work, for a reason that is not about features.

**A relay cannot guarantee the client reaches the host it named.** A `CONNECT` names a
destination; the proxy resolves it, checks the address against the upstream guard, and opens a
tunnel. Inside that tunnel the client then performs its own TLS handshake, presenting whatever
SNI it likes. On shared-IP hosting — any CDN, any load balancer fronting many sites — the
origin routes on that SNI.

So a client can `CONNECT good.example.com`, pass every check honestly, and then present
`SNI: evil.example.com` on the same connection and be served that instead. The proxy sees
encrypted bytes and approves. Destination filtering is not merely coarse here; it is
bypassable by design, and the bypass is invisible in the audit log.

This is exactly the threat model: the agent is the thing that might be compromised.

## Decision

Interception is mandatory. **`marshal serve` refuses to start without a CA** — no relay-only
mode, no per-profile opt-out.

The proxy re-originates its own TLS to upstream keyed on the CONNECT authority, never on
anything the client asserts inside the tunnel. SOCKS5 gets identical treatment.

The one sanctioned exception is `tls.passthrough`, an explicit host list for certificate-pinned
clients that would refuse the proxy's certificate. A passthrough host still gets an SNI
cross-check on its plain relay, and its CONNECT verdict becomes the sole decision point,
governed strictly by `default_action`.

## Alternatives considered

**Relay by default, intercept on request.** Ships the bypass above as the default configuration.

**Relay with an SNI cross-check and no interception.** Closes this specific attack and leaves
policy unable to see method, path, or body — no `rules`, no `dlp`, no `mcp`, no `judge`. That
is most of the product.

**Intercept by default, allow a documented relay-only mode.** Nearly this decision, and the
mode would be selected by whoever wanted the CA trust step to go away, which is whoever
understands the trade least.

## Consequences

Every deployment carries a CA trust step. This is the largest adoption cost in the tool, and it
is unavoidable rather than incidental — `ca init` prints per-runtime instructions and prefers
scoped environment variables over touching the system store, but it cannot be removed.

The proxy holds a CA private key, which is a serious secret: whoever has it can impersonate
every site the agent talks to. It is written `0600`, never logged, and
[Production](../production.md) recommends a dedicated service user largely because of it.

Certificate-pinned clients break, and correctly so. `tls.passthrough` is the answer, at the
cost of that host getting destination-level policy only.

Because `CONNECT` is now a pre-filter rather than the decision, an allowlist with
`on_match: allow` would short-circuit before the request-level layers run. That interaction is
subtle enough to be documented in [Concepts](../concepts.md#what-connect-can-and-cannot-decide).
