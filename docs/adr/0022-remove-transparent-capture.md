# ADR 0022: Remove transparent (nftables REDIRECT) capture

* **Status:** Accepted
* **Date:** 2026-09-03
* **Supersedes:** the transparent-capture portion of M6, shipped under
  [ADR-0008](0008-interception-is-mandatory.md)'s reasoning but never actually built to honour
  it

## Context

A security review of the implementation (`review/2026-09-03-security-review.md`, which is not
committed to this repository) found that `Server::serve_transparent` derived the policy
hostname from the TLS SNI or the
HTTP `Host` header, connected to the independently-recovered `SO_ORIGINAL_DST` destination, and
never checked that the two agreed. It then evaluated one connect-phase policy check and
byte-relayed the rest of the connection.

That is the exact attack [ADR-0008](0008-interception-is-mandatory.md) exists to close for
explicit traffic: an agent can `CONNECT`/arrive claiming `api.github.com` (satisfying an
allowlist and the upstream guard) while the actual destination serves something else entirely
on shared-IP hosting. ADR-0008 closes it for explicit mode by making interception mandatory —
the proxy re-originates its own TLS keyed on the authority it checked, never on anything the
client asserts inside the tunnel. Transparent capture never got that treatment: it byte-relayed
by construction, so `rules`, `dlp`, `mcp`, `judge`, and every `request_transforms`/
`response_transforms` never ran on transparent traffic at all — not scoped away from it, simply
never reached, silently.

Fixing this properly means routing transparent traffic through the same interception pipeline
explicit traffic already gets: terminate TLS, evaluate the real request, re-originate upstream.
At that point transparent capture is not a distinct mode any more — it is a second, harder-to-
verify way of feeding bytes into the pipeline explicit capture already feeds correctly, for a
threat model (an agent that won't cooperate with `HTTP_PROXY`) better addressed by
[`marshal run --isolation netns`](0014-netns-isolation-without-cap-net-admin.md), which
enforces rather than merely identifies.

## Decision

Remove transparent capture entirely rather than rebuild it on the interception pipeline.

Removed: `Server::serve_transparent` and the transparent-listener accept loop in
`Server::run`; `crates/marshal-proxy/src/transparent.rs` (`SO_ORIGINAL_DST` recovery and SNI/
Host classification); `ServerConfig.transparent` and `listeners.transparent` /
`TransparentListener` in the config schema; `IngressMode::Transparent`; `deploy/nftables.conf`
and its syntax-check test; the `transparent_redirect.rs` integration test.

A config that still sets `listeners.transparent` now fails to load with an unknown-field
error, not a silently ignored one.

## Alternatives considered

**Rebuild it on `mitm::intercept`.** The structurally correct fix, and it produces a mode
whose only remaining difference from explicit capture is *how the client's traffic arrives* —
worth doing if there is a real deployment need for firewall-redirected capture specifically,
but not worth carrying as unverified, silently-under-enforcing code until then.

**Keep it, documented as host-level-only.** Scoping transparent traffic to destination-only
policy (denylist/allowlist, no request-level layers) and documenting the gap was considered.
Rejected: a capture mode that silently gives some traffic weaker policy than the rest is
exactly the kind of gap this project exists to make impossible to miss, and "silently" is the
operative problem — nothing in a profile's own file says which capture mode it's reachable
from.

**Add a runtime check refusing to start with request-level layers under transparent mode.**
Narrows the gap without closing it, and still ships an SNI/destination mismatch nothing
catches.

## Consequences

A workload that cannot be configured to use a proxy at all now has one supported option — DNS
capture — which is honest about being a convenience rather than a boundary, instead of a mode
that looked like enforcement and wasn't. Where bypass genuinely matters,
[`marshal run --isolation netns`](0014-netns-isolation-without-cap-net-admin.md) is the answer
regardless: it is the only mode that removes the agent's route out rather than merely
identifying it.

`listener_port` identity lost its only means of ever binding more than one port and became
unreachable as a side effect. Restored on a different, simpler mechanism — see
[ADR-0023](0023-multi-port-explicit-listeners.md) — rather than left dead, since nothing about
the resolver itself was wrong.

Anyone with `listeners.transparent` in a deployed config needs to remove it before upgrading;
`config check` catches this immediately rather than at runtime.
