# Concepts

The model everything else assumes. Worth ten minutes before writing a real config.

## The problem

An agent on a developer machine or in CI has unrestricted outbound access. It can exfiltrate
secrets, fetch and execute arbitrary content, or be steered by a prompt injection into
contacting attacker infrastructure. Firewall rules are too coarse to help: agents legitimately
need GitHub, npm, PyPI and LLM APIs, and those same hosts are exfiltration channels. The
boundary has to understand HTTP, not just IPs.

## The path a request takes

```
                 ┌── explicit: CONNECT / SOCKS5 ──┐
 agent traffic ──┼── transparent: nft REDIRECT ───┼──► identity ──► profile
                 └── dns: A record → proxy IP ────┘                    │
                                                                       ▼
                    ┌──────────── policy chain (decides WHETHER) ───────────┐
                    │ denylist → allowlist → rules → mcp → dlp → judge      │
                    │ each: ALLOW | DENY | PASS(+evidence); first wins      │
                    │ all PASS ⇒ profile.default_action                     │
                    └───────────────────────┬───────────────────────────────┘
                                 DENY ─► 403│ ALLOW
                                            ▼
                    ┌──────── request_transforms (decide HOW) ─────┐
                    │ header filter → secret injection → rewrites  │
                    └───────────────────────┬──────────────────────┘
                                            ▼
                            upstream guard (post-resolution IP check)
                                            ▼
                    ┌──────── response chain + response_transforms ────────┐
                    │ size caps → MCP tools/list filter → redaction        │
                    └───────────────────────┬──────────────────────────────┘
                                            ▼
                                       audit record
```

Three [capture modes](capture.md) converge on one request representation, and everything
downstream is mode-agnostic. That convergence is the most important structural property of the
design: policy is written once, not once per way traffic arrived.

## Identity selects the profile

Which policy applies depends on *which agent* is connecting. Identity is **derived from the
connection, never asserted by the client** — transparent and DNS capture give a client no
channel to present a credential even if you wanted it to.

[Resolvers](configuration/identity.md) are tried in order and are not equal in strength: a
kernel-supplied uid cannot be forged, a `Proxy-Authorization` header trivially can. Anything
unresolved gets a synthetic identity and the most restrictive profile, flagged
`attributed: false` in every audit record — never a silent inheritance of a permissive one.

## Profiles hold the policy

A [profile](configuration/profiles.md) is the unit of policy: an ordered chain of layers, a
terminal `default_action`, and the transforms that apply to what it allows. Exactly one
profile is embedded in the base config as the unattributed fallback; every other one is a
named file that a resolver or `marshal run --profile` can target.

## The policy chain decides *whether*

Requests pass through an ordered chain of [layers](configuration/policy-layers.md). Each
returns **ALLOW**, **DENY**, or **PASS**; the first terminal verdict wins, and `PASS` falls
through carrying structured evidence that later layers can reason over.

```
denylist → allowlist → rules (CEL) → mcp → dlp → judge (LLM) → default_action
  trivial     trivial        cheap      cheap  moderate   expensive
```

Two consequences worth knowing up front:

* **Ordering is semantic.** A denylist at position 1 beats a later LLM approval simply by
  being first. Layers are ordered cheapest-first, and `marshal config check` warns when an
  expensive layer precedes a cheap one.
* **Default-deny lives in `default_action`,** the terminal applied when every layer passed.
  Setting it to `allow` requires an explicit acknowledgement in config. This is the single
  place the product's core guarantee lives.

## Transforms decide *how*

Deciding *whether* is separate from deciding *how*, and the two directions are separate from
each other. [Transforms](configuration/transforms.md) run only after the chain has allowed:

* **`request_transforms`** rewrite an allowed request on its way out — header filtering,
  swapping a placeholder for a real credential so the agent never holds it.
* **`response_transforms`** rewrite what comes back — redacting a secret the upstream echoed,
  summarising or compacting a body too large to be useful to an agent.

## Bodies stream by default

A transform declares whether it needs the body buffered, and that declaration is load-bearing
rather than advisory: bodies stream by default, and a transform that rewrites content cannot
run over a stream. Declaring a body transform is therefore a statement that the responses it
applies to are no longer streamable, so `marshal config check` warns and the profile should
scope it away from SSE and WebSocket endpoints.

This is why interception does not break streaming: SSE arrives event by event, request bodies
forward as they are written rather than being collected first, protocol upgrades become raw
bidirectional relays that survive idle periods, and `Content-Encoding` passes through
byte-identical. Buffering never surfaces as an error — only as an agent whose stream goes
quiet and then delivers everything at once, which is why these are the tests worth having.

## Why interception is mandatory

`marshal serve` refuses to start without a CA. A plain relay cannot enforce per-request
policy, and it cannot even guarantee the client reaches the host it claimed.

Shared-IP hosting (a CDN or load balancer serving many sites off one address) routes by the
TLS SNI *inside* the tunnel, which a relay never inspects. A client can
`CONNECT good.example.com` — correctly resolved, guard approved — then present
`SNI: evil.example.com` and have the origin serve that instead, entirely unseen by a proxy
that only relays bytes.

Interception defeats this structurally: the proxy re-originates its own TLS to upstream keyed
on the CONNECT authority, never on anything the client claims inside the tunnel. The one
sanctioned exception is `tls.passthrough`, for clients that pin certificates and would refuse
the proxy's own cert; a passthrough host still gets the same SNI cross-check on its plain
relay. The SOCKS5 front-end gets identical treatment to HTTP CONNECT — same mandatory
interception, same passthrough exception, same SNI check.

### What CONNECT can and cannot decide

A `CONNECT` names a destination and nothing else. When TLS will be intercepted it is treated
as a **pre-filter**: a destination no host-level layer *refused* proceeds to interception,
where `rules` and `dlp` make the real call on the actual request.

Otherwise the natural configuration is impossible — a short-circuiting chain means an
allowlist with `on_match: allow` terminates before those layers run, while `on_match: pass`
leaves nothing to permit the tunnel. Nothing reaches the upstream until a request-level
verdict allows it. The only way a connection is *not* eventually judged on the real request is
`tls.passthrough`, where the CONNECT verdict is the sole decision point and `default_action`
governs it strictly — the same trade a certificate-pinned client always makes by opting out
of interception.

## The upstream guard

Between the transforms and the connection, every resolved IP is checked against
`upstream.deny_cidrs`. The hostname is resolved once, each resulting address checked, and the
connection made **to that checked address** — never re-resolved between check and connect,
which is what closes DNS rebinding. This is the guard that keeps an allowed hostname from
becoming a route to `169.254.169.254`.

## Everything lands in the audit trail

Every request produces a record carrying the resolved identity, whether it was attributed,
which layer decided and why, the full evidence trail, status, and timing — with injected
secrets scrubbed. See [Observability](observability.md).
