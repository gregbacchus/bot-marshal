# bot-marshal

An egress firewall for AI agents, coding bots, and other untrusted automation.

An agent on a developer machine or in CI has unrestricted outbound access. It can exfiltrate
secrets, fetch and execute arbitrary content, or be steered by a prompt injection into
contacting attacker infrastructure. Firewall rules are too coarse to help: agents legitimately
need GitHub, npm, PyPI and LLM APIs, and those same hosts are exfiltration channels. The
boundary has to understand HTTP, not just IPs.

`bot-marshal` is a single binary that agent traffic is pointed at. It enforces default-deny
egress with per-request policy, injects real credentials at the boundary so the agent never
holds them, produces a complete audit trail, and does not break streaming.

Conceptually indebted to [iron-proxy](https://github.com/paradigmxyz/iron-proxy); an
independent Rust implementation rather than a port.

## The policy chain

Requests pass through an ordered chain of layers. Each returns **ALLOW**, **DENY**, or
**PASS**; the first terminal verdict wins, and `PASS` falls through carrying structured
evidence that later layers can reason over.

```
denylist → allowlist → rules (CEL) → dlp → mcp → judge (LLM) → default_action
   µs         µs            µs         ms     ms      ~100ms
```

Two consequences worth knowing up front:

* **Ordering is semantic.** A denylist at position 1 beats a later LLM approval simply by
  being first. Layers are ordered cheapest-first, and `marshal config check` warns when an
  expensive layer precedes a cheap one.
* **Default-deny lives in `default_action`,** the terminal applied when every layer passed.
  Setting it to `allow` requires an explicit acknowledgement in config.

## Transforms

Deciding *whether* (policy layers) is separate from deciding *how* (transforms), and the two
directions are separate from each other:

* **`request_transforms`** rewrite an allowed request on its way out — header filtering,
  swapping a placeholder for a real credential so the agent never holds it.
* **`response_transforms`** rewrite what comes back — redacting a secret the upstream echoed,
  summarising or compacting a body too large to be useful to an agent.

Both run only after the chain has allowed. A transform declares whether it needs the body
buffered, and that declaration is load-bearing rather than advisory: bodies stream by default,
and a transform that rewrites content cannot run over a stream. Declaring a body transform is
therefore a statement that the responses it applies to are no longer streamable, so
`marshal config check` warns and the profile should scope it away from SSE and WebSocket
endpoints.

## Status

Early, but **traffic flows and TLS is intercepted**. M2 is complete: policy evaluates the
real decrypted request, not just the tunnel destination, and each request inside a connection
is judged and audited separately.

Interception does not break streaming. SSE arrives event by event, request bodies forward as
they are written rather than being collected first, protocol upgrades become raw bidirectional
relays that survive idle periods, and `Content-Encoding` passes through byte-identical. Those
are the tests worth having: buffering never surfaces as an error, only as an agent whose
stream goes quiet and then delivers everything at once.

Without a CA the proxy still runs as a tunnel, sees destinations only, and says so at startup.

| Milestone | Contents | State |
|---|---|---|
| M0 | Workspace, core traits, config load + validate, CI | done |
| M1 | Explicit proxy (CONNECT + SOCKS5), chain runner, denylist + allowlist, upstream guard, audit | done |
| M2 | TLS MITM, streaming (WebSocket / SSE / chunked) | done |
| M3 | Secret injection, egress DLP, CEL rules layer | |
| M4 | Session identity, profiles, `marshal run` | |
| M4.5 | LLM judge layer | |
| M5 | MCP tool-level policy | |
| M6 | Transparent (nftables) and DNS interception | |
| M7 | Management API, hot reload, OTEL | |

## Try it

```bash
cargo run --bin marshal -- config check
```

Create a CA and trust it — `ca init` prints per-runtime instructions, and prefers scoped
environment variables over touching the system store:

```bash
cargo run --bin marshal -- ca init
```

Then run the proxy and point something at it:

```bash
cargo run --bin marshal -- serve --profile base --listen 127.0.0.1:8080
```

```bash
curl -x http://127.0.0.1:8080 https://api.github.com/zen
```

`api.github.com` is in the `github` bundle, so that succeeds. Anything not allowlisted comes
back as a 403 whose body says which layer refused and why — a bare 403 just makes agents
retry-loop.

```bash
curl -x http://127.0.0.1:8080 https://example.com/
```

SOCKS5 works on the same port; the protocol is sniffed from the first byte.

```bash
curl --socks5-hostname 127.0.0.1:8080 https://api.github.com/zen
```

Starting `--profile coding-agent` deliberately fails: that profile names `rules`, `dlp` and
`judge` layers that do not exist yet, and running it without them would enforce a chain more
permissive than the one written.

## Layout

`marshal-core` holds the traits and types and depends on no other crate in the workspace;
everything else builds on it. That keeps the boundaries honest and the policy chain testable
without a network.
