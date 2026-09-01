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

Deciding *whether* (policy layers) is separate from deciding *how* (transforms: header
filtering, secret injection). Transforms run only once the chain has allowed.

## Status

Early. **M0 (scaffold) is complete**: the workspace, core traits and types, configuration
loading and validation, and `marshal config check`. Traffic does not flow yet — that is M1.

| Milestone | Contents | State |
|---|---|---|
| M0 | Workspace, core traits, config load + validate, CI | done |
| M1 | Explicit proxy (CONNECT + SOCKS5), chain runner, denylist + allowlist, upstream guard, audit | next |
| M2 | TLS MITM, streaming (WebSocket / SSE / chunked) | |
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

## Layout

`marshal-core` holds the traits and types and depends on no other crate in the workspace;
everything else builds on it. That keeps the boundaries honest and the policy chain testable
without a network.
