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

M3 adds boundary secret injection, egress credential scanning, and CEL rules. The agent holds
only a placeholder; the real credential is swapped in at the boundary and scrubbed from the
audit trail. The DLP layer catches the inverse case — a real credential the agent obtained
some other way and is trying to send out, which destination filtering cannot see.

Without a CA the proxy still runs as a tunnel, sees destinations only, and says so at startup
— including a warning naming any layer that will therefore never evaluate.

## Identity

Which policy applies depends on *which agent* is connecting, and identity is derived from the
connection rather than asserted by the client — transparent and DNS ingress give a client no
way to present a credential. Resolvers are tried in order, and they are not equal in strength:

| resolver | strength | limitation |
|---|---|---|
| `peer_cred` uid | kernel-supplied, unspoofable | only separates agents running as different users |
| `launched` | cgroup naming from `marshal run`, inherited by child processes | a process can move itself between delegated cgroups |
| `source_ip` | as trustworthy as the network | collapses when two agents share a namespace |
| `proxy_auth` | client-asserted | an agent that can read another token can pick another profile |

Anything unresolved gets a synthetic session, the most restrictive profile, and
`attributed: false` in every audit record — never a silent inheritance of a permissive one.

The Unix listener exists for `SO_PEERCRED`, which is the only same-host identity that is both
unspoofable and free of a lookup race.

### Launching an agent

```bash
marshal run --profile coding-agent -- claude
```

This places the agent in a transient systemd scope named `marshal-coding-agent-<id>.scope`
and sets the proxy and CA environment for every runtime that consults its own trust store.
The naming convention *is* the registration: the `launched` resolver reads the profile back
out of the cgroup, so there is no control socket and nothing to get out of sync if the proxy
restarts. Because cgroups are inherited, the `git`, `npm` and `curl` processes the agent
spawns — which is where most of its egress actually comes from — are identified too.

That gives distinct sessions for agents running as the *same* uid, which uid alone cannot do.

`--isolation netns` is deliberately absent rather than half-implemented. It is the only option
that prevents bypass rather than merely identifying traffic, but doing it unprivileged needs a
forwarder inside the namespace; a flag that quietly did something weaker would be worse than
no flag. Use a container with its own address and a `source_ip` resolver for that today.

### A note on CONNECT

A `CONNECT` names a destination and nothing else. When TLS will be intercepted it is treated
as a pre-filter: a destination no host-level layer *refused* proceeds to interception, where
`rules` and `dlp` make the real call on the actual request. Otherwise the natural
configuration is impossible — a short-circuiting chain means an allowlist with
`on_match: allow` terminates before those layers run, while `on_match: pass` leaves nothing
to permit the tunnel. Nothing reaches the upstream until a request-level verdict allows it,
and in tunnel mode the CONNECT is the only decision point, so `default_action` governs it
strictly.

| Milestone | Contents | State |
|---|---|---|
| M0 | Workspace, core traits, config load + validate, CI | done |
| M1 | Explicit proxy (CONNECT + SOCKS5), chain runner, denylist + allowlist, upstream guard, audit | done |
| M2 | TLS MITM, streaming (WebSocket / SSE / chunked) | done |
| M3 | Secret injection, egress DLP, CEL rules layer | done |
| M4 | Session identity, profiles, `marshal run` | done |
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
