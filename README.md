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

## MCP

To a host allowlist every MCP call looks identical — one POST to one endpoint. The difference
between `search_repositories` and `delete_repository` is entirely in the body, so tool-level
policy needs its own layer:

```yaml
- layer: mcp
  servers:
    - rules: [{ host: "mcp.example.com" }]
      tools:
        - name: "search_*"                       # glob over a family
        - name: "create_issue"
          when: [{ path: owner, equals: gregbacchus }]
```

Default-deny applies: a tool not listed cannot be called. A denied `tools/call` comes back as
a **JSON-RPC error, not an HTTP 403** — the client is an MCP implementation, and a
transport-level failure reads to it as "the server is down", producing reconnects rather than
something the agent can act on.

Denied tools are also removed from `tools/list`, which matters more than blocking the call:
an error is something an LLM-driven agent retries and works around, whereas a tool it never
sees produces no intent at all. Filtering works on JSON responses and on SSE, and the SSE
path rewrites event by event rather than buffering, so MCP's streamable transport keeps
streaming.

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

The agent goes into a network namespace with no route out, inside a transient systemd scope
named `marshal-coding-agent-<id>.scope`. The scope supplies identity — the naming convention
*is* the registration, so the `launched` resolver reads the profile back out of the cgroup and
there is no control socket to get out of sync. Because cgroups are inherited, the `git`, `npm`
and `curl` processes the agent spawns — where most of its egress actually comes from — are
identified too. That gives distinct sessions for agents running as the *same* uid, which uid
alone cannot do.

**`netns` enforces rather than identifies**, which is what separates it from every other mode.
An unprivileged namespace has loopback and nothing else; the proxy is reached over a Unix
socket, which is a filesystem object and so crosses the namespace boundary untouched. A small
forwarder inside bridges loopback to it. No `CAP_NET_ADMIN`, no veth, no slirp4netns.

The difference is not theoretical. The same agent, told to unset its proxy variables and
connect directly to a host its profile denies:

| isolation | result |
|---|---|
| `cgroup` | reaches the host — **bypassed** |
| `netns`  | `Could not resolve host` — no route out |

Two consequences worth knowing. DNS is gone too, so a hostname is only ever resolved by the
proxy *after* policy has run, which closes DNS-based exfiltration that destination filtering
never sees. And a tool that ignores proxy environment variables gets no network at all rather
than silently bypassing — failing closed is the point, but it does surface badly-behaved
tooling as a hard error.

Only the network is isolated; the filesystem is passed through, because the agent needs its
workspace. This is an egress firewall, not a sandbox.

```bash
marshal run --profile coding-agent --isolation cgroup -- claude   # identify only
marshal run --profile coding-agent --isolation none   -- claude   # env vars only
```

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
| M5 | MCP tool-level policy | done |
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
