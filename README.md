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

## Quickstart

Build it:

```bash
cargo build --release
alias marshal=./target/release/marshal   # or install it onto PATH
```

With no `--config`, every subcommand looks in one default place:
`$XDG_CONFIG_HOME/bot-marshal/config.yaml`, which on almost every Linux setup is
`~/.config/bot-marshal/config.yaml`. Nothing creates it for you — write it yourself first,
same as you would for any other tool that follows this convention.

This walkthrough's config is deliberately minimal, not the fuller example shipped in this
repo at `config/marshal.yaml` — that one also defines profiles using the judge layer, and
**`serve` builds every profile in the config up front, not just the one `--profile`
selects**, so it refuses to start at all without `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` set.
Once you have the basics working, `config/marshal.yaml` is worth reading as a fuller example;
just export those variables first if you want to run it as-is with a `--config` pointed at
this checkout.

```bash
mkdir -p ~/.config/bot-marshal
cat > ~/.config/bot-marshal/config.yaml <<'CFG'
tls:
  ca_cert: "~/.config/bot-marshal/ca.crt"
  ca_key: "~/.config/bot-marshal/ca.key"
profiles:
  base:
    default_action: deny
    policy:
      - layer: allowlist
        allow: { domains: ["api.github.com"] }
        on_match: allow
        on_miss: pass
CFG
```

Check it's valid before anything else — this catches most mistakes before they matter:

```bash
marshal config check
```

Generate a CA. `ca init` writes the cert and key to the paths named by `tls.ca_cert` /
`tls.ca_key` and prints per-runtime trust instructions, preferring scoped environment
variables over touching the system store:

```bash
marshal ca init
```

Start the proxy:

```bash
marshal serve --listen 127.0.0.1:8080
```

Point something at it, trusting the CA you just generated (`--cacert` here is standing in for
whichever of `ca init`'s printed trust instructions fits your setup):

```bash
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://api.github.com/zen
```

That succeeds — `api.github.com` is explicitly allowlisted above. Anything not allowlisted
comes back as a 403 whose body says which layer refused and why, a bare 403 just makes agents
retry-loop:

```bash
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://example.com/
```

SOCKS5 works on the same port; the protocol is sniffed from the first byte:

```bash
curl --cacert ~/.config/bot-marshal/ca.crt --socks5-hostname 127.0.0.1:8080 https://api.github.com/zen
```

From here, `config/marshal.yaml` in the repo is worth reading as the fuller example — bundles,
secret injection, DLP, MCP, and a judge-gated profile — and [Launch an agent](#identity) covers
`marshal run`, which is how a real agent should be pointed at the proxy rather than by hand.

## CLI reference

Every subcommand accepts two global flags, before the subcommand name:

| flag | env var | default | |
|---|---|---|---|
| `--config`, `-c <path>` | `MARSHAL_CONFIG` | `$XDG_CONFIG_HOME/bot-marshal/config.yaml` | usually `~/.config/bot-marshal/config.yaml`; a system service should pass an explicit path (see [Running as a service](#running-as-a-service)) |
| `--log <level>` | `MARSHAL_LOG` | `info` | `error`, `warn`, `info`, `debug`, `trace` — the base messages' verbosity only; see [Watching activity](#watching-activity) |
| `--log-detail <level>` | `MARSHAL_LOG_DETAIL` | `access` | `log`, `access`, `audit` — how much per-request lines carry |
| `--log-sink <dest>` | `MARSHAL_LOG_SINK` | `auto` | `auto`, `stdout`, `journald`, `syslog` |
| `--log-format <fmt>` | `MARSHAL_LOG_FORMAT` | `auto` | `auto`, `pretty`, `json` — stdout only |

```bash
marshal --config /etc/bot-marshal/marshal.yaml --log debug serve
```

**`marshal config check`** — loads and validates the config, prints every diagnostic, exits
non-zero on any error. Warnings do not fail the check but are worth reading; `serve` logs
them at startup and refuses to start on an error the same way. Every subcommand — this one
included — checks the config file exists before doing anything else, and says so clearly
(naming the exact path it looked at) rather than surfacing a bare I/O error, since the first
thing most people hit is the default path they never typed.

**`marshal ca init [--common-name <name>] [--days <n>]`** — generates a CA at the paths named
by `tls.ca_cert` / `tls.ca_key`. Refuses to overwrite an existing one. `--days` is the CA's
own validity period, defaulting to 825 (~2.3 years); it is unrelated to `tls.leaf_expiry_hours`,
which governs the much shorter-lived per-host leaves the CA signs while it is valid.

**`marshal ca export [--pem-only]`** — prints the CA certificate and, unless `--pem-only`,
the same trust instructions `ca init` prints. Useful for piping into a container image build
or a trust store update without regenerating anything.

**`marshal serve [--profile <name>] [--listen <addr>] [--audit-log <path>]`** — runs the
proxy until `Ctrl-C`. `--profile` overrides `sessions.unidentified.profile` for the
unattributed fallback; it does not select a single profile to run — every profile in the
config gets built and is reachable by whatever resolves a session into it. `--listen`
overrides `listeners.explicit.listen`. `--audit-log <path>` additionally writes the full
structured JSON record (evidence trail, status code — more than the log's one-line summary)
to a file, append mode, created if missing — see [Watching activity](#watching-activity).

**`marshal run --profile <name> [--isolation netns|cgroup|none] [--proxy <url>] [--dry-run] -- <command...>`**
— launches an agent under a profile. `--isolation` defaults to `netns` (see
[Identity](#identity) for what each mode actually buys). `--proxy` is the address the agent
is told to use — it is **not** read from the config file, so it must match whatever `serve`
is actually listening on (default `http://127.0.0.1:8080` matches `serve`'s own default).
`--dry-run` prints the command, environment, and (for `netns`) the sandbox wiring without
running anything — useful for checking what a launch would actually do before trusting it
with a real agent.

`marshal sandbox` also exists, is intentionally undocumented in `--help`, and should never be
invoked directly — it is the half of `--isolation netns` that `marshal run` re-execs itself as
inside the network namespace.

## Configuration and storage

With no `--config`, bot-marshal looks in `$XDG_CONFIG_HOME/bot-marshal/config.yaml` — usually
`~/.config/bot-marshal/config.yaml` — which is the right default for a normal user running
this interactively (`ca init`, `marshal run`, trying things out) and the wrong one for a
long-running service: pass `--config` explicitly there. A conventional system layout looks
like `/etc/bot-marshal/marshal.yaml`, with bundle includes and any secret files it references
kept alongside or under it — see [Running as a service](#running-as-a-service).

What bot-marshal writes to disk, and only what it writes:

| what | where | notes |
|---|---|---|
| CA certificate | `tls.ca_cert` | created by `ca init`; world-readable is fine, it is a certificate |
| CA private key | `tls.ca_key` | created by `ca init` at mode `0600`; whoever holds it can impersonate every site the agent talks to |
| Unix socket | `listeners.explicit.unix_socket` | recreated on every start — a leftover socket from a previous run is removed automatically, never left to block a restart |
| Audit log | `--audit-log <path>`, optional | JSON lines, append mode, created if missing; never truncated or rotated by bot-marshal itself |

That is the complete list. There is no database, no cache directory, and no other state
persisted between runs — `/v1/sessions` and `/v1/metrics` counters, and the judge's response
cache, all live in memory and reset on restart. A config `include` glob and any files a
`file`-type secret source or `tls.upstream_ca_certs` entry points at are read, never written.

`~/` at the start of a path (`tls.ca_cert`, `tls.upstream_ca_certs` entries, secret `file`
source paths) expands against `$HOME`. Nothing else is expanded — no `~user/`, no
environment variable substitution inside a path string.

## Running as a service

The proxy itself, and the agents `marshal run` launches, are two separate concerns that can
run as different users. Nothing requires them to be the same, and there is a reason to keep
them apart: the proxy process holds the CA private key and the real credentials
`request_transforms.secrets` inject, so it is worth minimising what else runs as that user.

A minimal systemd unit for the proxy itself:

```ini
# /etc/systemd/system/bot-marshal.service
[Unit]
Description=bot-marshal egress proxy
After=network.target

[Service]
User=bot-marshal
Group=bot-marshal
ExecStart=/usr/local/bin/marshal --config /etc/bot-marshal/marshal.yaml serve
Restart=on-failure
# Only if listeners.dns or listeners.explicit binds a port below 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --home-dir /var/lib/bot-marshal bot-marshal
sudo mkdir -p /etc/bot-marshal /var/lib/bot-marshal
sudo chown bot-marshal:bot-marshal /var/lib/bot-marshal
# tls.ca_cert / tls.ca_key in marshal.yaml should point under /var/lib/bot-marshal
sudo -u bot-marshal marshal --config /etc/bot-marshal/marshal.yaml ca init
sudo systemctl enable --now bot-marshal
```

If `listeners.transparent` is enabled, point `deploy/nftables.conf`'s `$MARSHAL_UID` at this
user's uid (`id -u bot-marshal`) so the ruleset excludes the proxy's own egress from the
redirect — see [Transparent](#capture) for why that matters.

**A genuine gotcha if you also run `marshal run` from automation as this same service user:**
`--isolation cgroup` and `--isolation netns` both go through `systemd-run --user`, which
needs a running *user* systemd instance for that account. An interactive login session has
one; a bare service account usually does not, unless lingering is enabled for it
(`sudo loginctl enable-linger bot-marshal`). Without that, `marshal run` fails outright rather
than silently falling back to a weaker mode — the same "fail loud, not quiet" choice made
everywhere else identity is involved.

## Watching activity

Base operational messages (startup, warnings, shutdown) always print. `--log-detail` adds a
line per request on top, at one of three levels — each a strict superset of the one before,
so this is a level, not a set of things to combine:

* **`log`** — no per-request lines at all, just the base messages.
* **`access`** (default) — one summary line per request: session, host, method, profile,
  which layer decided, how long it took. This is what you watch to see traffic.
* **`audit`** — the same line with everything else added: status code, whether the verdict
  was cached, `would_deny`, and the full evidence trail. Noticeably bulkier — reach for it
  while a policy is still being worked out (`--log-detail audit`), and drop back to `access`
  once it's settled.

Whatever `--log-detail` is set to, it all goes to the same place and renders the same way —
one destination and one format, not one per level:

* **`--log-sink`** (`auto` by default) picks the destination: **journald**, if `JOURNAL_STREAM`
  is set (true for any systemd unit whose stdout/stderr is the journal) and the socket
  connection actually succeeds; else classic **syslog** (`/dev/log` or `/var/run/syslog`),
  the common case on non-systemd or minimal Linux; else plain **stdout**. Each tier is a real
  connection attempt, not a guess. `stdout`/`journald`/`syslog` force one, erroring out if
  it's not actually reachable rather than silently landing somewhere else — useful when you
  want plain stdout while running under something that sets `JOURNAL_STREAM`.

* **`--log-format`** (`auto` by default; stdout only — journald and syslog format
  themselves) decides how stdout renders every line: `auto` checks whether stdout
  is actually a terminal — a human watching `marshal serve` in a shell gets short, coloured
  lines; anything reading the stream programmatically (`docker logs`, a file redirect, a
  collector that doesn't set `JOURNAL_STREAM`) gets one JSON object per line, unprompted, no
  flag needed. `pretty`/`json` forces one regardless of what stdout actually is.

Under journald, every field lands as a real, structured journal field (`session` → `F_SESSION`,
`host` → `F_HOST`, …), so `journalctl` *is* the follow/watch command:

```bash
journalctl -u bot-marshal -f                                       # follow, human-readable
journalctl -u bot-marshal -o json -f | jq -c 'select(.TARGET=="access")'
journalctl -u bot-marshal FIELD=F_HOST=api.github.com               # everything for one host
```

`tracing`'s fields are flat, so `audit`'s evidence trail travels as a JSON *string* rather
than a nested value there and in the `json` stdout format — still fully queryable
(`jq '.trail | fromjson'`), just not natively nested. For a pristine, natively-nested,
durable copy independent of all of the above, `--audit-log <path>` additionally writes the
full record as real JSON to a file (append mode, created if missing).

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

**Interception is mandatory, not a fallback.** `marshal serve` refuses to start without a CA
— run `marshal ca init` first. A plain relay cannot enforce per-request policy, and it cannot
even guarantee the client reaches the host it claimed: shared-IP hosting (a CDN or load
balancer serving many sites off one address) routes by the TLS SNI *inside* the tunnel, which
a relay never inspects. A client can `CONNECT good.example.com` — correctly resolved, guard
approved — then present `SNI: evil.example.com` and have the origin serve that instead,
entirely unseen by a proxy that only relays bytes. Interception defeats this structurally: the
proxy re-originates its own TLS to upstream keyed on the CONNECT authority, never on anything
the client claims inside the tunnel. The one sanctioned exception is `tls.passthrough`, for
clients that pin certificates and would refuse the proxy's own cert; a passthrough host still
gets the same SNI cross-check on its plain relay, and the SOCKS5 front-end gets identical
treatment to HTTP CONNECT — same mandatory interception, same passthrough exception, same
SNI check.

## Rolling it out

Turning default-deny on for an existing agent breaks everything it was quietly relying on,
and that list cannot be known in advance. Warn mode is how it gets discovered:

```yaml
profiles:
  coding-agent:
    mode: warn      # run the whole chain, record refusals, forward anyway
```

Audit records then carry `would_deny: true` while `action` stays `allow`. Filter on it to
build the allowlist from real traffic, then set `mode: enforce`. It is deliberately noisy —
a startup warning, a `config check` warning, a log line per request, and a
`warn_only_profiles` field in `/v1/healthz` — because a proxy silently in warn mode is worse
than no proxy: somebody believes it is protecting them.

## Operating it

```yaml
listeners:
  management:
    listen: "127.0.0.1:9092"
    api_key_env: "MARSHAL_MANAGEMENT_KEY"
```

| endpoint | auth | purpose |
|---|---|---|
| `GET /v1/healthz` | none | alive, generation, profiles, warn-mode profiles |
| `GET /v1/metrics` | none | Prometheus counters by profile and session |
| `GET /v1/sessions` | bearer | what each agent has done |
| `POST /v1/reload` | bearer | re-read config and swap atomically |

Reload builds the entire new configuration — every chain, transform and resolver — before
swapping a single pointer. **A reload that fails changes nothing**, and says so:

```json
{ "status": "rejected",
  "error": "profiles.base.policy[0]: references unknown bundle `does-not-exist`",
  "note": "the previously loaded configuration is still in effect" }
```

A connection reads the runtime once and keeps that view, so a reload never changes the rules
under a request already in flight.

¹ OpenTelemetry export is not implemented — see *Not built* below.

## Capture

Three ways traffic reaches the proxy, in decreasing order of how much the client must
cooperate:

| mode | client must | strength |
|---|---|---|
| explicit | set `HTTP_PROXY` / use SOCKS5 | relies entirely on cooperation |
| transparent | nothing — nftables redirects it | holds while the firewall rules do |
| DNS | point its resolver at the proxy | a convenience, not a boundary |

**Transparent** interception recovers the pre-redirect destination from conntrack via
`SO_ORIGINAL_DST`, then recovers the *hostname* separately from the TLS SNI or the HTTP
`Host` header. Both are needed: policy is written in terms of names, and an address is only
what the client's DNS happened to return, so a proxy that could see only `140.82.121.4` would
be back to the coarse filtering this project exists to improve on. `deploy/nftables.conf`
ships the ruleset, including the `filter` chain that makes the redirect binding rather than
advisory — without it, an agent using a non-standard port or QUIC walks straight past.

`SO_ORIGINAL_DST` is exercised against a real kernel redirect, not just its parsing — an
unprivileged network namespace (`unshare --net --map-root-user`) grants full `CAP_NET_ADMIN`
*inside* itself with no root needed, the same mechanism `--isolation netns` already relies on,
and a loopback-only redirect proves the identical code path a deployed ruleset uses.

**DNS** mode resolves every name to the proxy so unconfigured workloads arrive on their own.
Static records beat passthrough, which beats interception; TTLs are short so a stale answer
cannot outlive a policy change. `examples/docker/` shows two containers captured with no
proxy environment variables at all, told apart purely by source address.

Be clear about what DNS mode is not: a client that ships its own resolver, uses DNS-over-HTTPS,
or connects to a literal address never asks us. It is for workloads that cannot be configured.
Where bypass actually matters, use `marshal run --isolation netns`, or the firewall rules.

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

Config-wise this is one `sessions:` block: an ordered `resolvers` list (first match wins),
each entry mapping something the connection carries to a `session` name and a `profile`, plus
`unidentified` for the fallback when nothing matches:

```yaml
sessions:
  resolvers:
    - type: peer_cred                 # kernel-supplied uid — strongest, list it first
      enrich: true                    # needed for cgroup matching below; costs a /proc walk
      map:
        - uid: 1001
          session: "bot-ci"
          profile: base

    - type: launched                  # sessions `marshal run` registers — no map needed,
                                       # the cgroup naming convention *is* the registration

    - type: source_ip                 # containers / netns: one IP per agent
      map:
        - cidr: "172.20.0.10/32"
          session: "agent-a"
          profile: coding-agent

    - type: proxy_auth                # weakest — client-asserted — so it goes last
      credentials:
        - user: "agent-a"
          password_env: "MARSHAL_AGENT_A_PW"
          session: "agent-a"
          profile: coding-agent

  unidentified:                       # nothing matched
    profile: base                     # the most restrictive profile, never a permissive one
    action: allow_with_profile        # or `deny`, for a hard-fail posture
```

A resolved `session`/`profile` pair doesn't have to be declared anywhere else — the profile
just has to exist under `profiles:` (see [The policy chain](#the-policy-chain)). Every audit
record carries the resolved `session`, which `resolver` matched, and `attributed: false` when
none did — that's what makes `attributed: false` in a record a hard signal to look at, not
noise: it means every resolver missed and the request got the fallback profile above.

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
to permit the tunnel. Nothing reaches the upstream until a request-level verdict allows it. The only way a
connection is *not* eventually judged on the real request is `tls.passthrough`, where the
CONNECT verdict is the sole decision point and `default_action` governs it strictly — the
same trade a certificate-pinned client always makes by opting out of interception.

| Milestone | Contents | State |
|---|---|---|
| M0 | Workspace, core traits, config load + validate, CI | done |
| M1 | Explicit proxy (CONNECT + SOCKS5), chain runner, denylist + allowlist, upstream guard, audit | done |
| M2 | TLS MITM, streaming (WebSocket / SSE / chunked) | done |
| M3 | Secret injection, egress DLP, CEL rules layer | done |
| M4 | Session identity, profiles, `marshal run` | done |
| M4.5 | LLM judge layer | done |
| M5 | MCP tool-level policy | done |
| M6 | Transparent (nftables) and DNS interception | done |
| M7 | Management API, hot reload, warn mode, metrics | done¹ |

## The judge

```yaml
- layer: judge
  provider: { type: anthropic, model: "claude-haiku-4-5-20251001", api_key_env: ANTHROPIC_API_KEY }
  # or: provider: { type: openai, model: "...", api_key_env: OPENAI_API_KEY }
  # either provider takes an optional base_url — Azure OpenAI, OpenRouter, a local vLLM or
  # Ollama instance, an internal gateway. scheme://host[:port], no path; http:// is honoured
  # for a local server, not upgraded to https.
  #   base_url: "http://localhost:11434"
  scope: [{ host: "api.github.com", methods: ["POST", "PATCH", "DELETE"] }]
  prompt: "Allow only changes to repositories owned by gregbacchus. Deny anything ..."
```

Adding a provider is additive by design: the scoping constraints below live in the layer
itself, not in `AnthropicProvider`, so a new `Provider` implementation inherits them without
rework — one more config variant, one more `match` arm in `build_chain`. The two providers'
response shapes genuinely differ in a way worth knowing about if you add a third: Anthropic's
tool-use `input` is a native JSON object, while OpenAI's `function.arguments` is a
**JSON-encoded string** requiring a second decode — verified against OpenAI's own published
OpenAPI spec rather than assumed, specifically because guessing wrong here fails in a way
that looks like "the model returned nonsense" rather than "this needed one more parse".

The judge sees **method, host, path, and header names — never header values, never the
body**. It sends a description of the request to a third-party API, so anything shown there
is a potential leak; a header value is exactly where a credential lives, and the body is
exactly where proprietary content or a secret an earlier layer hasn't caught yet would be.
Neither is ever necessary to answer a scoping question, so neither is offered the chance to
leak.

The untrusted request travels inside explicit `<request>` tags in the message content, never
concatenated into the system prompt, and the verdict comes back through a forced tool call —
never parsed from prose. Those two close the mechanical injection surface: there is no string
an attacker controls that ever becomes an instruction, and no free text this layer ever
interprets as a decision. What that does *not* guarantee is that the underlying model resists
a sufficiently crafted `<request>` payload through that data channel — that is a live-model
behavioural property, not a parsing one, and no unit test proves it. Treat the judge as
defence-in-depth, not a substitute for the layers before it.

Verdicts cache on a normalised signature (method, host, path, sorted header names) with a
configurable TTL, and a circuit breaker opens after consecutive failures so an unhealthy
provider degrades to `on_error` instead of adding latency to every request in scope while it
is down.

## Not built

**OpenTelemetry export.** The audit log is already structured JSON carrying the full layer
trail, session attribution, status and timing, and `/v1/metrics` covers scraping. OTLP would
add correlation with an agent's own traces, which is genuinely useful — but it is a large
dependency tree for something a log shipper largely covers, so it is left as a deliberate
decision rather than assumed.

**An interactive approval decider.** The `Defer` verdict and the `Decider` trait exist and
the chain resolves them; the only implementation refuses. A human-in-the-loop approval flow
plugs in without touching the chain.

**Rate limits and budgets.** Per-session counters exist and are exported, which is the
groundwork; enforcement does not.

**Response body transforms — `summarize`, `compact`, `redact`.** Declared as config shapes
since M3 (they determine whether a response can stream, which the rest of the design has to
respect) but never implemented. A profile naming one fails to start rather than serving a
response that was supposed to be rewritten, unrewritten — which is why the shipped
`coding-agent` profile, which configures a `redact`, still does not start end to end.

## Layout

`marshal-core` holds the traits and types and depends on no other crate in the workspace;
everything else builds on it. That keeps the boundaries honest and the policy chain testable
without a network.
