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

## Try it

```bash
cargo build --release
alias marshal=./target/release/marshal

mkdir -p ~/.config/bot-marshal
cat > ~/.config/bot-marshal/config.yaml <<'CFG'
tls:
  ca_cert: "~/.config/bot-marshal/ca.crt"
  ca_key: "~/.config/bot-marshal/ca.key"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { domains: ["api.github.com"] }
      on_match: allow
      on_miss: pass
CFG

marshal config check
marshal ca init
marshal serve --listen 127.0.0.1:8080
```

```bash
# allowed
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://api.github.com/zen
# 403, with a body saying which layer refused and why
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://example.com/
```

Then read **[Getting started](docs/getting-started.md)** for the walkthrough, and
**[Concepts](docs/concepts.md)** for the model everything else assumes.

## Documentation

Full documentation lives in **[docs/](docs/)**.

| | |
|---|---|
| [Getting started](docs/getting-started.md) | build, configure, first request |
| [Concepts](docs/concepts.md) | capture → identity → policy chain → transforms → audit |
| [CLI](docs/cli.md) | every subcommand and flag |
| [Configuration](docs/configuration/) | [profiles](docs/configuration/profiles.md) · [policy layers](docs/configuration/policy-layers.md) · [bundles](docs/configuration/bundles.md) · [transforms](docs/configuration/transforms.md) · [identity](docs/configuration/identity.md) |
| [Capture](docs/capture.md) | explicit, transparent (nftables), DNS |
| [Observability](docs/observability.md) | logs, audit trail, metrics |
| [Operations](docs/operations.md) | management API, hot reload, warn-mode rollout |
| [Production](docs/production.md) | dedicated service user, systemd |
| [Roadmap](docs/roadmap.md) | what is built, what deliberately is not |

## How it works, briefly

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
                              transforms (decide HOW) ──► upstream guard ──► audit
```

* **Identity is derived from the connection, never asserted by the client.** A kernel-supplied
  uid cannot be forged; a `Proxy-Authorization` header trivially can, and the resolvers are
  ranked accordingly.
* **Default-deny lives in `default_action`,** the terminal applied when every layer passed.
  Turning it off requires an explicit acknowledgement in config.
* **Ordering is semantic.** A denylist at position 1 beats a later LLM approval by being first.
* **Bodies stream by default.** A transform that needs buffering must declare it, and that
  declaration is what makes SSE, WebSockets and large uploads work.
* **Interception is mandatory.** A plain relay cannot enforce per-request policy, and cannot
  even guarantee the client reaches the host it claimed — see
  [Concepts](docs/concepts.md#why-interception-is-mandatory).

## Repository layout

```
crates/          eleven crates; marshal-core holds the traits and depends on no other
config/          a fuller example config, with profiles/, bundles/ and transforms/
deploy/          nftables ruleset for transparent mode
examples/docker/ compose: two containers captured with no proxy env vars at all
docs/            documentation
```

`AGENTS.md` covers working on this codebase.
