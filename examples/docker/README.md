# Capture without cooperation

The client containers here set **no proxy environment variables** and know nothing about
bot-marshal. Their resolver points at the proxy, so every hostname resolves to the proxy's
address and connections arrive on their own.

```bash
mkdir -p ca
cargo run --bin marshal -- --config marshal.yaml ca init
docker compose up --build -d
```

`agent-a` may reach GitHub; `agent-b` may reach the Anthropic API. Neither may reach the
other's host, and the only thing distinguishing them is their source address.

```bash
docker compose exec agent-a curl -sS -o /dev/null -w '%{http_code}\n' https://api.github.com/zen
docker compose exec agent-a curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/
docker compose exec agent-b curl -sS -o /dev/null -w '%{http_code}\n' https://api.anthropic.com/
```

The audit log shows each request attributed to a session by `source_ip`:

```bash
docker compose logs proxy | grep '"action"'
```

## What this does not do

DNS interception is a convenience for workloads that cannot be configured, not a containment
boundary. A client that ships its own resolver, uses DNS-over-HTTPS, or connects to a literal
address never asks us at all. `deploy/nftables.conf` closes those gaps on a host you control;
`marshal run --isolation netns` closes them for a process you launch.
