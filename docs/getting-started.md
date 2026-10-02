# Getting started

This walks from an empty machine to a request that the proxy actually judged. It uses a
deliberately minimal config — see [Configuration](configuration/) once it works.

## Install

Homebrew installs the appropriate prebuilt binary on macOS or Linux:

```bash
brew install gregbacchus/tap/bot-marshal
```

To build from source instead, see [Developing](https://github.com/gregbacchus/bot-marshal#developing).

## Platform prerequisites

| workflow | Linux | macOS |
|---|---|---|
| `serve`, CA management, configuration validation, explicit proxy clients | supported | supported |
| `run --isolation none` | proxy variables only | proxy variables only |
| `run --isolation cgroup` | systemd user session required | unavailable: no systemd cgroups |
| `run --isolation netns` (default) | systemd user session, bubblewrap and usable unprivileged namespaces | unavailable: Linux namespace workflow |
| container example | Docker Compose or compatible Podman provider | Docker/Podman Linux VM and compatible Compose provider |

Installation does not create a configuration or start a daemon. Use explicit proxy variables
for macOS clients; `netns` is a Linux enforcement feature. All `marshal run` modes currently
require a `run` resolver in the configuration, including `none`; configuring the resolver does
not make Linux cgroup attribution available on macOS. Inspect the audit record rather than
assuming launch success means strong attribution. See [Identity](configuration/identity.md).

## Write a config

With no `--config`, every subcommand looks in one default place:
`$XDG_CONFIG_HOME/bot-marshal/config.yaml`, which on almost every Linux setup is
`~/.config/bot-marshal/config.yaml`. Nothing creates it for you — write it yourself first,
same as you would for any other tool that follows this convention.

```bash
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
```

That `profile:` block is the fallback applied to traffic nobody could attribute to a specific
agent. It is required, and with no [identity resolvers](configuration/identity.md) configured
yet it is the only profile in play.

Check it before anything else — this catches most mistakes before they matter:

```bash
marshal config check
```

## Generate a CA

Interception is mandatory, not a fallback: `marshal serve` refuses to start without a CA.
[Concepts](concepts.md#why-interception-is-mandatory) explains why a plain relay cannot
enforce per-request policy.

`ca init` writes the cert and key to the paths named by `tls.ca_cert` / `tls.ca_key` and
prints per-runtime trust instructions, preferring scoped environment variables over touching
the system store:

```bash
marshal ca init
```

## Run it

```bash
marshal serve --listen 127.0.0.1:8080
```

Point something at it, trusting the CA you just generated (`--cacert` here stands in for
whichever of `ca init`'s printed trust instructions fits your setup):

```bash
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://api.github.com/zen
```

That succeeds — `api.github.com` is explicitly allowlisted. Anything not allowlisted comes
back as a 403 whose body says which layer refused and why; a bare 403 just makes agents
retry-loop:

```bash
curl --cacert ~/.config/bot-marshal/ca.crt -x http://127.0.0.1:8080 https://example.com/
```

SOCKS5 works on the same port; the protocol is sniffed from the first byte:

```bash
curl --cacert ~/.config/bot-marshal/ca.crt --socks5-hostname 127.0.0.1:8080 https://api.github.com/zen
```

The terminal running `serve` shows a line per request — identity, host, method, profile,
which layer decided, how long it took. See [Observability](observability.md) for the other
detail levels and where else those lines can go.

## Point a real agent at it

A cooperative client can use the proxy on any supported host. Set trust/proxy variables in
its own terminal, following the runtime-specific instructions from `ca init`. Do not put the
proxy's real API credential in that terminal; keep it in marshal's env file or protected
credential source. Some clients require an authentication setting before sending any traffic;
consult their current client documentation rather than assuming proxy injection configures it.

For Linux network containment, extend the configuration from above. Stop the first `serve`
with `Ctrl-C`, then add these blocks to the base file:

```yaml
listeners:
  explicit:
    listen: "127.0.0.1:8080"
    unix_socket: "~/.config/bot-marshal/marshal.sock"
identities:
  resolvers:
    - type: run
```

Create a named profile that permits the first smoke request:

```bash
mkdir -p ~/.config/bot-marshal/profiles
cat > ~/.config/bot-marshal/profiles/coding-agent.yaml <<'CFG'
default_action: deny
policy:
  - layer: allowlist
    allow: { domains: ["api.github.com"] }
    on_match: allow
    on_miss: pass
CFG
marshal config check
marshal serve
```

In a second terminal, verify Linux prerequisites and run a system-installed client:

```bash
marshal run --profile coding-agent --dry-run -- /usr/bin/curl https://api.github.com/zen
marshal run --profile coding-agent -- /usr/bin/curl https://api.github.com/zen
```

Use your actual curl path if it differs. This checks namespace routing and trust before adding
an agent's larger dependency set. The proxy must be running before either invocation: it
creates the Unix socket. A successful request should be attributed to `pid-<pid>` by `run`.

Then add the domains your agent requires and its install/config paths using
[bind groups](configuration/bind-groups.md). A user-local `claude` binary, for example, is not
visible inside `netns` unless its invocation path and symlink target are bound. Use
[`--dry-run`](cli.md#marshal-run---profile-name---isolation-netnscgroupnone---proxy-url---bind-path---bind-group-name---dry-run----command)
to inspect the bind list. The minimal profile above is a routing check, not a complete policy
for an arbitrary coding agent. See [Troubleshooting](troubleshooting.md) for failures.

## The fuller example

`config/marshal.yaml` in this repo is worth reading next: bundles, secret injection, DLP, MCP,
and a judge-gated profile.

One thing to know before running it as-is — **`serve` builds every profile in the config up
front, not just the one `--profile` selects**, so a config containing a judge layer refuses to
start at all without `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` set. Export those first, or read
it as a reference rather than running it. The shipped `coding-agent` profile also declares
unimplemented response `redact`, so the complete shipped config cannot serve as written.
Use the minimal config above; see [Roadmap](roadmap.md#not-built).
