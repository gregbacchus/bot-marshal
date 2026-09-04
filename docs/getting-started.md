# Getting started

This walks from an empty machine to a request that the proxy actually judged. It uses a
deliberately minimal config — see [Configuration](configuration/) once it works.

## Install

Homebrew installs the appropriate prebuilt binary on macOS or Linux:

```bash
brew install gregbacchus/tap/bot-marshal
```

To build from source instead, see [Developing](https://github.com/gregbacchus/bot-marshal#developing).

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

Configuring an agent by hand with `HTTPS_PROXY` and `SSL_CERT_FILE` works, but
[`marshal run`](configuration/identity.md#launching-an-agent) is the intended path: it sets
those variables, gives the agent its own identity, and can put it in a network namespace
where the proxy is the *only* route out.

```bash
marshal run --profile coding-agent -- claude
```

That needs a named profile called `coding-agent`, which means splitting the config across
files — see [Profiles](configuration/profiles.md).

## The fuller example

`config/marshal.yaml` in this repo is worth reading next: bundles, secret injection, DLP, MCP,
and a judge-gated profile.

One thing to know before running it as-is — **`serve` builds every profile in the config up
front, not just the one `--profile` selects**, so a config containing a judge layer refuses to
start at all without `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` set. Export those first, or read
it as a reference rather than running it.
