# Configuration

The config file is YAML. `marshal config check` validates it and is worth running before
every restart.

* [Profiles](profiles.md) — the unit of policy; embedded vs named, warn mode.
* [Policy layers](policy-layers.md) — `denylist`, `allowlist`, `rules`, `dlp`, `mcp`, `judge`.
* [Bundles](bundles.md) — named, reusable allow-lists.
* [Transforms](transforms.md) — header setting/filtering, secret injection, response rewriting.
* [Secret injection examples](secret-injection-examples.md) — worked configs for OpenAI, Anthropic, OpenRouter, Claude Code, Codex, GitHub, and others.
* [Identity](identity.md) — which agent is connecting, and `marshal run`.

## Where the config lives

With no `--config`, bot-marshal looks in `$XDG_CONFIG_HOME/bot-marshal/config.yaml` — usually
`~/.config/bot-marshal/config.yaml`. That is the right default for a normal user running this
interactively (`ca init`, `marshal run`, trying things out) and the wrong one for a
long-running service: **pass `--config` explicitly there.** A conventional system layout looks
like `/etc/bot-marshal/marshal.yaml`, with the profile, bundle and transform directories and
any secret files it references kept alongside — see [Production](../production.md).

`~/` at the start of a path (`tls.ca_cert`, `tls.upstream_ca_certs` entries, secret `file`
source paths) expands against `$HOME`. Nothing else is expanded — no `~user/`, no environment
variable substitution inside a path string.

## The base file

```yaml
listeners:
  explicit:
    listen: "127.0.0.1:8080"                   # CONNECT and SOCKS5, protocol sniffed
    # or a list — ["127.0.0.1:8080", "127.0.0.1:8081"] — for `listener_port` identity
    unix_socket: "/run/user/1000/marshal.sock" # unlocks SO_PEERCRED identity
  dns:
    enabled: false
    listen: "127.0.0.1:5353"
    proxy_ip: "127.0.0.1"
    passthrough: ["*.internal.corp", "localhost"]
  management:
    listen: "127.0.0.1:9092"
    api_key_env: "MARSHAL_MANAGEMENT_KEY"

tls:
  ca_cert: "~/.config/bot-marshal/ca.crt"
  ca_key: "~/.config/bot-marshal/ca.key"
  cert_cache_size: 1000
  leaf_expiry_hours: 72
  passthrough: []          # hosts never intercepted (certificate-pinned clients)

upstream:
  deny_cidrs:              # checked against every resolved IP, after DNS and before connect
    - "169.254.0.0/16"     # link-local, incl. cloud metadata endpoints
    - "127.0.0.0/8"
    - "::1/128"
  allow_private: false
  max_response_bytes: 0

state_dir: "~/.local/state/bot-marshal"   # optional; only OAuth2 enrolment needs it

profile:                   # the embedded fallback — required, see Profiles
  default_action: deny
  request_transforms:
    set_headers:
      Accept: "application/json"
      Accept-Encoding: "identity"
  response_transforms:
    body:
      - transform: limit
        max_bytes: 262144
        on_oversize: { action: fail }

identities:                # see Identity
  resolvers: []
  unidentified:
    action: allow_with_profile
```

`listeners.dns` is covered in [Capture](../capture.md); `listeners.management` in
[Operations](../operations.md).

## Splitting across files

The base config has exactly one embedded profile, `profile:` — the fallback applied to traffic
nobody could attribute. Every *named* profile lives one-per-file under a `profiles/` directory
next to the config file, and the same convention holds for `bundles/` and `transforms/`:

```
/etc/bot-marshal/
├── marshal.yaml          # listeners, tls, upstream, the embedded `profile:`, `identities:`
├── profiles/
│   ├── coding-agent.yaml # the filename is the profile's name
│   └── llm-agent.yaml
├── bundles/
│   ├── github.yaml
│   └── npm.yaml
└── transforms/
    └── default-headers.yaml
```

This is a **fixed convention, not an arbitrary include glob**. The filename is the name, and
each file's schema is scoped to that one thing, so a profile file structurally cannot also set
`tls:` / `listeners:` / anything else — `marshal config check` rejects a stray field there as
a parse error, not a silent no-op.

### Relocating the directories

`profiles_path` / `bundles_path` / `transforms_path` rename or relocate any of the three, if
the default name next to the config file doesn't fit — a bundle set shared outside this
config's own tree, for instance:

```yaml
profiles_path: "agent-profiles"                         # relative to this file, like the default
bundles_path: "~/.config/bot-marshal/shared-bundles"    # ~/ expands against $HOME
```

Relocating a directory doesn't loosen anything: a file found there is still deserialised as
nothing but a profile, bundle, or transform bundle, so the same structural guarantees apply
regardless of where the path points.

### Trusting a private CA

`tls.upstream_ca_certs` adds roots on top of the public ones. It applies to **both** kinds of
outbound connection marshal makes: proxied traffic on an agent's behalf, and calls marshal
makes as itself — an OAuth2 token endpoint, an LLM judge. An operator who says "trust this CA"
means both; trusting it for one and not the other would be a distinction with nothing behind it.

### `state_dir`

Everything above is configuration marshal is *given*. `state_dir` is the one directory marshal
*owns*: where it keeps state it produced itself, which today means OAuth2 refresh tokens
obtained by enrolment. Same resolution rules as the paths above — relative to this file, `~/`
expands against `$HOME`.

```yaml
state_dir: "~/.local/state/bot-marshal"   # a service would use /var/lib/bot-marshal
```

Leave it unset and marshal persists nothing: every credential it mints lives only as long as
the process, which is fine for `grant: client_credentials` and `grant: refresh_token` and
makes the interactive OAuth2 grants unusable — those are refused at startup rather than at the
first request.

The directory holds live credentials, so marshal creates it `0700` and each file `0600`, and
**refuses to use a directory anyone else can read** rather than quietly tightening it: a
refresh token that has already been readable by another local user wants re-enrolling, not
locking down after the fact.

Changing `state_dir` takes effect on restart, not on reload — moving live credentials to a new
directory underneath a running process would be worse than making the operator say when.

## What gets written to disk

| what | where | notes |
|---|---|---|
| CA certificate | `tls.ca_cert` | created by `ca init`; world-readable is fine, it is a certificate |
| CA private key | `tls.ca_key` | created by `ca init` at mode `0600`; whoever holds it can impersonate every site the agent talks to |
| Unix socket | `listeners.explicit.unix_socket` | recreated on every start — a leftover socket from a previous run is removed automatically, never left to block a restart |
| Audit log | `--audit-log <path>`, optional | JSON lines, append mode, created if missing; never truncated or rotated by bot-marshal itself |
| OAuth2 refresh tokens | `<state_dir>/oauth/<name>.json`, optional | mode `0600` in a `0700` directory; written by `marshal secrets oauth login` and rewritten whenever a provider rotates the token |

That is the complete list. There is no database and no cache directory — `/v1/identities` and
`/v1/metrics` counters, the judge's response cache, and OAuth2 *access* tokens all live in
memory and reset on restart. Files a `file`-type secret source or a `tls.upstream_ca_certs`
entry points at are read, never written.
