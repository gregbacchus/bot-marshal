# CLI reference

## Global flags

Every subcommand accepts these, before the subcommand name:

| flag | env var | default | |
|---|---|---|---|
| `--config`, `-c <path>` | `MARSHAL_CONFIG` | `$XDG_CONFIG_HOME/bot-marshal/config.yaml` | usually `~/.config/bot-marshal/config.yaml`; a system service should pass an explicit path (see [Production](production.md)) |
| `--log <level>` | `MARSHAL_LOG` | `info` | `error`, `warn`, `info`, `debug`, `trace` — the base messages' verbosity only; see [Observability](observability.md) |
| `--log-detail <level>` | `MARSHAL_LOG_DETAIL` | `access` | `log`, `access`, `audit` — how much per-request lines carry |
| `--log-sink <dest>` | `MARSHAL_LOG_SINK` | `auto` | `auto`, `stdout`, `journald`, `syslog` |
| `--log-format <fmt>` | `MARSHAL_LOG_FORMAT` | `auto` | `auto`, `pretty`, `json` — stdout only |

```bash
marshal --config /etc/bot-marshal/marshal.yaml --log debug serve
```

Every subcommand checks the config file exists before doing anything else, and says so
clearly — naming the exact path it looked at — rather than surfacing a bare I/O error, since
the first thing most people hit is the default path they never typed.

## `marshal config check`

Loads and validates the config, prints every diagnostic, exits non-zero on any error.

Warnings do not fail the check but are worth reading; `serve` logs them at startup and refuses
to start on an error the same way.

```bash
marshal config check
```

## `marshal ca init [--common-name <name>] [--days <n>]`

Generates a CA at the paths named by `tls.ca_cert` / `tls.ca_key`, and prints per-platform
trust instructions. **Refuses to overwrite an existing one.**

`--days` is the CA's own validity period, defaulting to 825 (~2.3 years). It is unrelated to
`tls.leaf_expiry_hours`, which governs the much shorter-lived per-host leaves the CA signs
while it is valid.

## `marshal ca export [--pem-only]`

Prints the CA certificate and, unless `--pem-only`, the same trust instructions `ca init`
prints. Useful for piping into a container image build or a trust store update without
regenerating anything.

## `marshal serve [--profile <name>] [--listen <addr>] [--audit-log <path>]`

Runs the proxy until `Ctrl-C`.

| flag | effect |
|---|---|
| `--profile <name>` | overrides `identities.unidentified.profile` for the unattributed fallback |
| `--listen <addr>` | replaces `listeners.explicit.listen` entirely with this one address |
| `--audit-log <path>` | additionally write the full structured JSON record to a file |

`--profile` **does not select a single profile to run.** Every profile in the config gets
built and is reachable by whatever [resolves an identity](configuration/identity.md) into it;
this flag only changes which one catches traffic nothing could attribute.

`--audit-log` writes the complete record — evidence trail, status code, more than the log's
one-line summary — in append mode, created if missing. See
[Observability](observability.md#the-audit-log).

## `marshal run --profile <name> [--isolation netns|cgroup|none] [--proxy <url>] [--bind <path>] [--dry-run] -- <command...>`

Launches an agent under a profile. See
[Identity › Launching an agent](configuration/identity.md#launching-an-agent) for what each
isolation mode actually buys.

| flag | default | |
|---|---|---|
| `--profile <name>` | required | a *named* profile, from `profiles/` |
| `--isolation` | `netns` | `netns` enforces, `cgroup` identifies, `none` sets env vars only |
| `--proxy <url>` | `http://127.0.0.1:8080` | the address the agent is told to use |
| `--bind <path>` | none, repeatable | extra path bound read-write inside `--isolation netns`; ignored by other modes |
| `--dry-run` | off | print the command, environment and sandbox wiring; run nothing |

`--proxy` is **not** read from the config file, so it must match whatever `serve` is actually
listening on. The default matches `serve`'s own default.

`--dry-run` is useful for checking what a launch would actually do before trusting it with a
real agent — for `--isolation netns` specifically, it prints the exact bind list the sandbox
gets, which is the fastest way to tell whether a missing file will be the difference between
the agent working and failing.

`--isolation netns` gives the agent only the workspace, the standard system directories, the
CA certificate, and the marshal socket — not the whole filesystem (see
[Identity](configuration/identity.md#netns-enforces-rather-than-identifies)). A tool that
needs something else, such as a package manager cache kept outside the workspace, needs
`--bind` for it explicitly:

```bash
marshal run --profile coding-agent --bind ~/.cache/uv -- uv sync
```

```bash
marshal run --profile coding-agent -- claude
marshal run --profile llm-agent --isolation cgroup -- python agent.py
```

## `marshal sandbox`

Exists, is intentionally undocumented in `--help`, and should never be invoked directly — it
is the half of `--isolation netns` that `marshal run` re-execs itself as inside the network
namespace.
