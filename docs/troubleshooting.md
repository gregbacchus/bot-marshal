# Troubleshooting

Start with `marshal --config <path> config check`, then run the service in the foreground
with an explicit log destination. Validation does not establish CA availability, usable
listener sockets, compiled policy expressions or working upstream credentials.

```bash
marshal --config /path/to/config.yaml --log debug --log-detail audit \
  --log-sink stdout --log-format pretty serve --audit-log /tmp/marshal-debug.jsonl
```

Use the real config path. The audit file contains destinations, identities and policy
decisions; keep it private and remove it when no longer needed. Do not paste live credentials
into commands or diagnostic output. For an interactive tool launched by OAuth bootstrap,
write audit output to a file rather than interleaving proxy logs with the tool's terminal UI.

## The service will not start

| symptom | check and remedy |
|---|---|
| no config file | create the default file or pass `--config`; installation does not create one |
| CA paths unset or CA missing | set `tls.ca_cert` and `tls.ca_key`, then run `ca init` as the proxy user |
| permission denied reading CA/secret | check the proxy user's access, including parent directories; do not make the key world-readable |
| judge API-key error | every profile is built, including unused ones; supply the configured key to marshal or remove the judge from your runnable config |
| `redact`, `summarize` or `compact` is not implemented | these response-body shapes cannot run; use a runnable profile and do not assume response redaction happened |
| address already in use | inspect which process owns the configured TCP/Unix address; use another port or stop the old service |
| unknown profile/bundle/group | check filenames, directory overrides and mounts beside the base config |

Inspect startup logs for optional listeners that failed to bind even when the main TCP
listener started. A health response alone does not prove the Unix socket or every extra port
is available. The shipped full coding-agent config is a reference, not a runnable minimal
deployment; [Getting started](getting-started.md) supplies the latter.

## TLS trust fails

The client must trust marshal's CA certificate. Follow `marshal ca export`'s runtime-specific
instructions: Node, Python and curl may use different trust settings. Do not disable TLS
verification to hide the symptom. A newly generated CA invalidates old client trust.

For an upstream behind a private CA, add a PEM path to `tls.upstream_ca_certs`; this affects
both proxied upstream TLS and marshal's own judge/OAuth calls. It is separate from client
trust of marshal. A certificate-pinned client may require an explicit `tls.passthrough`
exception, which gives up request/body policy and transforms inside the tunnel.

## `marshal run` cannot launch or traffic is unattributed

`run` does not start `serve`. All modes currently require a `run` resolver; default `netns`
also requires a running proxy's configured Unix socket, a systemd user session, bubblewrap
and usable unprivileged namespaces. See the [platform matrix](getting-started.md#platform-prerequisites).

Run `--dry-run` to inspect the command and bind paths. User-local binaries and their symlink
targets need explicit binds; the sandbox does not expose all of `$HOME`. Binds grant
read-write access, so do not solve an install-path issue by exposing a whole secret directory.

Resolvers use the first match. A broad earlier `peer_cred` mapping can select a profile before
the `run` resolver sees the cgroup. Inspect `resolver`, `identity`, `profile` and `attributed`
in the audit record. For containers, inspect the source IP marshal actually sees; NAT can
collapse the addresses you expected to distinguish.

`cgroup` and `none` do not prevent direct egress. Switching to them can make a tool run but
changes the enforcement guarantee. On macOS, configure clients explicitly; Linux cgroup and
namespace attribution are not supplied by adding YAML alone.

## A request fails

Read the structured response and audit `reason.code`, not just the HTTP status:

| observation | interpretation |
|---|---|
| policy denial or unattributed refusal | a configured rule/fallback refused the request |
| upstream guard refusal | the resolved destination is private or explicitly blocked; client/container addressing alone is not a reason to enable private upstreams |
| transform/credential error | policy may have allowed, but rewriting or minting failed; the request was not sent unauthenticated |
| upstream `401`/`403` | a forwarded response may reflect provider permissions, scope or credential shape, rather than marshal policy |
| `action: allow`, `reason.code: model_catalog` or `oauth2_terminated` | marshal answered locally; no upstream forwarding is implied |
| `would_deny: true` | warn mode forwarded a request that enforce mode would refuse |

An early `allow` short-circuits later DLP/MCP/judge checks. For an allowlist that is only a
destination prerequisite, use `on_match: pass` and provide a later terminal allow for legitimate
requests. A chain of passes still ends at `default_action`.

## Streaming stops or a response is too large

Inspect `response_transforms.body` and `upstream.max_response_bytes`. An implemented body
limiter buffers and cannot run on SSE; use a separate streaming profile. `fail`/`truncate`
limiters reject encoded responses: request `Accept-Encoding: identity` if you need a readable
byte ceiling. A response limit counts bytes, not tokens, and UTF-8 truncation need not leave
valid JSON. See [Transforms](configuration/transforms.md#response-size-limits).

## OAuth login captures nothing or API requests still fail

For bootstrap, configure a CA and `state_dir`, use the printed proxy/trust settings and watch
the tool's token exchange. Browser/loopback flows need `--wait` or `--isolation cgroup`;
default `netns` isolates the browser and callback too. Those alternatives give up containment.
`--log debug` and safe request/response header metadata can explain a non-match without
printing credentials.

A provider must issue a refresh token for persistent enrolment. Bootstrap does not discover
the authorization endpoint or API resource host: edit the generated bundle's `rules` host,
attach it to the profile, and check it on the enrolled host. Ensure the policy allows that
resource host as well. Some resources require an ID-token claim header or a token exchange;
these are explicit options, not automatically discovered API requirements.

`oauth refresh` tests minting in its own CLI process; it does not invalidate a running
proxy's access cache. `logout` removes disk state but is not provider revocation and does not
clear another process's cached grant. See [OAuth2](configuration/oauth2.md#what-this-costs).

## A config edit has no effect

Check [the reload table](operations.md#what-reload-changes). Env-file values, listener settings,
the forwarding guard and state directory require restart. Existing connections retain their
old runtime, and OAuth caches survive reload. An already-set process environment variable wins
over an edited env-file value; `config check` reports that count. Use the same config path and
service account as the running proxy when validating changes.
