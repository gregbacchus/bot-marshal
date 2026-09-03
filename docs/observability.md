# Observability

## Detail levels

Base operational messages (startup, warnings, shutdown) always print. `--log-detail` adds a
line per request on top, at one of three levels — each a strict superset of the one before, so
this is a level, not a set of things to combine:

* **`log`** — no per-request lines at all, just the base messages.
* **`access`** (default) — one summary line per request: identity, host, method, profile,
  which layer decided, how long it took. This is what you watch to see traffic.
* **`audit`** — the same line with everything else added: status code, whether the verdict was
  cached, `would_deny`, and the full evidence trail. Noticeably bulkier — reach for it while a
  policy is still being worked out, and drop back to `access` once it's settled.

```
INFO allow identity=unidentified profile=default host=example.com method=GET layer=default_action duration_ms=51
```

## Where it goes

Whatever `--log-detail` is set to, it all goes to the same place and renders the same way —
one destination and one format, not one per level.

**`--log-sink`** (`auto` by default) picks the destination:

1. **journald**, if `JOURNAL_STREAM` is set (true for any systemd unit whose stdout/stderr is
   the journal) and the socket connection actually succeeds;
2. else classic **syslog** (`/dev/log` or `/var/run/syslog`), the common case on non-systemd
   or minimal Linux;
3. else plain **stdout**.

Each tier is a real connection attempt, not a guess. `stdout` / `journald` / `syslog` force
one, erroring out if it's not actually reachable rather than silently landing somewhere else —
useful when you want plain stdout while running under something that sets `JOURNAL_STREAM`.

**`--log-format`** (`auto` by default; stdout only — journald and syslog format themselves)
decides how stdout renders every line. `auto` checks whether stdout is actually a terminal: a
human watching `marshal serve` in a shell gets short, coloured lines; anything reading the
stream programmatically (`docker logs`, a file redirect, a collector that doesn't set
`JOURNAL_STREAM`) gets one JSON object per line, unprompted, no flag needed. `pretty` / `json`
forces one regardless.

## Under journald

Every field lands as a real, structured journal field (`identity` → `F_IDENTITY`, `host` →
`F_HOST`, …), so `journalctl` *is* the follow command:

```bash
journalctl -u bot-marshal -f                                       # follow, human-readable
journalctl -u bot-marshal -o json -f | jq -c 'select(.TARGET=="access")'
journalctl -u bot-marshal FIELD=F_HOST=api.github.com               # everything for one host
```

`tracing`'s fields are flat, so `audit`'s evidence trail travels as a JSON *string* rather than
a nested value there and in the `json` stdout format — still fully queryable
(`jq '.trail | fromjson'`), just not natively nested.

## The audit log

For a pristine, natively-nested, durable copy independent of all of the above:

```bash
marshal serve --audit-log /var/log/bot-marshal/audit.jsonl
```

One JSON object per line, append mode, created if missing, **never truncated or rotated by
bot-marshal itself** — point logrotate at it.

Each record carries the resolved identity, whether it was attributed, which resolver matched,
the profile, the deciding layer, the full evidence trail, status and timing. Injected secrets
are scrubbed from every audit path and log line.

### A request marshal answered itself

`action: allow` no longer implies the request reached the upstream. A
[`RequestResponder`](adr/0031-a-responder-may-answer-a-request.md) may answer it instead, and
the record says so in `reason`:

```json
{ "action": "allow", "method": "POST", "path": "/oauth2/token", "status_code": 200,
  "reason": { "layer": "oauth2.token", "code": "oauth2_terminated",
              "message": "marshal completed this OAuth2 exchange itself ..." } }
```

`reason.code` is the field to key on. Today `oauth2_terminated` is the only one, emitted when
[in-band capture](configuration/transforms.md#in-band-capture) answers a token request rather
than forwarding it. Every such response also carries `proxy-agent: bot-marshal` on the wire.

### OAuth2 log lines

Credential acquisition logs at `info` on the base log, independently of `--log-detail` (these
are not per-request lines):

| message | fields | when |
|---|---|---|
| `minted an oauth2 access token` | `secret`, `grant`, `expires_in_secs` | a token was obtained; once per expiry, not once per request |
| `substituted marshal's PKCE challenge into an authorization request` | `secret` | in-band capture rewrote an authorization request |
| `captured an authorization code in band and exchanged it` | `secret`, `scope` | capture succeeded |
| `captured an authorization code but could not exchange it` | `secret`, `error` | **at `error`** — the agent's flow appears to have succeeded, but requests needing the credential will be refused |
| `answered a token request locally` | `secret` | the agent's exchange was terminated at the proxy |
| `the provider rotated this refresh token, but it comes from a source marshal does not own` | `secret`, `source` | **at `warn`** — the configured value is now dead; see `grant: refresh_token` |

No value appears in any of them. `secret` is the swap name.

A repeated `minted an oauth2 access token` at high frequency means the cache is not holding —
usually a provider that omits `expires_in`, which is never cached because treating a token with
no stated lifetime as immortal would mean a revoked credential is never re-fetched.

## Metrics

`GET /v1/metrics` on the [management listener](operations.md) exposes Prometheus counters:

```
marshal_requests_total{profile="coding-agent",action="allow"}
marshal_requests_total{profile="coding-agent",action="deny"}
marshal_would_deny_total{profile="coding-agent"}
marshal_identity_requests_total{identity="agent-a",action="allow"}
```

Counters are per-request, not per-connection: once TLS is intercepted a single CONNECT carries
many requests, and counting tunnels would understate an agent's activity by whatever its
connection reuse happens to be.

`marshal_would_deny_total` is the [warn mode](operations.md#rolling-it-out) signal — the
requests a profile forwarded but would have refused.
