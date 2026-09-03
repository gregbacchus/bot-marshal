# Transforms

Transforms decide **how** an allowed request is rewritten. They run only after the
[policy chain](policy-layers.md) has allowed, and the two directions are independent:

* **`request_transforms`** rewrite a request on its way out — setting and filtering headers,
  injecting a credential at the boundary so the agent never holds it.
* **`response_transforms`** rewrite what comes back — redacting a secret the upstream echoed,
  limiting a body that would overload the agent's context, compacting a body too large to be
  useful.

## Header transforms

### Setting request headers

```yaml
request_transforms:
  set_headers:
    Accept: "application/json"
    X-Client-Version: "2026-09-03"
```

`set_headers` adds a header when it is absent and replaces the client-supplied value when it
is present. Header names are case-insensitive. Values are used exactly as configured; quote
values that YAML might otherwise interpret as a number, boolean, or date. Invalid HTTP header
names and values are rejected by `marshal config check` with the path to the offending entry.

`Host`, `Content-Length`, proxy-authentication headers, and hop-by-hop headers cannot be set:
the proxy owns destination routing and wire framing, and `config check` rejects attempts to
override them.

Header setters run before secret injection, so a `secrets` transform can still overwrite an
`Authorization` value a header setter configured. Hop-by-hop headers are still removed before
the request is forwarded.

The standard content-negotiation header is `Accept` (singular). A header named `Accepts` is
valid as a custom header, but most HTTP servers will not interpret it as content negotiation.

### Allow-listing headers

```yaml
request_transforms:
  headers:
    allow: ["accept*", "content-*", "user-agent", "authorization"]

response_transforms:
  headers:
    allow: ["content-*", "date", "etag", "cache-control", "retry-after"]
```

An allow-list, not a deny-list: a header not named is dropped. Globs match a family.

## Secret injection

The real credential never exists in the agent's process, environment, or filesystem — so
compromising the agent no longer costs a rotation. There is no placeholder for a client to
hold or present, and no cooperation required from it: the client does not need to know the
endpoint is authenticated in the first place.

```yaml
request_transforms:
  secrets:
    - name: GIT_TOKEN
      source: { type: env, var: GIT_TOKEN }
      inject: { type: basic, username: "x-access-token" }
      rules: [{ host: "github.com" }]
```

```bash
git clone https://github.com/owner/repo   # no credential anywhere in the command
```

Every request the policy chain allows to `github.com` gets `Authorization: Basic
base64("x-access-token:<secret>")` set unconditionally — replacing whatever the client sent,
including nothing at all.

| field | |
|---|---|
| `source` | `{ type: env, var: ... }` or `{ type: file, path: ... }` |
| `inject` | how to construct the `Authorization` header — see below |
| `rules` | the hosts this swap applies to — a credential is never offered to a host that shouldn't see it |

Two injection kinds:

* **`{ type: basic, username: "..." }`** — `Authorization: Basic base64("{username}:{secret}")`,
  what `git`, most package registries, and container registry logins use
  ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)).
* **`{ type: bearer }`** — `Authorization: Bearer {secret}`, a plain API token, e.g. an
  `npm` `_authToken` or a GitHub API PAT.

Secrets are redacted in every audit path and log line.

**Within a swap's host scope, *every* allowed request is authenticated** — not just ones the
agent tried to authenticate. `rules` is therefore the entire trust boundary for that
credential, not host-allowlist-plus-something-else. Scope a swap as narrowly as the endpoint
that actually needs it. See
[ADR-0027](../adr/0027-secret-injection-is-unconditional-only.md) for the full reasoning.

## Response body transforms

### Response size limits

```yaml
response_transforms:
  body:
    - transform: limit
      max_bytes: 262144
      on_oversize:
        action: truncate
        method: utf8
        marker: "\n...[response truncated by bot-marshal]"
```

`limit` bounds the response body presented to the agent. `max_bytes` counts bytes, not tokens.
The default `on_oversize` action is `fail`.

| action | result |
|---|---|
| `fail` | returns a small structured `502 Bad Gateway` response with `error: response_too_large` |
| `truncate` | preserves the upstream status and content type, retaining a prefix plus `marker` within `max_bytes` |
| `replace` | preserves the upstream status but replaces the body with the configured short UTF-8 message |

`truncate` supports two boundary methods:

* `utf8` (the default) backs up to a valid UTF-8 boundary before adding the marker. This is
  normally the right choice for JSON, source code, logs, and prose, although the truncated
  result is not guaranteed to remain valid JSON or another structured format.
* `bytes` cuts at the exact byte boundary. Use it only when byte-exact behavior matters; it can
  split a multi-byte character.

The marker counts toward `max_bytes`; if it consumes the entire budget, none of the upstream
prefix remains. A `replace` body must itself fit within `max_bytes`, which `marshal config
check` validates. Every action that changes a response sets `X-Marshal-Response-Limited` to
`fail`, `truncate`, or `replace`, corrects `Content-Length`, and removes stale
`Content-Encoding`.

```yaml
response_transforms:
  body:
    # Fail is the default and can be written explicitly.
    - transform: limit
      max_bytes: 262144
      on_oversize: { action: fail }

    # Replace the response with a known bounded message.
    - transform: limit
      max_bytes: 262144
      on_oversize:
        action: replace
        body: "Response omitted because it exceeded the agent context budget."
```

Compressed bodies need special care: their wire size does not bound the decoded content an
agent receives. `fail` and `truncate` therefore refuse any non-identity encoded response with
a structured `502`; `replace` can discard an encoded response when its wire bytes exceed the
limit. To enforce the limit against readable response bytes, pair it with
`request_transforms.set_headers.Accept-Encoding: "identity"`.

The deployment-wide `upstream.max_response_bytes` setting supplies a default `fail` limiter
for profiles without an explicit `limit`; `0` means uncapped. An explicit profile limit
replaces that default rather than combining with it.

### Other body transforms

```yaml
response_transforms:
  body:
    - transform: redact
      patterns: ["github-pat"]
```

Redaction closes the loop on injection: never let an injected credential echo back to the
agent through a response.

**A body transform stops the response streaming.** Bodies stream by default, and a transform
that rewrites content cannot run over a stream — so declaring one is a statement that the
responses it applies to are no longer streamable. `marshal config check` warns. A buffering
transform applied to SSE fails loudly with a structured `502` rather than being silently
skipped; upgraded connections bypass response-body transforms. Keep profiles with body
transforms away from SSE and WebSocket endpoints.

> `summarize` and `compact` are declared as config shapes but **not implemented** — a profile
> naming one fails to start. See [Roadmap](../roadmap.md#not-built).

## Named transform bundles

A `transforms/` directory holds named transform bundles — `request_transforms` and/or
`response_transforms` in one file, shared across profiles:

```yaml
# transforms/default-headers.yaml
request_transforms:
  headers:
    allow: ["accept*", "content-*", "user-agent", "authorization"]
```

A profile opts in by name:

```yaml
# profiles/llm-agent.yaml
default_action: deny
transforms: default-headers
policy: [...]
```

`transforms: <name>` and embedded `request_transforms:` / `response_transforms:` are
**mutually exclusive on one profile** — `marshal config check` rejects setting both rather
than silently picking one.
