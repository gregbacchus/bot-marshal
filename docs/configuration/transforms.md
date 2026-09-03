# Transforms

Transforms decide **how** an allowed request is rewritten. They run only after the
[policy chain](policy-layers.md) has allowed, and the two directions are independent:

* **`request_transforms`** rewrite a request on its way out — setting and filtering headers,
  swapping a placeholder for a real credential so the agent never holds it.
* **`response_transforms`** rewrite what comes back — redacting a secret the upstream echoed,
  compacting a body too large to be useful.

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
responses it applies to are no longer streamable. `marshal config check` warns, and the
profile should scope it away from SSE and WebSocket endpoints.

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
