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

Header setters run before secret injection, so a configured header may contain a placeholder
that a later `secrets` transform replaces. Hop-by-hop headers are still removed before the
request is forwarded.

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

The agent holds only a placeholder. It can still authenticate to hosts the chain allows, but
the real credential never exists in the agent's process, environment or filesystem — so
compromising the agent no longer costs a rotation.

```yaml
request_transforms:
  secrets:
    - name: GITHUB_TOKEN
      source: { type: env, var: GITHUB_TOKEN }
      proxy_value: "marshal-github-placeholder"
      match_headers: ["authorization"]
      require: true
      rules: [{ host: "api.github.com" }]
```

| field | |
|---|---|
| `source` | `{ type: env, var: ... }` or `{ type: file, path: ... }` |
| `proxy_value` | the placeholder the agent is given and configured with |
| `match_headers` | which headers to search for the placeholder |
| `require` | refuse the request if it does not carry the placeholder at all, rather than forwarding it as-is |
| `rules` | the hosts this swap applies to — a credential is never offered to a host that shouldn't see it |

Secrets are redacted in every audit path and log line. `require: true` is the safe setting:
without it, a request that simply forgot the placeholder goes upstream unauthenticated, which
fails in a confusing way (a bare 401 the agent has no way to explain) rather than an obvious
one. If the secret source itself fails to resolve — the environment variable is unset, the
file is missing — the request fails regardless of `require`, since there is nothing to inject
either way.

### Basic auth

`git` over HTTPS, most package registries (npm, pip, cargo private registries), and container
registry logins all commonly send credentials as `Authorization: Basic
base64("user:password")` rather than a plain bearer token. This needs no separate
configuration: a swap that scans the `authorization` header (the default) finds the
placeholder whether it appears in plain text or inside a `Basic` challenge's decoded
credential, and re-encodes correctly when it swaps it in.

```yaml
request_transforms:
  secrets:
    - name: GIT_TOKEN
      source: { type: env, var: GIT_TOKEN }
      proxy_value: "marshal-git-placeholder"
      require: true
      rules: [{ host: "github.com" }]
```

```bash
git clone https://x-access-token:marshal-git-placeholder@github.com/owner/repo
```

The agent's git config, npm `.npmrc`, pip index URL, or `docker login` password never holds
anything but the placeholder; whichever of the two forms the client happens to send is
recognised without a flag to set, because `Basic <base64>` is a fixed wire format
([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)), not something the proxy has to guess at.

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
