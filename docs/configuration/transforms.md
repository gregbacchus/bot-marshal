# Transforms

Transforms decide **how** an allowed request is rewritten. They run only after the
[policy chain](policy-layers.md) has allowed, and the two directions are independent:

* **`request_transforms`** rewrite a request on its way out — setting and filtering headers,
  routing an LLM model, injecting a credential at the boundary so the agent never holds it.
* **`response_transforms`** rewrite what comes back — translating a routed LLM response or
  enforcing a response size limit. Body redaction, summarization and compaction are
  [not implemented](#unimplemented-body-transforms).

## LLM routing and model mapping

`request_transforms.llm_router` maps stable client-facing model aliases onto an origin host,
path, model id and OpenAI Chat Completions, Anthropic Messages or native System One wire format.
It translates between the two chat formats, including streaming SSE and tool calls; native
decision requests map only to native decision origins. The
request half runs before secret injection; the paired response half translates back into the
client's dialect.

This transform has enough configuration and security consequences to warrant its own page:
[LLM routing](llm-routing.md). Native System One endpoints use the same router;
see [Decision APIs](decision-apis.md) for decision-only mapping and limits.

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

### Filtering headers: allow or deny

```yaml
request_transforms:
  headers:
    allow: ["accept*", "content-*", "user-agent", "authorization"]

response_transforms:
  headers:
    deny: ["set-cookie", "server"]
```

Exactly one of `allow` or `deny` — they are two different default behaviors, not two lists
that combine, and `marshal config check` rejects both set together (or neither). `allow` is
default-deny: a header not named is dropped. `deny` is default-allow: only a header matching a
pattern is dropped, everything else passes through. Globs (`*`) match a family; matching is
case-insensitive, as header names are.

A filter never touches wire-framing headers — `Host`, `Content-Length`, `Connection`,
`Transfer-Encoding`, and the rest of what [`request_header_is_managed`](../../crates/marshal-config/src/model.rs)
and its response-side counterpart name — regardless of what `allow`/`deny` says. An `allow`
list that forgets `host`, or a `deny` pattern that happens to match `content-*`, filters what a
config author meant to filter without breaking the request or response those headers make
possible in the first place.

Request-side filtering runs before `set_headers` and before secret injection, so a client's own
header is dropped (or kept) first, and marshal's own additions are never at risk of being
filtered out from under it. Response-side filtering runs last, after any `response_transforms.body`
`limit` has had its say — an `allow` list governs exactly what reaches the agent, including a
header a body limiter itself added (`x-marshal-response-limited`); list it explicitly if a
profile using both needs the agent to see it.

## Secret injection

Marshal supplies the real credential at the proxy boundary; the client does not need a
placeholder or a live credential to make an authenticated request. This protects a credential
only when the agent cannot obtain it independently. Keep secrets out of the agent's inherited
environment, workspace and extra bind paths, and use a separate proxy account where practical.
`marshal run --isolation none` inherits its caller's environment; injection does not scrub it.
The env-file overlay is not inherited, but its file is still readable if the agent can access
that path. See [Production](../production.md) for account separation and
[Identity](identity.md#netns-enforces-rather-than-identifies) for filesystem access.

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

See [Secret injection examples](secret-injection-examples.md) for worked configs — OpenAI,
Anthropic, OpenRouter, Google, Azure, Claude Code, Codex, GitHub, Slack, Stripe, and others.

Every request the policy chain allows to `github.com` gets `Authorization: Basic
base64("x-access-token:<secret>")` set unconditionally — replacing whatever the client sent,
including nothing at all.

| field | |
|---|---|
| `source` | where the credential comes from: `env`, `file`, `oauth2`, or `oauth2_claim` — required for every `inject.type` except `sigv4`, which carries its own sources instead |
| `inject` | how, and where, to set the credential — see below |
| `rules` | the hosts this swap applies to — a credential is never offered to a host that shouldn't see it |

Five injection kinds:

* **`{ type: basic, username: "..." }`** — `Authorization: Basic base64("{username}:{secret}")`,
  what `git`, most package registries, and container registry logins use
  ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)).
* **`{ type: bearer }`** — `Authorization: Bearer {secret}`, a plain API token, e.g. an
  `npm` `_authToken` or a GitHub API PAT.
* **`{ type: header, name: "..." }`** — `{name}: {secret}`, the raw secret value set on an
  arbitrary header. Covers the common API-key pattern where a service defines its own header
  (`X-Api-Key`, `Api-Key`, or a vendor-specific name) instead of using `Authorization` at all.
* **`{ type: query, name: "..." }`** — `?{name}={secret}` appended to the request's query
  string, percent-encoded, alongside whatever query the client already sent. For APIs that
  accept (or only accept) the key this way.
* **`{ type: sigv4, ... }`** — AWS Signature Version 4. See below; this kind needs its own
  section because it signs the whole request rather than setting one static value.

```yaml
request_transforms:
  secrets:
    - name: SERVICE_API_KEY
      source: { type: env, var: SERVICE_API_KEY }
      inject: { type: header, name: "X-Api-Key" }
      rules: [{ host: "api.example.com" }]
```

### Where `env` sources get their value

`{ type: env, var: SERVICE_API_KEY }` reads the variable from marshal's environment, or from the
[env file](README.md#the-env-file) if the environment does not have it — a `KEY=value` file next
to the config, `.env` by default. The environment wins where both have a value.

The env file is read by marshal and is never loaded into the environment an agent could inherit,
so a credential kept there stays as far from the agent as one kept in a `file` source.

### File sources and rotation

```yaml
request_transforms:
  secrets:
    - name: SERVICE_TOKEN
      source: { type: file, path: "/etc/bot-marshal/service-token.json", ttl: "5m", json_key: token }
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
```

| field | default | meaning |
|---|---|---|
| `path` | required | file to read; leading `~/` expands against marshal's `$HOME` |
| `ttl` | `5m` | how long a read value is cached; a later request rereads after expiry |
| `json_key` | unset | a top-level JSON key whose value must be a string |

Without `json_key`, surrounding whitespace is trimmed from the file's text. With it, the
file must parse as JSON and contain the named string field; it is not a dotted path or JSON
Pointer. Relative file paths resolve from marshal's working directory, unlike profile/bundle
directories and `state_dir`, which resolve beside the base config. Prefer absolute paths for
services. Validation builds the source but does not read its file; missing files and malformed
content fail when resolved. Rotate by replacing the file securely and allow for its TTL.

`oauth2_claim` is a fourth source type; it reads a claim from an earlier OAuth2 swap and is
covered in [OAuth2 credentials](oauth2.md#an-id-token-claim-as-a-second-header).

### AWS SigV4

```yaml
request_transforms:
  secrets:
    - name: AWS_S3
      inject:
        type: sigv4
        access_key_id: { type: env, var: AWS_ACCESS_KEY_ID }
        secret_access_key: { type: env, var: AWS_SECRET_ACCESS_KEY }
        session_token: { type: env, var: AWS_SESSION_TOKEN }  # optional, for temporary creds
        region: us-east-1
        service: s3
        max_body_bytes: 1048576   # optional, defaults to 1 MiB
      rules: [{ host: "*.s3.amazonaws.com" }]
```

SigV4 signs the request — method, canonical path and query, `host`, and a hash of the body —
with an access key pair, rather than setting one static header value. That needs two secrets,
not one, so a `sigv4` swap does not use the top-level `source` field at all; setting one
alongside `inject.type: sigv4` is a config error. `access_key_id` and `secret_access_key` are
each their own `{ type: env, ... }` / `{ type: file, ... }` source, exactly like the top-level
`source` field on every other kind. `session_token` is optional, for temporary/STS credentials.

**This kind buffers the request body**, capped by `max_body_bytes` (default 1 MiB) — the one
exception among the injection kinds, all of which otherwise only ever touch headers or the
query string. A body larger than the cap is refused, never signed unhashed. See
[ADR-0028](../adr/0028-sigv4-buffers-the-body.md) for why this proxy always hashes the real
body rather than falling back to AWS's `UNSIGNED-PAYLOAD` mode, and what that means for very
large signed uploads.

Only `host`, `x-amz-content-sha256`, and `x-amz-date` are signed headers — that is all AWS
requires. `X-Amz-Security-Token` is set when `session_token` is configured but, per AWS's own
rule for temporary credentials, is not itself part of the signature.

### OAuth2

`oauth2` is a **source**, not an injection kind: marshal calls a token endpoint, caches the
access token, and mints a new one when it expires, so the agent never holds a live credential.
It composes with all five injection kinds — `bearer` is what almost every API wants, but
nothing stops a service that expects its token on `X-Api-Key`.

```yaml
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_secret: { type: env, var: SERVICE_CLIENT_SECRET }
        scope: ["read:things"]
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
```

Five grants, private-key client authentication, an agent-driven `capture: in_band` flow, and
what this costs (blocking, revocation, redaction, the auth server's own egress rules) are their
own page: [OAuth2 credentials](oauth2.md). See also [ADR-0030](../adr/0030-oauth2-is-a-secret-source.md).

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

### Unimplemented body transforms

`redact`, `summarize` and `compact` are declared configuration shapes but **are not
implemented**. A profile naming any of them is rejected when `serve` builds its chain.
`config check` can parse these shapes and warn about buffering without proving they work.
Do not rely on them to scrub a response or to preserve streaming.

For reference, `redact` declares `patterns` (default `[]`) and a `max_bytes` buffering cap
(default 1 MiB). These fields are not an operational redaction guarantee. Marshal's learned
credential redaction applies to logs/audit output, not to arbitrary upstream response bodies.
See [Roadmap](../roadmap.md#not-built).

Implemented `limit` buffers the responses it governs. A buffering transform applied to SSE
fails with a structured `502`; upgraded connections bypass response-body transforms. Body
transforms have no per-host selector in this schema: use a separate profile without buffering
body transforms for SSE endpoints. A named bundle is reuse, not a runtime scope restriction.

## Named transform bundles

A `transforms/` directory holds named transform bundles — `request_transforms` and/or
`response_transforms` in one file, shared across profiles:

```yaml
# transforms/default-headers.yaml
request_transforms:
  headers:
    allow: ["accept*", "content-*", "user-agent", "authorization"]
```

A profile opts in by name — `transforms:` is a list, so more than one bundle can compose on
the same profile:

```yaml
# profiles/llm-agent.yaml
default_action: deny
transforms: [default-headers]
policy: []  # deny-all until you add an allow policy
```

```yaml
# profiles/llm-agent.yaml, using two bundles together
default_action: deny
transforms: [default-headers, claude-subscription]
policy: []  # deny-all until you add an allow policy
```

Composing is concatenation, not replacement: `secrets` and response `body` transforms from
every named bundle all apply, in the order listed. `set_headers` merges, a later bundle
winning on a key two bundles both set. A `headers` allowlist (request or response) is the one
piece that does not silently combine — at most one bundle in the list may set it on a given
side, since merging two allowlists would be a guess about which one governs rather than a
decision either bundle actually made; `marshal config check` rejects two that both try.

`transforms:` and embedded `request_transforms:` / `response_transforms:` are **mutually
exclusive on one profile** — `marshal config check` rejects setting both rather than silently
picking one.
