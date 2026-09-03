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

See [Secret injection examples](secret-injection-examples.md) for worked configs — OpenAI,
Anthropic, OpenRouter, Google, Azure, Claude Code, Codex, GitHub, Slack, Stripe, and others.

Every request the policy chain allows to `github.com` gets `Authorization: Basic
base64("x-access-token:<secret>")` set unconditionally — replacing whatever the client sent,
including nothing at all.

| field | |
|---|---|
| `source` | where the credential comes from: `{ type: env, ... }`, `{ type: file, ... }`, or `{ type: oauth2, ... }` — required for every `inject.type` except `sigv4`, which carries its own sources instead |
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

Every other source hands back a credential somebody else obtained. `oauth2` *obtains* one:
marshal calls a token endpoint, caches the access token for its stated lifetime, and mints a
new one when it expires. The agent holds nothing — and unlike a long-lived API key, there is
nothing long-lived for it to hold in the first place.

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

It is a **source**, not an injection kind, so it composes with all five: `bearer` is what
almost every API wants, but a service expecting its token on `X-Api-Key` works too, with no
special case. See [ADR-0030](../adr/0030-oauth2-is-a-secret-source.md).

`name` is required for an `oauth2` source. It keys the token store and the redaction label, so
marshal needs it before the credential exists — there is nothing to derive it from.

| field | |
|---|---|
| `token_endpoint` | the full URL, path included |
| `client_id` | |
| `grant` | `client_credentials` (default), `refresh_token`, `jwt_bearer`, `authorization_code`, `device_code` |
| `client_auth` | `client_secret_basic` (default), `client_secret_post`, `private_key_jwt`, `none` |
| `client_secret` | itself a source — `{ type: env, ... }` or `{ type: file, ... }`. Required unless `client_auth: none` |
| `refresh_token` | a source. Required by `grant: refresh_token`; meaningless for the others |
| `scope` | a list, joined with spaces per RFC 6749 |
| `audience` | sent as `audience=` when set |
| `extra_params` | name/value pairs sent verbatim on every token request — the escape hatch for a provider this does not otherwise model (`resource`, a tenant id, a vendor flag) |
| `expiry_skew` | subtracted from the stated lifetime so a token cannot expire in flight. Defaults to `60s` |
| `timeout` | how long any single call to the provider may take. Defaults to `10s` |

#### Grants

**`client_credentials`** is machine-to-machine and needs nothing but the client credential. It
is the only grant that works with no state and no enrolment.

**`refresh_token`** presents a long-lived refresh token that something outside marshal manages:

```yaml
      source:
        type: oauth2
        grant: refresh_token
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_secret: { type: env, var: SERVICE_CLIENT_SECRET }
        refresh_token: { type: file, path: /etc/bot-marshal/service-refresh-token }
```

If the provider *rotates* refresh tokens this grant cannot keep up: marshal does not own that
file or environment variable and will not rewrite it, so it logs a warning and the configured
value goes stale. Use an interactive grant against a rotating provider.

**`jwt_bearer`** ([RFC 7523 §2.1](https://www.rfc-editor.org/rfc/rfc7523#section-2.1)) signs
an assertion with a private key and exchanges it — how a Google service account, Salesforce, or
Snowflake authenticates a workload with a key rather than a password. Nothing to enrol and
nothing to refresh: every mint signs a fresh assertion.

```yaml
      source:
        type: oauth2
        grant: jwt_bearer
        token_endpoint: https://oauth2.googleapis.com/token
        client_id: svc@project.iam.gserviceaccount.com
        client_auth: none
        private_key: { type: file, path: /etc/bot-marshal/sa.json, json_key: private_key }
        scope: ["https://www.googleapis.com/auth/cloud-platform"]
```

`private_key` is itself a source, so a Google service-account JSON file — which is JSON with
the PEM inside it — is read by the existing `file` source with `json_key: private_key` and no
special case. PKCS#8 and the older PKCS#1/SEC1 PEM forms are all accepted.

| field | |
|---|---|
| `private_key` | a source yielding a PEM. Required by `jwt_bearer` and `private_key_jwt` |
| `algorithm` | `RS256` (default) or `ES256`. `HS256` is deliberately absent — it is a shared secret wearing asymmetric clothes, so it offers nothing over `client_secret_basic` |
| `key_id` | the assertion's `kid` header, for a provider publishing more than one key |
| `issuer` | the assertion's `iss`. Defaults to `client_id` |
| `subject` | the assertion's `sub`. Defaults to `issuer`; set it to an impersonated user for Google's domain-wide delegation |
| `assertion_audience` | the assertion's `aud`. Defaults to `token_endpoint` |
| `assertion_lifetime` | defaults to `5m` — an assertion is used once, immediately |

`scope` is sent both in the assertion and in the form body. RFC 7523 permits it in the form;
Google reads it only from the assertion; sending both is the union of what providers accept.

**`client_auth: private_key_jwt`** ([RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523#section-2.2))
is the same signing machinery used for *client authentication* instead. It composes with any
grant, uses the same `private_key`/`algorithm`/`key_id` fields, and means there is no client
secret to rotate or to leak:

```yaml
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: private_key_jwt
        private_key: { type: file, path: /etc/bot-marshal/client.pem }
        algorithm: ES256
        key_id: "2026-09"
```

Each client assertion carries a fresh `jti`, which is what lets a provider reject a replayed one.

**`authorization_code`** and **`device_code`** are enrolled once by a human and then run
unattended. Both require [`state_dir`](README.md#state_dir), because the refresh token they
produce is the only copy and has to survive a restart. Until a swap is enrolled its requests
are refused with a message saying to run
[`marshal secrets oauth login`](../cli.md#marshal-secrets-oauth-login-name---open---timeout-duration),
rather than failing obscurely.

```yaml
      source:
        type: oauth2
        grant: authorization_code
        token_endpoint: https://auth.example.com/oauth2/token
        authorization_endpoint: https://auth.example.com/oauth2/authorize
        redirect_uri: http://127.0.0.1:7777/callback   # loopback only — marshal binds it
        client_id: marshal
        client_secret: { type: env, var: SERVICE_CLIENT_SECRET }
        scope: ["offline_access", "read:things"]
```

```yaml
      source:
        type: oauth2
        grant: device_code
        token_endpoint: https://auth.example.com/oauth2/token
        device_authorization_endpoint: https://auth.example.com/oauth2/device
        client_id: marshal
        client_auth: none
        scope: ["offline_access"]
```

| field | |
|---|---|
| `authorization_endpoint` | required by `authorization_code` |
| `redirect_uri` | required by `authorization_code`. **Loopback only** — `marshal secrets oauth login` binds it to receive the code, and a redirect anywhere else would deliver the code to something that is not marshal |
| `device_authorization_endpoint` | required by `device_code` |

`scope` almost certainly needs `offline_access` (or Google's `access_type: offline` in
`extra_params`): without it most providers complete the flow and issue no refresh token, and
marshal refuses to record an enrolment that would not survive a restart.

`device_code` is the one that works over SSH — it binds nothing and needs no browser on the
host.

#### In-band capture

Everything above assumes marshal was given, or enrolled, the credential in advance. `capture:
in_band` covers the other case: an **agent** that drives an OAuth authorization flow itself.

Left alone, that ends with the agent holding live tokens — precisely the state boundary
injection exists to prevent. Under `capture: in_band` it ends with the agent holding nothing:

```yaml
      source:
        type: oauth2
        grant: authorization_code
        capture: in_band
        token_endpoint: https://auth.example.com/oauth2/token
        authorization_endpoint: https://auth.example.com/oauth2/authorize
        client_id: marshal
        client_secret: { type: env, var: SERVICE_CLIENT_SECRET }
        scope: ["offline_access"]
```

What happens, in order:

1. **The agent's authorization request has its PKCE challenge replaced** with one marshal
   derived from a verifier only marshal holds. Its `state` and `redirect_uri` are untouched, so
   the agent's own CSRF check still passes and the provider still recognises the redirect URI.
   From here, the code the provider will issue is redeemable *only* by marshal — not because
   the agent is blocked from trying, but because it does not hold the matching verifier.
2. **The redirect never reaches the agent with a real code in it.** Marshal intercepts the
   `Location` header, lifts the code out, and completes the exchange itself — a direct call to
   the token endpoint, out of band, nothing forwarded. The `code` the agent receives is an inert
   sentinel. The real code is replaced whether or not marshal's own exchange succeeded; if it
   failed, the agent must not get the chance either, and the failure surfaces as a refused API
   request naming the cause.
3. **The agent's own token request is answered locally and never forwarded** — a well-formed
   token response carrying a sentinel. Its state machine completes normally, on nothing. That
   response, like every response marshal synthesizes, carries `proxy-agent: bot-marshal`.

The sentinel is not a placeholder to be recognised later. Injection is unconditional, so
whatever the agent presents to the API is overwritten with the real token regardless.

Marshal also keeps the refresh token the exchange produced, exactly as
`marshal secrets oauth login` would — so the credential survives a restart without the agent
ever authorising again.

**What it costs, and when not to use it:**

* **Only `grant: authorization_code`.** The other grants have no authorization flow to take over.
* **Both endpoints must be `https`.** Capture depends on marshal seeing the *response*, which
  requires the connection to be intercepted; a plain `http` request through the explicit proxy
  is relayed instead. This is a config error, not a silent no-op.
* **A client that checks its own flow breaks.** One that verifies the challenge in the
  authorization URL matches the one it generated, or validates the token response against a
  nonce, will fail — correctly, from its point of view. There is no way to support both.
* **It is best-effort.** The provider redirects whoever made the authorization request. If that
  is a browser rather than the agent's HTTP client, the browser must also be behind the proxy.
  An authorization request made outside the proxy's capture is never rewritten at all.
  [`marshal secrets oauth login`](../cli.md#marshal-secrets-oauth-login-name---open---timeout-duration)
  is the guaranteed path; this is the convenient one.

`capture` defaults to `off`. See [ADR-0032](../adr/0032-marshal-owns-the-pkce-verifier.md) and
[ADR-0031](../adr/0031-a-responder-may-answer-a-request.md).

#### What this costs

**A request can block on a third party.** Minting happens on the request path, so a slow token
endpoint makes the first request after an expiry slow — bounded by `timeout`, because an
endpoint that accepts a connection and then goes silent would otherwise hang the request
indefinitely while every other request for that credential queued behind it. Failure is closed:
a request whose credential cannot be minted is refused, with the provider's own `error` and
`error_description` in the 403 body, never forwarded unauthenticated.

**A revoked token is not noticed until it expires.** Nothing invalidates a cached token when an
upstream rejects it, so a credential revoked at the provider ahead of its stated expiry goes on
being presented until the cached copy ages out. `marshal secrets oauth refresh <name>` forces a
new one.

**Concurrent requests on an expired token mint once**, not once each — some providers
invalidate the previous refresh token on every use, which turns a concurrent double refresh
into a broken credential rather than merely a wasted round trip.

**The token endpoint obeys `upstream.deny_cidrs` and `upstream.allow_private`**, the same
rules that constrain agent egress. A token endpoint on the public internet is unaffected; an
*internal* auth server on RFC1918 needs `upstream.allow_private: true`, which also opens agent
egress to private addresses. A refusal names the exact rule that blocked it.

**An OAuth2 swap never injects into its own endpoints.** The `token_endpoint` and
`authorization_endpoint` are excluded from injection automatically, whatever `rules` says —
they are frequently on the same host as the API. The authorization request is by construction
the one request in the flow that is not yet authenticated, and under `capture: in_band` setting
a credential on it is also circular: injecting means minting, minting needs the credential, and
the credential is what the request exists to obtain. The exclusion is recorded in the evidence
trail as `secrets.not_injected.<host><path>` rather than being silent.

**`tls.upstream_ca_certs` applies to marshal's own calls too.** An internal auth server behind a
private CA works without further configuration: the roots the proxy trusts for upstream traffic
are the roots marshal trusts when it calls a token endpoint for itself.

**Every credential in play is redacted** — the tokens a provider returns, and the client
secret, signing key and refresh token marshal presents. A minted token is redacted from the
moment it is minted rather than from startup; see
[ADR-0029](../adr/0029-the-redaction-set-is-learned-at-runtime.md).

**Nothing is minted at boot**, so starting the proxy never depends on an auth server being
reachable, never creates a credential nobody asked for, and — against a provider that rotates
refresh tokens — never consumes a rotation just by starting or reloading.

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
