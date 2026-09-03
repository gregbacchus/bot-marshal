# Secret injection: worked examples

A cookbook of `request_transforms.secrets` swaps for real APIs — mainly LLM providers, since
that's what most agents spend their egress on, plus a handful of others that come up constantly.
Each one is a complete, copy-pasteable `secrets:` entry. See [Transforms](transforms.md) for
what `source`, `inject` and `rules` mean and the full list of injection kinds; this page is
"what shape does provider X want", not the mechanism.

Every snippet here has been run through `marshal config check` and loads cleanly. None of them
is a recommendation to trust these hosts with more than the policy chain in front of them
grants — `rules` is the entire trust boundary for a swap (see
[ADR-0027](../adr/0027-secret-injection-is-unconditional-only.md)), so scope it as narrowly as
the endpoint that actually needs the credential, not as broadly as "the provider's whole domain"
out of convenience.

## Picking a shape

Most APIs fall into one of five buckets. If a provider isn't listed below, this is usually
enough to work it out from their docs:

| what their docs say | use |
|---|---|
| `Authorization: Bearer <token>` | `inject: { type: bearer }` |
| `Authorization: Basic <user:pass base64>` | `inject: { type: basic, username: "..." }` |
| a custom header (`X-Api-Key`, `api-key`, `X-Auth-Token`, ...) | `inject: { type: header, name: "..." }` |
| `?api_key=...` / `?key=...` in the URL | `inject: { type: query, name: "..." }` |
| "get a short-lived token from our OAuth endpoint first" | `source: { type: oauth2, ... }` — see below and [Transforms § OAuth2](transforms.md#oauth2) |
| AWS SigV4 (`Authorization: AWS4-HMAC-SHA256 ...`) | `inject: { type: sigv4, ... }` — see [Transforms § AWS SigV4](transforms.md#aws-sigv4) |

A provider that documents both Bearer and Basic (Stripe is one) — prefer Bearer. It's one
secret instead of a fixed username plus a secret, and it's usually the shorter path through
their docs.

---

## LLM providers

### OpenAI

Bearer token, nothing unusual.

```yaml
request_transforms:
  secrets:
    - name: OPENAI
      source: { type: env, var: OPENAI_API_KEY }
      inject: { type: bearer }
      rules: [{ host: "api.openai.com" }]
```

If requests carry an `OpenAI-Organization` or `OpenAI-Project` header, those aren't secrets —
set them with `set_headers` alongside this swap, not through injection.

### OpenRouter

Same shape as OpenAI — OpenRouter's API is intentionally OpenAI-compatible.

```yaml
request_transforms:
  secrets:
    - name: OPENROUTER
      source: { type: env, var: OPENROUTER_API_KEY }
      inject: { type: bearer }
      rules: [{ host: "openrouter.ai" }]
```

OpenRouter's own docs recommend an `HTTP-Referer` and `X-Title` header so usage shows up
correctly attributed on their dashboard — worth adding via `set_headers` if you use it, but
check their current docs for the exact header names before relying on it; that's attribution,
not authentication, so it isn't this page's concern.

### Anthropic (Claude API)

Anthropic uses a custom header, not `Authorization` — `x-api-key` — plus a required
`anthropic-version` header that has nothing to do with the credential and belongs in
`set_headers`.

```yaml
request_transforms:
  set_headers:
    anthropic-version: "2023-06-01"
  secrets:
    - name: ANTHROPIC
      source: { type: env, var: ANTHROPIC_API_KEY }
      inject: { type: header, name: "x-api-key" }
      rules: [{ host: "api.anthropic.com" }]
```

This is also what **Claude Code** uses when it's configured for direct API billing (the
`ANTHROPIC_API_KEY` path) rather than a Pro/Max subscription login — see below for the
subscription case, which is a different credential shape entirely.

### Google Gemini API

Gemini takes the key as a query parameter, not a header — a clean example of `type: query`.

```yaml
request_transforms:
  secrets:
    - name: GEMINI
      source: { type: env, var: GEMINI_API_KEY }
      inject: { type: query, name: "key" }
      rules: [{ host: "generativelanguage.googleapis.com" }]
```

### Azure OpenAI

Azure's own header, `api-key` (lowercase, no `Authorization` prefix at all), and the host is
per-deployment rather than a single shared one — so a swap here is usually scoped to a single
customer's resource name rather than a wildcard.

```yaml
request_transforms:
  secrets:
    - name: AZURE_OPENAI
      source: { type: env, var: AZURE_OPENAI_API_KEY }
      inject: { type: header, name: "api-key" }
      rules: [{ host: "your-resource-name.openai.azure.com" }]
```

### Google Vertex AI (service account, no static key at all)

Vertex AI authenticates with a Google service account rather than a long-lived key —
`grant: jwt_bearer` (RFC 7523) is built for exactly this, and it's the one entry here with no
static secret anywhere: marshal signs a fresh assertion and exchanges it for an access token on
every mint. See [Transforms § OAuth2](transforms.md#oauth2) for the field reference.

```yaml
request_transforms:
  secrets:
    - name: VERTEX
      source:
        type: oauth2
        grant: jwt_bearer
        token_endpoint: https://oauth2.googleapis.com/token
        client_id: your-service-account@your-project.iam.gserviceaccount.com
        client_auth: none
        # The service-account JSON file Google Cloud IAM gives you — the PEM is one field
        # inside it, and `json_key` reads straight into that field with no conversion step.
        private_key: { type: file, path: /etc/bot-marshal/vertex-sa.json, json_key: private_key }
        scope: ["https://www.googleapis.com/auth/cloud-platform"]
      inject: { type: bearer }
      rules: [{ host: "*.googleapis.com" }]
```

Scope `rules` down to `aiplatform.googleapis.com` if this credential shouldn't also authenticate
to every other Google API the service account happens to have IAM roles for.

---

## Coding agent CLIs

Both of the following tools are HTTP clients like any other from marshal's point of view — the
interesting part is *which* credential they end up presenting, since both support more than one
auth mode.

### Claude Code — API key mode

When `ANTHROPIC_API_KEY` is set in its environment, Claude Code talks straight to
`api.anthropic.com` exactly as described in the Anthropic section above. Reuse that swap; there
is nothing Claude-Code-specific about it.

### Claude Code — subscription login (`claude login`)

Logging in with a Claude Pro/Max subscription instead of an API key is a different thing
entirely: an interactive OAuth flow against Anthropic's own auth infrastructure, producing a
token scoped to the subscription rather than to API billing. Marshal's OAuth2 support
(`grant: authorization_code`, [Transforms § OAuth2](transforms.md#oauth2)) is built to acquire
exactly this shape of credential — but the concrete `client_id`, `authorization_endpoint` and
`token_endpoint` for this flow are not something documented here, because they belong to
Anthropic's client application and this project has no verified, stable values to publish as
fact. Anthropic's own tooling doesn't currently support running with a boundary proxy in front
of a subscription login anyway.

The template below is the shape the config would take *if* you have those three values (from
your own client registration, or from inspecting the tool's own OAuth requests) — treat it as a
starting point to fill in and test against `marshal config check`, not as something to paste
verbatim:

```yaml
request_transforms:
  secrets:
    - name: CLAUDE_SUBSCRIPTION
      source:
        type: oauth2
        grant: authorization_code
        token_endpoint: https://REPLACE-WITH-THE-REAL-TOKEN-ENDPOINT
        authorization_endpoint: https://REPLACE-WITH-THE-REAL-AUTHORIZE-ENDPOINT
        redirect_uri: http://127.0.0.1:41111/callback   # loopback only — marshal binds it
        client_id: REPLACE-WITH-THE-REAL-CLIENT-ID
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "api.anthropic.com" }]
```

Once the real values are in place, enroll once with:

```bash
marshal secrets oauth login CLAUDE_SUBSCRIPTION --open
```

which opens a browser, captures the redirect on marshal's own loopback listener, and stores the
resulting refresh token under `state_dir` — see [`state_dir`](README.md#state_dir). From then
on the swap mints its own access tokens unattended, and Claude Code itself never needs to hold
one. If instead you want Claude Code to drive its *own* login through the proxy and end up
holding nothing either, that's what `capture: in_band` is for
([Transforms § In-band capture](transforms.md#in-band-capture)) — a heavier mechanism, and worth
reading ADR-0032 before reaching for it.

### OpenAI Codex CLI — API key mode

Same story as Claude Code: with `OPENAI_API_KEY` set, Codex talks to `api.openai.com` exactly
as in the OpenAI section above. Reuse that swap.

### OpenAI Codex CLI — ChatGPT sign-in

Codex also supports signing in with a ChatGPT account instead of an API key, which is again an
OAuth flow with credentials specific to OpenAI's own client application. The same caveat as
Claude Code's subscription login applies — this page won't publish a guessed `client_id` and
call it correct. The shape is the same `authorization_code` + loopback `redirect_uri` template
above, pointed at `api.openai.com` instead, filled in with values from OpenAI's own client
registration or observed traffic, and enrolled the same way:

```bash
marshal secrets oauth login CODEX_SUBSCRIPTION --open
```

---

## A few other useful ones

### GitHub — git over HTTPS

The canonical example from [Transforms](transforms.md) — `git clone` with no credential
anywhere in the command:

```yaml
request_transforms:
  secrets:
    - name: GITHUB_GIT
      source: { type: env, var: GITHUB_TOKEN }
      inject: { type: basic, username: "x-access-token" }
      rules: [{ host: "github.com" }]
```

### GitHub — REST/GraphQL API

The API itself takes a plain Bearer token rather than the git-over-HTTPS Basic shape above —
scope it to `api.github.com` specifically so it doesn't leak onto plain `github.com` traffic
(and vice versa):

```yaml
request_transforms:
  secrets:
    - name: GITHUB_API
      source: { type: env, var: GITHUB_TOKEN }
      inject: { type: bearer }
      rules: [{ host: "api.github.com" }]
```

### Slack (Web API)

Bearer token — a bot token (`xoxb-...`) works exactly like any other Bearer credential.

```yaml
request_transforms:
  secrets:
    - name: SLACK
      source: { type: env, var: SLACK_BOT_TOKEN }
      inject: { type: bearer }
      rules: [{ host: "slack.com" }]
```

### Stripe

Stripe's docs lead with Basic auth (secret key as the username, blank password) but also accept
plain Bearer — take Bearer, since it's one secret instead of a fixed empty password sitting next
to a real one.

```yaml
request_transforms:
  secrets:
    - name: STRIPE
      source: { type: env, var: STRIPE_SECRET_KEY }
      inject: { type: bearer }
      rules: [{ host: "api.stripe.com" }]
```

### npm registry

```yaml
request_transforms:
  secrets:
    - name: NPM
      source: { type: env, var: NPM_TOKEN }
      inject: { type: bearer }
      rules: [{ host: "registry.npmjs.org" }]
```

### AWS S3 (SigV4)

Fully documented in [Transforms § AWS SigV4](transforms.md#aws-sigv4) — it needs an access key
pair rather than one secret, and it's the one kind that buffers the request body to hash it.
Not repeated here; that section is the reference.

### A generic internal API (OAuth2 client credentials)

The machine-to-machine case that most non-LLM SaaS and internal-platform APIs actually use —
Auth0, Okta, and most homegrown auth servers all speak this shape:

```yaml
request_transforms:
  secrets:
    - name: INTERNAL_API
      source:
        type: oauth2
        token_endpoint: https://your-tenant.auth0.com/oauth/token
        client_id: your-m2m-client-id
        client_secret: { type: env, var: INTERNAL_API_CLIENT_SECRET }
        # Most client_credentials providers want the target API identified this way rather
        # than (or as well as) scope — check whether yours calls this `audience`, `resource`,
        # or something else, and use `extra_params` if it's neither.
        audience: "https://your-internal-api.example.com"
      inject: { type: bearer }
      rules: [{ host: "your-internal-api.example.com" }]
```

`grant: client_credentials` is the default, so it doesn't need to be spelled out. See
[Transforms § OAuth2](transforms.md#oauth2) for `refresh_token`, `jwt_bearer`, and the
interactive grants this same source type also supports.
