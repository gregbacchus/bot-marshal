# OAuth2 credentials

There are four different ways marshal ends up holding an OAuth2 credential, and which one
applies depends on two questions: **do you control the OAuth application** (its `client_id`
and endpoints), and **who is driving the login**, marshal or the agent/tool.

| | you control the OAuth application | you don't (a vendor's own client) |
|---|---|---|
| **no interactive login needed** | a `{ type: oauth2 }` source with `grant: client_credentials`, `refresh_token`, or `jwt_bearer` — authenticates from config alone, below | — |
| **a human logs in once, marshal drives it** | `grant: authorization_code`/`device_code` + `marshal secrets oauth login <name>`, below | [§ Bootstrap capture](#bootstrap-capture) — marshal discovers the application from the exchange itself, no config needed |
| **an agent drives the login unattended** | `source.capture: in_band`, [§ In-band capture](#in-band-capture) — marshal takes the flow over so the agent gets nothing | not possible — capture needs the authorization endpoint declared in advance |

The first two rows are a `{ type: oauth2 }` secret source declared in a profile, and are what
the rest of this page covers up to and including [§ In-band capture](#in-band-capture).
[§ Bootstrap capture](#bootstrap-capture) is the fourth row: a CLI command with **no source
declaration at all**.

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

## Grants

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

## In-band capture

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

**Why `client_id` (and `client_secret`) are still required.** Step 2 is not a relay of the
agent's own token request — marshal performs its *own* call to `token_endpoint`, and every
token request needs a `client_id` regardless of whether the client is confidential or public
(RFC 6749 §4.1.3). Marshal has to authenticate to the provider as the same registered
application the agent already has, because that is the application whose PKCE challenge it
just replaced. This is the real distinction between this and bootstrap capture below:
`in_band` requires you to already know that application's `client_id` (and `client_secret`
unless it's a public client, `client_auth: none`); bootstrap capture exists for exactly the
case where you don't.

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

## Bootstrap capture

Everything above — including `in_band` — assumes marshal already knows the OAuth application:
its `client_id`, its endpoints. Bootstrap capture is for the case it doesn't, which is the
common one for a vendor's own CLI subscription login: the application belongs to the vendor,
is not published, and there is no `{ type: oauth2 }` source to declare in the first place.

There is **no config for this at all** beyond a top-level `state_dir:`. It is a command, not a
secret source:

```bash
marshal secrets oauth login CLAUDE_SUBSCRIPTION --mode steal --run -- some-vendor-cli login
```

Instead of driving a flow it already knows, marshal starts a disposable, foreground proxy
instance and watches for the tool's *own* token exchange — the request the tool's own process
makes to redeem its code. That single request carries everything worth knowing (`client_id`,
`redirect_uri`, and — as its own destination — `token_endpoint` itself), which is why nothing
needs to be declared beforehand. It matches on the *shape* of the request (a POST whose body
parses as `grant_type=authorization_code` or the device-code grant) rather than a configured
host and path, because by definition it does not know the host or path yet.

That looseness is safe here specifically because this proxy exists for one command, in the
foreground, under a timeout, with somebody watching — not as a standing part of `serve`.
`--mode` decides what happens to the exchange it matches:

* **`observe`** (default) — forwards it untouched. The tool's own login succeeds normally and
  keeps its own working credential; marshal simply also learns one.
* **`steal`** — redeems the code out of band itself and answers the tool with a sentinel, so
  the tool never ends up holding a working credential — at the cost of its login reporting
  failure, which from its point of view is exactly what happened.

Either way, a refresh token the exchange produced is written under `state_dir`, and marshal
prints the configuration it discovered — endpoint, `client_id`, scope — ready to paste into a
profile if you want an ongoing declared swap afterward. Bootstrap capture only seeds a
credential once; it is not itself a standing part of the runtime.

Full command reference, flags, and the sandboxing `--run` applies:
[`marshal secrets oauth login <name> --wait`/`--run`](../cli.md#marshal-secrets-oauth-login-name---wait----run----cmd).
See also [ADR-0034](../adr/0034-bootstrap-capture-reads-the-token-exchange.md).

## What this costs

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

