# Roadmap and status

Early, but **traffic flows and TLS is intercepted**. Policy evaluates the real decrypted
request, not just the tunnel destination, and each request inside a connection is judged and
audited separately.

## Milestones

| Milestone | Contents | State |
|---|---|---|
| M0 | Workspace, core traits, config load + validate, CI | done |
| M1 | Explicit proxy (CONNECT + SOCKS5), chain runner, denylist + allowlist, upstream guard, audit | done |
| M2 | TLS MITM, streaming (WebSocket / SSE / chunked) | done |
| M3 | Secret injection, egress DLP, CEL rules layer | done |
| M4 | Identity resolution, profiles, `marshal run` | done |
| M4.5 | LLM judge layer | done |
| M5 | MCP tool-level policy | done |
| M6 | Transparent capture and DNS resolver | done, later partially reverted¹ |
| M7 | Management API, hot reload, warn mode, metrics | done² |
| M8 | OAuth2 credential acquisition | done³ |
| M9 | LLM model routing, OpenAI/Anthropic translation and native decision APIs | done |

¹ Transparent (nftables REDIRECT) capture was removed after M6 — see
[Removed](#removed) below. The DNS resolver remains; its direct HTTP/TLS ingress limitation is listed below.

² OpenTelemetry export is not implemented — see below.

³ Complete: `client_credentials`, `refresh_token`, `jwt_bearer`, `authorization_code` (with
PKCE) and `device_code`, the last two enrolled via `marshal secrets oauth login`;
`client_secret_basic`/`_post`, `private_key_jwt` and public clients; and two capture
mechanisms with deliberately different threat models —
[`capture: in_band`](configuration/oauth2.md#in-band-capture), which owns the PKCE verifier
so an untrusted agent cannot redeem its own code
([ADR-0032](adr/0032-marshal-owns-the-pkce-verifier.md)), and
[`oauth login --wait`/`--run`](cli.md#marshal-secrets-oauth-login-name---wait----run----cmd),
which learns a credential whose OAuth application marshal does not control by observing a real
login ([ADR-0034](adr/0034-bootstrap-capture-reads-the-token-exchange.md)).

## Removed

**Transparent (nftables REDIRECT) capture.** Shipped in M6, removed afterward: it derived the
policy hostname from TLS SNI or the HTTP `Host` header but never verified the redirected
destination actually belonged to it, and it byte-relayed the connection rather than
intercepting, so `rules`/`dlp`/`mcp`/`judge` and every transform never ran on that traffic —
the same gap [interception being mandatory](concepts.md#why-interception-is-mandatory) exists
to close for explicit traffic. See [ADR-0022](adr/0022-remove-transparent-capture.md).

Losing it also broke `listener_port` identity, which depended on transparent's multi-listener
mechanism to bind more than one port. That resolver now works again through a different,
simpler path: `listeners.explicit.listen` accepts a list of addresses, each running the full
policy pipeline (not a raw relay) — see [Identity](configuration/identity.md#listener_port) and
[ADR-0023](adr/0023-multi-port-explicit-listeners.md).

Workloads must use the explicit proxy protocol. [DNS answers](capture.md#dns) do not supply
a replacement HTTP/TLS ingress for clients that cannot use a proxy.

## Not built

**OpenTelemetry export.** The audit log is already structured JSON carrying the full layer
trail, identity attribution, status and timing, and `/v1/metrics` covers scraping. OTLP would
add correlation with an agent's own traces, which is genuinely useful — but it is a large
dependency tree for something a log shipper largely covers, so it is left as a deliberate
decision rather than assumed.

**An interactive approval decider.** The `Defer` verdict and the `Decider` trait exist and the
chain resolves them; the only implementation refuses. A human-in-the-loop approval flow plugs
in without touching the chain.

**Rate limits and budgets.** Per-identity counters exist and are exported, which is the
groundwork; enforcement does not.

**Response body transforms — `redact`, `summarize`, `compact`.** Declared as config shapes since M3
(they determine whether a response can stream, which the rest of the design has to respect) but
never implemented. A profile naming one fails to start rather than serving a response that was
supposed to be rewritten, unrewritten. The shipped `coding-agent` profile declares `redact` and therefore remains a reference
example that cannot start as written, even with its judge API credential. Use the minimal
getting-started configuration for a runnable example. Log/audit credential redaction is
implemented independently of response-body redaction.

**Rego rules via `regorus`.** The `rules` layer is CEL only. Rego is designed for as an opt-in
for anyone already running OPA policy.

**DLP response scanning.** `scan_response` exists in the schema but is not wired into the
runtime. Request header/query scanning and optional request-body scanning are implemented.

**Direct HTTP/TLS ingress after DNS resolution.** The DNS server supplies proxy addresses,
static records and passthrough answers, but there is no direct origin-HTTP/TLS listener that
intercepts ordinary clients sent to those addresses. DNS alone is not a complete capture path;
use an explicit proxy. See [Capture](capture.md#dns).

Already-enrolled authorization-code credentials are supported: the builder checks the stored
grant and permits omitting `authorization_endpoint` and `redirect_uri`. Consequently that
configuration's validation depends on the machine's credential state; keep the endpoint fields
for a portable configuration, or validate bootstrap output on its enrolled host.

## Architecture

`marshal-core` holds the traits and types and depends on no other crate in the workspace;
everything else builds on it. That keeps the boundaries honest and the policy chain testable
without a network.

| crate | |
|---|---|
| `marshal-core` | types and traits — verdicts, policy layers, transforms, identities. No I/O. |
| `marshal-config` | layered YAML load, the `profiles/`/`bundles/`/`transforms/` convention, the env file, validation |
| `marshal-tls` | CA load/generate, leaf minting, cache, rustls configs |
| `marshal-policy` | chain runner and the denylist, allowlist, rules, dlp, mcp layers |
| `marshal-secrets` | env/file/oauth2 sources, TTL cache, token store, in-band and bootstrap capture, injection and redaction |
| `marshal-judge` | the LLM judge layer: providers, structured verdicts, cache, breaker |
| `marshal-llm` | model-table routing, OpenAI/Anthropic JSON and SSE translation, and native System One decision routing |
| `marshal-launch` | `marshal run`: netns and cgroup isolation, identity registration |
| `marshal-http` | the upstream guard, and the one-shot client for calls marshal makes as itself |
| `marshal-proxy` | listeners, CONNECT, SOCKS5, MITM, streaming |
| `marshal-dns` | hickory authority: resolve-to-proxy, passthrough, static records |
| `marshal-audit` | JSON records, tracing layer |
| `marshal-cli` | the `marshal` binary |

Native System One decisions are supported as judge providers (`system_one` and `decisions_api`)
and as agent model routes. DecisionsApi is an independent service; an official OpenAI decision
adapter awaits a published contract. See [Decision APIs](configuration/decision-apis.md).
