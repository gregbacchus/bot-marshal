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
| M6 | Transparent (nftables) and DNS interception | done, later partially reverted¹ |
| M7 | Management API, hot reload, warn mode, metrics | done² |
| M8 | OAuth2 credential acquisition | partial³ |

¹ Transparent (nftables REDIRECT) capture was removed after M6 — see
[Removed](#removed) below. DNS interception is unaffected.

² OpenTelemetry export is not implemented — see below.

³ `client_credentials`, `refresh_token`, `authorization_code` (with PKCE) and `device_code`
all work end to end, the last two via `marshal secrets oauth login`. `jwt_bearer` and
`private_key_jwt` are not implemented, and neither is in-band capture — see below.

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

For a workload that cannot be configured to use a proxy at all, [DNS capture](capture.md#dns)
is the supported option now — weaker, but honest about that weakness rather than silently
under-enforcing while appearing to intercept.

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

**Response body transforms — `summarize`, `compact`.** Declared as config shapes since M3
(they determine whether a response can stream, which the rest of the design has to respect) but
never implemented. A profile naming one fails to start rather than serving a response that was
supposed to be rewritten, unrewritten — which is why the shipped `coding-agent` profile does
not start end to end as written.

**Rego rules via `regorus`.** The `rules` layer is CEL only. Rego is designed for as an opt-in
for anyone already running OPA policy.

**OAuth2 `jwt_bearer` and `private_key_jwt`.** RFC 7523: sign an assertion with a private key
and exchange it, which is how Google service accounts, Salesforce and Snowflake authenticate.
Needs RS256/ES256 signing, which `marshal-secrets` has no dependency for yet.

**In-band OAuth2 capture.** The agent driving an authorization flow *through* the proxy, with
marshal substituting its own PKCE challenge, intercepting the redirect, completing the exchange
itself, and handing the agent a flow that completes on nothing usable. The interesting version
of the feature, and a much larger change: it needs a request-path component that can *answer* a
request rather than forward it, which today only a denial can do.

## Architecture

`marshal-core` holds the traits and types and depends on no other crate in the workspace;
everything else builds on it. That keeps the boundaries honest and the policy chain testable
without a network.

| crate | |
|---|---|
| `marshal-core` | types and traits — verdicts, policy layers, transforms, identities. No I/O. |
| `marshal-config` | layered YAML load, the `profiles/`/`bundles/`/`transforms/` convention, validation |
| `marshal-tls` | CA load/generate, leaf minting, cache, rustls configs |
| `marshal-policy` | chain runner and the denylist, allowlist, rules, dlp, mcp layers |
| `marshal-secrets` | env/file/oauth2 sources, TTL cache, token store, injection and redaction |
| `marshal-judge` | the LLM judge layer: providers, structured verdicts, cache, breaker |
| `marshal-launch` | `marshal run`: netns and cgroup isolation, identity registration |
| `marshal-http` | the upstream guard, and the one-shot client for calls marshal makes as itself |
| `marshal-proxy` | listeners, CONNECT, SOCKS5, MITM, streaming |
| `marshal-dns` | hickory authority: resolve-to-proxy, passthrough, static records |
| `marshal-audit` | JSON records, tracing layer |
| `marshal-cli` | the `marshal` binary |
