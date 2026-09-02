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
| M6 | Transparent (nftables) and DNS interception | done |
| M7 | Management API, hot reload, warn mode, metrics | done¹ |

¹ OpenTelemetry export is not implemented — see below.

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

**TPROXY.** Transparent mode uses REDIRECT, which is enough for TCP to the proxy's own host.
TPROXY would preserve the original destination without conntrack.

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
| `marshal-secrets` | env/file sources, TTL cache, injection and redaction |
| `marshal-judge` | the LLM judge layer: providers, structured verdicts, cache, breaker |
| `marshal-launch` | `marshal run`: netns and cgroup isolation, identity registration |
| `marshal-proxy` | listeners, CONNECT, SOCKS5, transparent, MITM, streaming, upstream guard |
| `marshal-dns` | hickory authority: resolve-to-proxy, passthrough, static records |
| `marshal-audit` | JSON records, tracing layer |
| `marshal-cli` | the `marshal` binary |
