# Policy layers

Layers decide **whether** a request proceeds. Each returns ALLOW, DENY or PASS; the first
terminal verdict wins, and PASS falls through carrying evidence the next layer can read.

Order is semantic and cost-ordered — cheapest first. `marshal config check` warns when an
expensive layer precedes a cheap one.

```
denylist → allowlist → rules (CEL) → mcp → dlp → judge (LLM) → default_action
  trivial     trivial        cheap      cheap  moderate   expensive
```

## `denylist`

Hard refusals. Put it first: because the chain short-circuits, position 1 means nothing later
— including a judge approval — can override it.

```yaml
- layer: denylist
  deny:
    domains: ["*.onion", "pastebin.com"]
    cidrs: ["169.254.0.0/16"]
```

## `allowlist`

Destination filtering by [bundle](bundles.md), domain glob, or CIDR. The two outcome knobs
matter more than they look:

```yaml
- layer: allowlist
  allow:
    bundles: [github, npm, pypi, crates-io]
  on_match: pass      # or `allow`
  on_miss: deny       # or `pass`
```

* `on_match: allow` **terminates the chain** — nothing after this layer runs for a matching
  host.
* `on_match: pass` makes the allowlist *necessary but not sufficient*, letting `rules`, `dlp`
  and `judge` still get a say. This is usually what you want in a chain with those layers.
* `on_miss: deny` refuses anything not listed; `on_miss: pass` defers to later layers and
  ultimately `default_action`.

## `rules`

CEL expressions over the request and the accumulated evidence. Sandboxed and
non-Turing-complete, so an expression cannot hang the request path.

```yaml
- layer: rules
  expressions:
    - when: 'req.method in ["GET", "HEAD"] && ev.facts["domain.bundle"] == "github"'
      verdict: allow
    - when: 'req.method in ["POST", "PATCH", "DELETE"]'
      verdict: pass
      annotate:
        flags: ["WriteOperation"]
```

`req` carries method, host, path and header names. `ev` carries the facts and flags earlier
layers contributed. `annotate` adds to that evidence without deciding, which is how a cheap
layer marks something for an expensive one to reason over.

## `mcp`

To a host allowlist every MCP call looks identical — one POST to one endpoint. The difference
between `search_repositories` and `delete_repository` is entirely in the body, so tool-level
policy needs its own layer:

```yaml
- layer: mcp
  servers:
    - rules: [{ host: "mcp.example.com" }]
      tools:
        - name: "search_*"                       # glob over a family
        - name: "create_issue"
          when: [{ path: owner, equals: gregbacchus }]
```

Default-deny applies: a tool not listed cannot be called.

A denied `tools/call` comes back as a **JSON-RPC error, not an HTTP 403** — the client is an
MCP implementation, and a transport-level failure reads to it as "the server is down",
producing reconnects rather than something the agent can act on.

Denied tools are also removed from `tools/list`, which matters more than blocking the call: an
error is something an LLM-driven agent retries and works around, whereas a tool it never sees
produces no intent at all. Filtering works on JSON responses and on SSE, and the SSE path
rewrites event by event rather than buffering, so MCP's streamable transport keeps streaming.

## `dlp`

The inverse of secret injection: catches a real credential the agent obtained some other way
and is trying to send *out* — something destination filtering cannot see.

```yaml
- layer: dlp
  scan_request: true
  patterns: ["aws-access-key", "github-pat", "private-key-pem", "openai-key"]
  on_match: deny
  max_body_bytes: 1048576
  on_oversize: deny
```

Scanning a body means requests this layer applies to **stop streaming**, which is why the cap
and the oversize rule are explicit rather than defaulted silently. `on_oversize` chooses
between refusing and forwarding unscanned; there is no silent truncation.

## `judge`

An LLM in the request path, for decisions no static rule expresses well. Expensive, so it
caches and circuit-breaks.

```yaml
- layer: judge
  provider:
    type: anthropic
    model: "claude-haiku-4-5-20251001"
    api_key_env: ANTHROPIC_API_KEY
  scope:
    - host: "api.github.com"
      methods: ["POST", "PATCH", "DELETE"]
  cache: { ttl: "15m", max_entries: 10000 }
  timeout: "8s"
  max_concurrent: 32
  on_error: deny
  on_timeout: deny
  circuit_breaker: { consecutive_failures: 5, cooldown: "30s" }
  prompt: |
    Allow only changes to repositories owned by gregbacchus. Deny anything that
    modifies workflow files, repository secrets, or repository settings.
```

### Providers

`type: anthropic` or `type: openai`. Either takes an optional `base_url` — Azure OpenAI,
OpenRouter, a local vLLM or Ollama instance, an internal gateway. `scheme://host[:port]`, no
path; `http://` is honoured for a local server, not upgraded to `https`.

```yaml
provider: { type: openai, model: "...", api_key_env: OPENAI_API_KEY, base_url: "http://localhost:11434" }
```

Adding a provider is additive by design: the scoping constraints below live in the layer
itself, not in the provider, so a new implementation inherits them without rework. The two
shipped providers' response shapes genuinely differ in a way worth knowing if you add a third:
Anthropic's tool-use `input` is a native JSON object, while OpenAI's `function.arguments` is a
**JSON-encoded string** requiring a second decode — verified against OpenAI's published
OpenAPI spec rather than assumed, specifically because guessing wrong here fails in a way that
looks like "the model returned nonsense" rather than "this needed one more parse".

### What the judge is allowed to see

**Method, host, path, and header names — never header values, never the body.**

It sends a description of the request to a third-party API, so anything shown there is a
potential leak; a header value is exactly where a credential lives, and the body is exactly
where proprietary content or a secret an earlier layer hasn't caught yet would be. Neither is
ever necessary to answer a scoping question, so neither is offered the chance to leak.

### Injection hardening

The untrusted request travels inside explicit `<request>` tags in the message content, never
concatenated into the system prompt, and the verdict comes back through a **forced tool call**
— never parsed from prose. Those two close the mechanical injection surface: there is no
string an attacker controls that ever becomes an instruction, and no free text this layer ever
interprets as a decision.

What that does *not* guarantee is that the underlying model resists a sufficiently crafted
`<request>` payload through that data channel — a live-model behavioural property, not a
parsing one, and no unit test proves it. **Treat the judge as defence-in-depth, not a
substitute for the layers before it.**

### Failure behaviour

Verdicts cache on a normalised signature (method, host, path, sorted header names) with a
configurable TTL, and a circuit breaker opens after consecutive failures so an unhealthy
provider degrades to `on_error` instead of adding latency to every request in scope while it
is down. An LLM provider outage must not brick all egress, and must not silently open it
either — whichever happens is a config choice that shows up in the audit record.

The judge's own outbound API call bypasses the proxy chain, or it would deadlock.
