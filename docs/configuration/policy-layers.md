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
    - when: 'req.method in ["GET", "HEAD"] && "domain.bundle" in ev.facts && ev.facts["domain.bundle"] == "github"'
      verdict: allow
    - when: 'req.method in ["POST", "PATCH", "DELETE"]'
      verdict: pass
      annotate:
        flags: ["WriteOperation"]
```

`req` carries method, host, path and header names. `ev` carries the facts and flags earlier
layers contributed. `annotate` adds to that evidence without deciding, which is how a cheap
layer marks something for an expensive one to reason over.

### CEL inputs and evaluation

| value | type | meaning |
|---|---|---|
| `req.method` | string | HTTP method |
| `req.host` | string | client-facing destination hostname |
| `req.port` | integer | destination port |
| `req.path` | string | URI path, without query |
| `req.has_query` | boolean | whether a query exists, without its contents |
| `req.headers` | list of strings | lowercase header names, not values |
| `ev.facts` | map | accumulated layer facts |
| `ev.flags` | list of strings | accumulated flags |

Rules are tested in list order. A matching `allow` or `deny` ends evaluation; a matching
`pass` adds its annotation and continues to the next expression. If none terminates, the
layer passes. Guard access to optional facts with a membership check before indexing:

```yaml
- layer: rules
  expressions:
    - when: '"domain.bundle" in ev.facts && ev.facts["domain.bundle"] == "github" && req.method == "GET"'
      verdict: allow
```

Malformed expressions fail when the chain is built. An evaluation error or a non-boolean
result refuses the request; it is not treated as a non-match. `config check` validates the
configuration model but does not compile the policy chain, so also start `serve` before
assuming an expression is usable. CEL's bounded language avoids general-purpose loops;
expressions still consume CPU on the request path.

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

### MCP fields and constraints

| field | default | meaning |
|---|---|---|
| `max_body_bytes` | 1 MiB | request inspection and tools-list response cap |
| `servers` | `[]` | server scopes and permitted tools |
| `servers[].name` | unset | optional descriptive name |
| `servers[].rules` | `[]` | host patterns or CIDRs matching that server |
| `servers[].tools` | `[]` | permitted tool-name globs and argument constraints |
| `tools[].when` | `[]` | constraints; all must hold for this tool entry |

Each constraint has a dotted `path` into the arguments and one or more checks: `equals`
(JSON equality), `in` (a list of permitted JSON values), or `matches` (a regular expression on
a string). A missing argument fails a constraint. Checks on one constraint combine; separate
tool entries can provide alternative ways to permit the same tool.

```yaml
- layer: mcp
  max_body_bytes: 1048576
  servers:
    - name: repository-tools
      rules: [{ host: "mcp.example.com" }]
      tools:
        - name: create_issue
          when:
            - { path: owner, in: ["example-org", "example-team"] }
            - { path: "repo.name", matches: "^public-" }
```

A tool passing MCP policy still needs a later `allow` or `default_action: allow`; the MCP
layer passes accepted calls rather than granting all egress. Keep an allowlist before it set
to `on_match: pass`, or that allowlist short-circuits tool checking. Other JSON-RPC methods
and non-JSON-RPC requests pass through this layer and remain subject to the rest of the chain.
Oversize governed requests are refused; JSON tools-list responses are bounded, and SSE lists
are rewritten event by event.

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

### DLP fields and limitations

| field | default | meaning |
|---|---|---|
| `scan_request` | `false` | buffer and scan the UTF-8 request body |
| `scan_response` | `false` | declared schema field; currently not implemented and does not enable response scanning |
| `patterns` | `[]` | named built-in detectors; no configured patterns means no pattern matches |
| `on_match` | `deny` | `deny`, `allow` or `pass`; `allow` terminates the chain |
| `annotate.flags` | `[]` | flags added to passed evidence when a pattern matches |
| `max_body_bytes` | 1 MiB | request buffering cap |
| `on_oversize` | `deny` | `deny` or `pass_unscanned` |

Header values and the query string are always scanned; `scan_request` adds body scanning.
Bodies are checked as UTF-8 text, not decoded archives or arbitrary binary formats. This is
pattern detection, not proof that a request contains no confidential data. `pass_unscanned`
permits an oversize body while recording `BodyNotScanned` and `dlp.body_scanned: false`.
Keep `deny` when body inspection is a required control.

Built-in names: `aws-access-key`, `github-pat`, `github-fine-grained`, `slack-token`,
`openai-key`, `anthropic-key`, `google-api-key`, `stripe-key`, `private-key-pem`, and `jwt`.
Unknown names fail when the chain is built. Findings identify the pattern and location,
not the matched credential value. No custom-pattern schema is available here.

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
