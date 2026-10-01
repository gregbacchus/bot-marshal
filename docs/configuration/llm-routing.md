# LLM routing

The LLM router gives an agent stable, client-facing model names while an operator chooses the
real origin, provider dialect, path and model. It understands two wire formats:

* `openai` — OpenAI Chat Completions at `/v1/chat/completions`;
* `anthropic` — Anthropic Messages at `/v1/messages` (the format used by Claude clients).

Those names describe JSON and SSE shapes, not vendors. An `openai` target may be OpenAI,
OpenRouter, Azure, vLLM or an internal compatible gateway. A mapping may keep the same dialect,
or translate OpenAI to Anthropic and Anthropic to OpenAI in either direction.

## A complete mapping

```yaml
default_action: deny
policy:
  - layer: allowlist
    allow:
      domains: ["llm.local"]
    on_match: allow
    on_miss: pass

request_transforms:
  llm_router:
    listen:
      - dialect: openai
        hosts: ["llm.local"]
      - dialect: anthropic
        hosts: ["claude.llm.local"]

    models:
      fast:
        model: "gpt-5-mini"
        dialect: openai
        host: "api.openai.com"
      smart:
        model: "claude-sonnet-4-5-20250929"
        dialect: anthropic
        host: "api.anthropic.com"
      local:
        model: "qwen3-coder"
        dialect: openai
        host: "llm.internal.example"
        port: 8443
        path: "/openai/v1/chat/completions"

    unmapped: deny
    max_request_bytes: 1048576
    max_response_bytes: 8388608

  secrets:
    - name: OPENAI
      source: { type: env, var: OPENAI_API_KEY }
      inject: { type: bearer }
      rules: [{ host: "api.openai.com" }]
    - name: ANTHROPIC
      source: { type: env, var: ANTHROPIC_API_KEY }
      inject: { type: header, name: "x-api-key" }
      rules: [{ host: "api.anthropic.com" }]
```

An OpenAI client can send `model: smart` to
`https://llm.local/v1/chat/completions`. Marshal evaluates policy against `llm.local`, turns
the request into Anthropic Messages JSON, sends it to `api.anthropic.com` as
`claude-sonnet-4-5-20250929`, and turns the response back into Chat Completions JSON. A Claude
client can send `model: fast` to `https://claude.llm.local/v1/messages` and take the reverse
route.

`listen.hosts` are the names the **client connects to**. The policy allowlist therefore names
those client-facing hosts. A secret rule names the **mapped origin**, because routing runs
before secret injection. The upstream guard resolves and checks the mapped origin before
opening its socket; the model table cannot bypass blocked private, loopback or link-local
addresses.

## Model map fields

| field | default | meaning |
|---|---:|---|
| `models.<alias>.model` | required | model id written into the origin request |
| `models.<alias>.dialect` | required | origin wire format: `openai` or `anthropic` |
| `models.<alias>.host` | required | bare origin host, without scheme, path or port |
| `models.<alias>.port` | `443` | origin TLS port |
| `models.<alias>.path` | dialect default | origin-form request path; useful for gateways with a prefix |
| `unmapped` | `deny` | refuse an alias absent from the table; `pass` leaves it untouched |
| `max_request_bytes` | 1 MiB | cap for buffered request JSON; oversize is refused, never truncated |
| `max_response_bytes` | 8 MiB | cap for non-streaming JSON that needs response translation |

An alias is shared by every listen dialect. That is what permits both kinds of client to use
the same stable names. Use different aliases when the client populations need different
choices.

`listen.paths` replaces the dialect's default client path. It contains absolute paths only,
with no query or fragment. The target `path` may include a query but not a fragment. `marshal
config check` rejects an endpoint claimed by two listen entries, since it could not know which
inbound dialect to parse.

## Credentials and headers

The router removes client-side `Authorization`, `x-api-key`, `Content-Encoding`, `anthropic-version`,
`anthropic-beta`, `openai-organization` and `openai-project` before retargeting. This is
intentional even when the mapped host is the same: a credential carried by the agent is not
assumed safe for the operator-selected origin. Configure a later `secrets` transform for the
origin credential. Anthropic-bound requests receive `anthropic-version: 2023-06-01`; a later
header or secret transform may replace it.

The rewritten request receives a correct `Host`, `Content-Type` and `Content-Length`. Response
translation removes stale content encoding and length metadata before setting the translated
JSON length.

## What translation covers

The router translates ordinary messages, system instructions, text content, token limits,
temperature, stop sequences, tool definitions, tool choice, tool calls/results, finish reasons,
usage counts and provider error envelopes. For `stream: true`, it translates SSE events
incrementally; it does not collect the stream before returning the first token.

The APIs are not identical. Provider-only options with no safe equivalent are not forwarded.
If a workload depends on one, use a same-dialect mapping or a gateway that defines its
translation. This feature targets OpenAI **Chat Completions**, not the Responses API. A
non-chat path is outside the router and proceeds under the rest of the profile unchanged.

## Model discovery and failures

`GET /v1/models` on an OpenAI listen host is answered by marshal with the configured aliases,
so a client can discover `fast`, `smart` and `local` without seeing origin model ids. It is a
synthesized allowed response and is audited with reason code `model_catalog`.

For routed traffic, audit facts record `llm_router.from_model`, `to_model`, `to_host` and
`to_dialect`. A missing model, malformed JSON, oversize body, translation failure or blocked
mapped origin fails closed with a structured proxy error. `unmapped: pass` is the one explicit
exception: only an unknown model passes unchanged.

See [ADR-0041](../adr/0041-llm-router-may-connect-to-a-mapped-origin.md) for why policy judges
the client-facing request while the guard still checks the actual mapped connection.
