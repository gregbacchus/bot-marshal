# Decision APIs

Use a native decision model when you need a bounded answer rather than generated text.
Marshal supports TypeSafe/Jev System One and the independent DecisionsApi service, both at
`POST /v1/systemone`. They can judge marshal's policy requests or serve decision requests
made by your agents through the model router.

These are separate uses: the **judge** receives only reduced request metadata, while a
**routed agent request** carries the state and questions the agent supplies. Allow that
outbound data deliberately in your policy.

## Services and maturity

| judge provider type | default origin | model example |
|---|---|---|
| `system_one` | `https://api.typesafe.ai` | `jev-latest` |
| `decisions_api` | `https://decisionapi.net` | `typesafe/jev-1.13` |

DecisionsApi is an independent multi-provider service. Its site discusses an OpenAI Decisions
API preview, but this adapter implements the site's documented System One endpoint; it does
not call an undocumented official OpenAI endpoint. Availability and model IDs may change.
Use your own compatibility, latency, cost and accuracy measurements before switching a
production judge. Existing OpenAI/Anthropic judges remain available.

Source contracts: [TypeSafe OpenAPI](https://api.typesafe.ai/openapi.json),
[DecisionsApi documentation](https://decisionapi.net/docs), and its
[OpenAI preview guide](https://decisionapi.net/decisions-api). Checked 2 October 2026.

## Use a decision model as the judge

This is a complete profile fragment. Keep `DECISIONS_API_KEY` in marshal's environment or
protected env file, outside the agent's environment and accessible filesystem.

```yaml
default_action: deny
policy:
  - layer: allowlist
    allow: { domains: ["api.github.com"] }
    on_match: pass
    on_miss: deny
  - layer: judge
    provider:
      type: decisions_api
      model: "typesafe/jev-1.13"
      api_key_env: DECISIONS_API_KEY
      min_confidence: 0.9
    scope: [{ host: "api.github.com" }]
    prompt: "Permit GET and HEAD repository reads. Refuse repository writes. Pass when the available metadata does not establish which applies."
    timeout: 2s
    on_error: deny
    on_timeout: deny
```

For direct TypeSafe access, change `type` to `system_one`, `model` to an available TypeSafe
model such as `jev-latest`, and `api_key_env` to your TypeSafe key variable.

| field | default | meaning |
|---|---|---|
| `model` | required | service model ID or alias |
| `api_key_env` | required | variable holding that service's bearer API key |
| `base_url` | service origin above | optional `http(s)://host[:port]`, without a path; useful for compatible gateways or local tests |
| `min_confidence` | `0.9` | finite value from 0 to 1; below it the judge returns `pass` |

The endpoint path is `/v1/systemone`. Native models do not generate a verdict explanation,
so there is no `max_tokens` setting for these providers. Marshal supplies one Choice question
with `allow`, `deny` and `pass` options. The operator's policy is in the question's
instructions; the request is separate state containing method, host, path and header names.
Neither header values nor request bodies reach the judge.

Marshal validates the answer type, selected option, confidence and probability distribution.
An invalid answer is a provider error handled by `on_error`. A valid low-confidence answer
is `pass`, **not deny**: later layers and `default_action` decide. Keep `default_action: deny`
when uncertainty must refuse the request. Cache, scope, concurrency, timeout and circuit
breaker behave as for other [judge providers](policy-layers.md#judge).

The audit reason reports the native choice, returned confidence and configured threshold;
it is a marshal-generated summary, not a model-generated rationale. HTTP error bodies from
these services are omitted from judge diagnostics because they may echo credentials or data.

## Route an agent's decision requests

Use the `system_one` wire dialect in the existing LLM router. This complete profile fragment
lets a client choose a stable `quick` alias while the operator selects the service and key:

```yaml
default_action: deny
policy:
  - layer: allowlist
    allow: { domains: ["decisions.local"] }
    on_match: allow
    on_miss: deny
request_transforms:
  llm_router:
    listen: [{ dialect: system_one, hosts: ["decisions.local"] }]
    models:
      quick:
        model: "typesafe/jev-1.13"
        dialect: system_one
        host: "decisionapi.net"
      direct:
        model: "jev-latest"
        dialect: system_one
        host: "api.typesafe.ai"
    unmapped: deny
    max_request_bytes: 65536
    max_response_bytes: 262144
  secrets:
    - name: DECISIONS
      source: { type: env, var: DECISIONS_API_KEY }
      inject: { type: bearer }
      rules: [{ host: "decisionapi.net" }]
    - name: TYPESAFE
      source: { type: env, var: TYPESAFE_API_KEY }
      inject: { type: bearer }
      rules: [{ host: "api.typesafe.ai" }]
```

Configure the agent's API base URL as `https://decisions.local` and send a native request to
`/v1/systemone` with `model: "quick"`, `state`, and a non-empty `questions` object. The proxy
can route this synthetic hostname without resolving it to a real server; the client must use
marshal's explicit proxy and trust its CA. Choosing `direct` sends the same wire format to
TypeSafe instead. The service still determines which question types its selected model accepts.

Policy evaluates the client-facing host and model before mapping. The mapped destination
still passes the upstream guard. Client credentials are removed; the service credential is
injected afterward. State, questions and extra fields are preserved, while the model and
configured origin/path change. Response answers and probabilities are preserved and a
returned top-level model is rewritten to the client alias.

Decision requests are buffered up to `max_request_bytes`, and routed JSON responses up to
`max_response_bytes`. Unrelated endpoints retain the usual streaming behavior. Native
System One requests with `stream: true` are refused. Decision-to-chat and chat-to-decision
translation are not supported: their inputs and outputs have different meanings. In a map
containing both families, choose an alias belonging to the client's dialect family.

Marshal does not synthesize a System One `/v1/models` catalog. Configure the aliases in the
client or consult the chosen service's model list directly. Other router fields and limits
are covered in [LLM routing](llm-routing.md).
