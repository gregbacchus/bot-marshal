# ADR 0041: The LLM router rewrites destination after allow, and intercept may connect to a mapped origin

* **Status:** Accepted
* **Date:** 2026-09-23

## Context

An agent speaks one LLM HTTP dialect — OpenAI Chat Completions or Anthropic Messages — to
whatever host it already CONNECTs to. An operator may want that traffic to land on a different
origin: another vendor, OpenRouter, Azure, vLLM, an internal gateway. The origin may speak the
same dialect (rewrite host, path, and `model`) or the other one (translate the JSON and the
SSE stream).

Until now, an intercepted CONNECT bound the TCP peer: [`mitm::intercept`](../../crates/marshal-proxy/src/mitm.rs)
TLS-handshakes a stream the guard had already opened to the CONNECT host, and every HTTP
request on that tunnel uses that sender. A request transform that changed `RequestContext.authority`
could not change where bytes went. Cross-origin routing is impossible on that path.

Answering the request locally ([ADR-0031](0031-a-responder-may-answer-a-request.md)) is the
wrong primitive: the origin still has to be contacted, and the response has to stream. The
buffered one-shot client in `marshal-http` is also the wrong transport — it caps and collects
the body, which would turn SSE into a single delivery when the stream ends.

The mapped origin is configuration, not something the agent asserts. That is what keeps this
from becoming an SSRF gadget: the agent picks a listen host and a model *name*; the operator's
table names the origin.

## Decision

The LLM router is a paired **request transform** and **response transform** (plus a
[`RequestResponder`](0031-a-responder-may-answer-a-request.md) only for the OpenAI model
catalog). It runs after the chain has allowed, before secret injection.

**Policy judges the agent-facing request** — CONNECT host, path, inbound model. The mapped
origin is not re-evaluated by the allowlist. It is operator-static.

**The upstream guard still applies to the socket that is actually opened.** After rewrite,
intercept calls `guard.connect` on `cx.authority` (the mapped host and port), resolves once,
checks every address, and connects to a checked address ([ADR-0010](0010-resolve-once-connect-to-the-checked-address.md)).
A listen host that the router may retarget is **not** TCP-connected at CONNECT time: tunnel
success means marshal accepted interception, not that the CONNECT name is reachable. Same-host
aliases that do not change authority keep the existing eager tunnel.

**Dialects are wire formats**, not vendors. `openai` and `anthropic` name JSON/SSE shapes;
hosts and paths are config, with dialect defaults (`/v1/chat/completions`, `/v1/messages`).

SSE translation is stateful. `ResponseTransform::rewrite_chunk` stays for filters that can
work host-and-chunk; a transform that needs per-response state returns an
`SseRewriter` session instead.

## Alternatives considered

**A responder that calls the origin itself.** Fewer intercept changes, and the OAuth broker
already answers. Rejected because the existing outbound client buffers, SSE would stall, and
"answer" would mean "be the origin" rather than "rewrite and forward" — two jobs in one
primitive.

**Always defer upstream connect on every intercepted tunnel.** Simpler intercept. Rejected as
a behaviour change for every CONNECT (tunnel success would no longer imply origin TCP) when
only router listen hosts need it.

**Re-run the policy chain on the mapped host.** Would make an allowlist of the listen host
insufficient, and would let a mapped origin's denylist refuse traffic the operator explicitly
routed there. The mapping table *is* the allow for the origin; the guard remains the SSRF
check.

## Consequences

CONNECT success for a router listen host no longer implies a TCP handshake to that host. An
origin that is down surfaces as a request-level 502, not a failed CONNECT.

Client TLS is minted for the CONNECT name; origin TLS is verified for the mapped name. Those
names differ whenever the mapping retargets. That is inherent to intercepting and rewriting
destination, not a verification skip.

Secret injection keys off `cx.authority` *after* rewrite, so `rules` must name the **origin**
host. The router strips listen-side `Authorization` / `x-api-key` / dialect headers first so a
credential meant for the client-facing API cannot ride to a different origin.

Someone reading an audit record must not assume `host` is both what the agent named and where
the socket went. Mapping facts (`llm_router.from_model`, `to_model`, `to_host`) are recorded
on the request; secrets are not.
