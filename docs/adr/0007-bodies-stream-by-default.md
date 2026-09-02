# ADR 0007: Bodies stream by default; buffering must be declared

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Agents use exactly the traffic patterns that buffering destroys. An LLM API streams tokens over
SSE; an MCP server streams over SSE; a coding agent uploads large diffs and downloads large
archives; anything interactive holds a WebSocket open for long idle periods.

Inspecting or rewriting a body requires having all of it. So the two requirements are in direct
conflict, and the conflict has to be resolved somewhere.

The dangerous property of getting this wrong is that **buffering does not fail**. There is no
error, no log line, nothing that shows up in a test asserting the response body is correct.
There is only an agent whose stream goes quiet and then delivers everything at once, minutes
later, which reads as "the model is slow" or "the network is bad".

## Decision

**Bodies stream by default.** A transform that needs the body buffered declares it, with an
explicit cap, and exceeding the cap is a configured decision (`on_oversize: deny` or forward
unscanned) — never a silent truncation.

That declaration is load-bearing rather than advisory: declaring a body transform *is* a
statement that responses it applies to are no longer streamable. `marshal config check` warns,
naming the transform and the cap, and the profile is expected to scope it away from SSE and
WebSocket endpoints.

## Alternatives considered

**Buffer everything up to a global cap.** One rule, easy to implement, and it breaks SSE and
WebSockets universally — the traffic this tool exists to sit in front of.

**Auto-detect streaming responses** (`text/event-stream`, upgrade headers) **and skip buffering
for them.** Attractive, and it makes the security property depend on a `Content-Type` the
upstream chooses. A DLP scan that silently does not run on responses labelled a particular way
is worse than one that visibly does not apply.

**Make buffering per-request rather than per-profile.** Finer-grained, but the decision has to
be made before the body arrives, when there is nothing yet to decide on.

## Consequences

Streaming works, and it works because it is the default path rather than a special case —
there is no "streaming mode" to fall out of.

The cost is that **body inspection is opt-in and scoped**, so a `dlp` layer protects only what
its profile points it at. That is a real gap and it is a visible one: the config says which
hosts are scanned.

Testing this needs care, and the tests worth having are not the obvious ones. Asserting a
final body is correct passes even when everything was buffered. The assertion that catches
regressions is **the first byte arriving well before the stream ends** — noted in
[AGENTS.md](../../AGENTS.md).

`summarize` and `compact` were specified as body transforms and never implemented. A profile
naming one fails to start rather than silently forwarding an unrewritten response — the same
fail-loud choice, applied to an unfinished feature.
