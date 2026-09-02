# ADR 0013: MCP denials are protocol errors, and `tools/list` is filtered

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

MCP traffic defeats host-level policy completely. Every call to a given server is one POST to
one endpoint. `search_repositories` and `delete_repository` are the same request as far as an
allowlist is concerned; the difference is entirely in the JSON-RPC body.

Two further things are specific to MCP clients.

**An HTTP error is not a protocol error.** The client is an MCP implementation, not a browser.
A 403 on a JSON-RPC call reads to it as transport failure — "the server is down" — and produces
reconnects and retries rather than anything the agent can reason about.

**A denied tool that remains visible still shapes behaviour.** An LLM-driven agent that can see
`delete_repository` in `tools/list` will form plans that use it, attempt them, get errors, and
work around them. The error is not a dead end; it is a prompt.

## Decision

An `mcp` policy layer that parses JSON-RPC over HTTP and SSE, gating `tools/call` by tool-name
glob and argument constraints. Default-deny: a tool not listed cannot be called.

**A denied `tools/call` returns a JSON-RPC error object, not an HTTP 403.**

**Denied tools are removed from `tools/list` responses.** Filtering works on JSON responses and
on SSE, and the SSE path rewrites event by event rather than buffering, so MCP's streamable
transport keeps streaming.

## Alternatives considered

**HTTP 403 for denials.** Consistent with the rest of the proxy and wrong for this client:
it produces reconnect loops instead of an actionable result.

**Block calls without filtering `tools/list`.** Enforces policy and leaves the agent forming
intent around tools it cannot use, generating retry traffic and confusing failures.

**Buffer SSE to filter it.** Much easier, and it breaks the streamable transport this layer
exists to support — see [ADR-0007](0007-bodies-stream-by-default.md).

## Consequences

**Removing a tool from `tools/list` prevents intent rather than punishing it**, which is the
more effective control by some distance — an agent that never sees a tool produces no plans
that need it.

The proxy now parses a body format, which is a larger attack surface than header inspection and
means tracking MCP's evolution. Method names or transport details changing upstream is
maintenance this layer signs up for.

Event-by-event SSE rewriting is genuinely harder than buffering and is the only way to keep the
transport streaming. It needs the streaming-specific tests noted in
[AGENTS.md](../../AGENTS.md).

The agent's view of a server is now profile-dependent: the same MCP server presents different
tool sets to different profiles. That is the intent, and it means a confusing bug report may be
a policy question rather than a server one.
