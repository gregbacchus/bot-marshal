# ADR 0040: Header filtering is allow or deny, never both — and never touches wire framing

* **Status:** Accepted
* **Date:** 2026-09-06

## Context

`request_transforms.headers`/`response_transforms.headers` (`{ allow: [...] }`) has existed in
the config schema and its docs since before this ADR, described as "an allow-list, not a
deny-list: a header not named is dropped." Investigating a request to add a `deny` option
alongside it found that `allow` was never wired into the runtime at all:
`build_request_transforms`/`build_response_transforms` in `marshal-policy/src/build.rs` read
only `set_headers` and the response body/MCP transforms — `HeaderAllowlist` was parsed,
merged across transform bundles, and validated for "at most one bundle sets it," but nothing
ever turned it into a `RequestTransform`/`ResponseTransform`. Every profile documented as using
it — including the shipped `config/profiles/coding-agent.yaml` example — had every header
passing through unfiltered on both directions. No test exercised it end to end.

Implementing it for real immediately surfaced why: a naive port (strip anything the pattern
list does not name) sent every intercepted request out with no `Host` header, because none of
the example allow-lists (`["accept*", "content-*", "user-agent", "authorization"]`) name it.
That is not a hypothetical — live-testing this change against a real upstream produced a `400`
that a filter-free request against the identical config did not. A deny-list has the mirror
failure mode: `deny: ["content-*"]` reads as "drop tracking-ish headers" and also drops
`Content-Length`, corrupting the request in a way nothing before the wire would catch.

## Decision

Header filtering ships as two things this ADR ties together:

**`allow` and `deny` are mutually exclusive, not composable**, on the renamed
`HeaderFilterSpec` (was `HeaderAllowlist`). `deny` is `allow`'s inverse default (default-allow,
drop only what matches) rather than a second list layered on top of it — layering would mean a
`deny` entry could never override something an `allow` entry decided, or vice versa, for no
benefit over picking one mode. `marshal config check` rejects a block with both set (ambiguous)
or neither set (does nothing) — [`check_header_filter`](../../crates/marshal-config/src/validate.rs).

**Neither mode can ever remove a header that governs wire framing**, whatever its patterns say.
[`request_header_is_managed`](../../crates/marshal-config/src/model.rs) already existed for
`set_headers` (a config author cannot set `Host` there either); this reuses it for the filter,
and adds a response-side counterpart (`content-length`, `connection`, `transfer-encoding`,
`upgrade`, and so on — not `host`, which has no response-side meaning). `header_filter_apply`
in `marshal-policy/src/transforms.rs` checks this exemption before consulting either pattern
list, on both `RequestHeaderFilter` and `ResponseHeaderFilter`.

Ordering matters and is fixed: request-side filtering runs *before* `set_headers` and secret
injection (a client's own header is judged first, so marshal's own additions are never at risk
of the filter it configured for the client); response-side filtering runs *last*, after any
`response_transforms.body: limit`, so an `allow` list has final say over everything the agent
sees, including a header a body limiter itself added.

## Alternatives considered

**Ship `deny` without also fixing `allow`'s dead wiring.** Building a deny-list transform on a
mechanism that silently does nothing gets an operator nothing — same effort either way, since
both modes share one implementation once either is wired in at all.

**Let `allow` and `deny` compose** (apply `deny` after `allow`, say). Rejected: they express
opposite defaults, and composing them raises exactly the question mutual exclusivity avoids —
which one wins when a pattern appears in both, and why would an operator ever want both at
once rather than a more precise single list.

**No managed-header exemption; document the footgun instead.** Consistent with how `allow`
already shipped (undocumented and untested, as it turned out) but proven wrong the moment this
was tested against a real request: a config author copying the docs' own example allow-list
breaks every request through that profile, silently, with no error at config-check time to
explain why.

## Consequences

**Every profile with an existing `headers: allow` block starts actually filtering** the moment
this ships, having done nothing before it. An operator who wrote one believing it worked has
been running unfiltered since — this is a correction, not a new restriction, but it changes
observed behavior on upgrade for anyone using the field at all.

**The managed-header exemption is not configurable.** An operator cannot filter `Host` or
`Content-Length` even if they believe they have a reason to; the two `_is_managed` functions are
the single source of truth for both `set_headers` and this filter, and widening what they cover
protects a new proxy-owned header automatically everywhere both mechanisms are used, at the
cost of no override existing if one is ever genuinely needed.

**Response-side `allow` now interacts with `response_transforms.body: limit`.** Running the
filter last means a profile that already declares a body limiter and wants the agent to see the
`x-marshal-response-limited` header it adds must list it explicitly — previously moot, since
neither transform's ordering mattered when the filter was a no-op.
