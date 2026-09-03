# ADR 0031: A responder may answer a request instead of forwarding it

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Until now there were exactly two things that could happen to a request: the chain denied it and
marshal returned a structured 403, or the chain allowed it, transforms rewrote it, and it went
upstream. "Did not reach the upstream" and "was denied" meant the same thing.

In-band OAuth2 capture ([ADR-0032](0032-marshal-owns-the-pkce-verifier.md)) breaks that
equivalence. Marshal takes over an authorization flow the agent started: it substitutes its own
PKCE challenge, intercepts the redirect, and completes the token exchange itself, out of band.
The agent is then holding a sentinel authorization code and does what any OAuth client does
next — POSTs it to the token endpoint.

That request can be neither forwarded nor denied.

Forwarding it sends a code marshal invented to a provider that has never seen it. The provider
answers `invalid_grant`, the agent's flow fails, and a failed exchange appears in the provider's
logs for no reason.

Denying it hands the agent a 403 in the middle of a protocol exchange it believes it is
conducting. An OAuth client has no handling for "the proxy refuses"; it retries, or reports a
failure, or stops. The point of in-band capture is that the agent's state machine completes
*normally* — on nothing — and a refusal is precisely what stops that happening.

What is needed is a third outcome: marshal answers, on the upstream's behalf, with a
well-formed response the client can consume.

## Decision

A new core trait, `RequestResponder`:

```rust
async fn respond(&self, cx: &mut RequestContext) -> Result<Option<SynthesizedResponse>>;
```

Registered per profile, exactly like transforms, and consulted in `handle_request` **after the
chain has allowed and after every request transform has run**, immediately before the upstream
send. `Some` answers the request; `None` lets it continue. An error refuses the request, on the
same reasoning that a failed transform does: something that could not do its job must not be
silently skipped, because the request it would have answered is one the upstream must not see.

The answer is audited as an `Allow` carrying the responder's own `Reason` — layer name,
`code`, and message — so the record says marshal served the request rather than forwarding it,
and says which component did.

The position in the pipeline is the substantive part of the decision. A responder runs *last*
because "what would the upstream have been asked?" is only a well-formed question once every
rewrite has been applied. A component deciding whether to answer needs to see the request as it
would actually have been sent, not as the client wrote it.

## Alternatives considered

**A terminal `Verdict::Respond` variant.** The first design, and rejected on inspection.
`Verdict` is the vocabulary of *whether a request may proceed*, matched on throughout
`marshal-core` and `marshal-policy`; answering on the upstream's behalf is not that question.
Worse, a policy layer runs before transforms, so a layer could only ever decide on the request
as the client wrote it — for the OAuth case that happens to be enough, but it bakes a
limitation into the primitive for no reason.

**Widening `RequestTransform` to return an optional response.** Fewer moving parts, and every
existing transform would have needed a one-line change. Rejected because it makes every
transform's signature carry a capability almost none of them have, and because "rewriting" and
"answering" have genuinely different failure semantics — a transform that declines has changed
nothing, whereas a responder that declines has decided not to intervene.

**Forward it and rewrite the failure on the way back.** No new primitive at all: let the agent's
POST reach the provider, let it fail, and use an ordinary `ResponseTransform` to replace the
400 with a synthetic 200. Genuinely tempting, and briefly the plan. Rejected because it
deliberately sends a request known to be invalid, leaks a fabricated code to a third party, and
puts a failed exchange in the provider's audit logs — three real costs to avoid one small
addition.

## Consequences

**"Did not reach the upstream" no longer implies "denied".** Anyone reading the audit trail, or
the request path, now has two cases to hold in mind. The `reason.code` distinguishes them, but
the invariant that used to be free is now a thing to check.

**A responder can lie about an upstream.** The trait's whole purpose is to produce a response
the client believes came from the server it addressed. Every response marshal synthesizes
carries `proxy-agent: bot-marshal`, which is the only structural signal a client gets, and a
client that does not look at it cannot tell. That is inherent to the feature, not an oversight
— but it is a capability that did not exist in this codebase before, and a future responder
added carelessly could use it far outside the narrow case that motivated it.

**Only intercepted traffic can be answered.** Answering requires having parsed the request, and
the plain-HTTP path through the explicit proxy deliberately relays bytes rather than parsing
them. A responder therefore never fires on plain HTTP. Rather than leave that as a silent gap,
the OAuth2 configuration that depends on it refuses to build unless its endpoints are `https`.

**Responders participate in body-requirement negotiation** alongside the chain and the
transforms, so one that needs a body says so and composes with ADR-0007 correctly. The OAuth2
responder does not need one: it decides on method, host and path alone.
