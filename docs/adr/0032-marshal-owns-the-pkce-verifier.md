# ADR 0032: Marshal owns the PKCE verifier and terminates the authorization flow

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

`marshal secrets oauth login` enrols an OAuth2 credential out of band: an operator authorises
once, marshal keeps the refresh token, and the proxy runs unattended thereafter. That covers
the case where a human sets a credential up in advance.

It does not cover the case that prompted this work: an **agent** that wants to authenticate to a
service and drives an OAuth flow itself. The agent opens an authorization URL, receives a
redirect carrying `?code=`, exchanges it, and holds the resulting tokens. At the end of that,
the agent is holding a live credential — which is exactly the state boundary injection
([ADR-0011](0011-secrets-are-injected-at-the-boundary.md)) exists to prevent. Compromising the
agent costs a rotation again.

Stopping the flow is not an answer. The agent needs the service; refusing the authorization
request tells it only that something is broken.

The observation the design turns on: **PKCE already gives one party exclusive redemption
rights, and nothing says that party has to be the client.** RFC 7636 binds an authorization code
to a secret held by whoever *started* the flow. If marshal substitutes its own challenge into
the authorization request, the code the provider later issues is redeemable only by marshal —
not because the agent is blocked from trying, but because it does not hold the verifier that
matches the challenge the provider recorded. The mechanism the client would have used to
protect itself becomes the mechanism that excludes it.

## Decision

Under `capture: in_band`, marshal takes over an authorization-code flow the agent starts, in
three steps:

1. **Substitute the challenge.** On a request to the configured `authorization_endpoint` with
   `response_type=code`, marshal generates its own verifier, replaces `code_challenge`, and
   forces `code_challenge_method=S256`. The agent's `state` and `redirect_uri` are left exactly
   as sent — they have to be, or the agent's own CSRF check fails and the provider rejects a
   redirect URI it was never registered with. Only the verifier is marshal's.

2. **Take the code out of the redirect.** Marshal intercepts the response, matches the
   `Location` header's `state` against a flow it started, lifts the code out, and completes the
   exchange itself — a direct call to the token endpoint, out of band. It then rewrites
   `Location` so the code the agent receives is an inert sentinel. **The real code is replaced
   whether or not marshal's own exchange succeeds**: if marshal cannot redeem it, the agent must
   not be handed the chance either, and the failure surfaces as a refused API request naming the
   cause.

3. **Answer the agent's exchange locally.** The agent's POST to the token endpoint is answered
   by marshal and never forwarded ([ADR-0031](0031-a-responder-may-answer-a-request.md)), with a
   well-formed token response carrying a sentinel. The agent's state machine completes
   normally, on nothing.

Matching for step 2 is on the `Location` header, not on the request URL. A provider typically
serves a login page at its authorization endpoint and issues the redirect from whatever the
login form posts to, so keying on "a `Location` whose `state` is one marshal issued" catches it
wherever it originates, and can fire on nothing else.

The sentinel does not resurrect the placeholder model
[ADR-0027](0027-secret-injection-is-unconditional-only.md) removed. Nothing matches on it and
nothing depends on the agent presenting it: injection is unconditional, so whatever the agent
sends to the API is overwritten with the real token regardless. The sentinel exists to make the
agent's protocol handling terminate, not to be recognised later.

`capture` is **off by default**, and applies only to `grant: authorization_code`.

## Alternatives considered

**Pass the agent's challenge through and take the code anyway.** Simpler by one step. Rejected:
without substitution, an agent that reads the code out of its own redirect before marshal's
response transform runs — or that obtains it by any path marshal does not see — can complete
the exchange itself and hold real tokens. Substitution is what makes the exclusion structural
rather than a race.

**Refuse authorization flows outright** and require `marshal secrets oauth login` for every
credential. Safe, and it remains the recommended path. Rejected as the only option because it
requires an operator to anticipate every service an agent will ever need, which is not how
agents are used.

**Let the agent complete its own flow and strip the tokens from the token response instead.**
Would avoid touching the authorization request at all. Rejected: the tokens exist at the
provider by then and the agent has already proven it can obtain them, so any path marshal does
not intercept — a retry, a different endpoint, a cached response — yields a live credential.
Intervening at the challenge means there is no such path.

## Consequences

**The agent can never complete its own OAuth flow, by construction.** That is the feature. It is
also a substantial claim on the agent's behaviour: marshal rewrites a request the agent
composed, and answers a request the agent addressed to somebody else. Anything that inspects
what it sent — a client that verifies the challenge in the authorization URL matches the one it
generated, or that checks the token response against a nonce — breaks. Such clients exist, and
there is no way to support them and this feature at once.

**Capture is best-effort by construction.** The provider redirects whoever made the
authorization request; if that is a browser rather than the agent's own HTTP client, the browser
must also be behind the proxy or marshal never sees the redirect. An authorization request made
outside the proxy's capture is never rewritten at all. `marshal secrets oauth login` is the
guaranteed path; this is the convenient one.

**Marshal now rewrites requests based on their content, not just their destination.** Every
other transform sets a header or signs what is there. This one parses a query string, makes a
decision about the protocol being spoken, and rewrites accordingly. A provider whose
authorization endpoint does something unusual is a source of breakage that no other transform
has.

**Requires `https` endpoints.** Capture depends on marshal seeing the response, which requires
interception; a plain `http` request through the explicit proxy is relayed. The configuration
refuses to build otherwise, rather than capturing nothing and saying nothing.

**Pending flows are bounded.** The table of open flows is filled by whatever the agent chooses
to request, so it is capped (32 per swap, 10 minute TTL, oldest evicted). A real flow can be
pushed out by 32 newer ones inside the TTL — an agent hammering the authorization endpoint can
therefore cause its own capture to fail, which is a denial of its own service and not a leak.
