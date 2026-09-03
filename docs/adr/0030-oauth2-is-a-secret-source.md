# ADR 0030: OAuth2 is a secret source, not an injection kind

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Boundary secret injection ([ADR-0011](0011-secrets-are-injected-at-the-boundary.md)) had two
sources — `env` and `file` — and five injection kinds. The sources and the kinds divide the
problem cleanly: a source answers *where the credential comes from*, a kind answers *how it is
presented*. Both existing sources share a property that was never stated because nothing
challenged it: the credential already exists, and reading it is local and cheap.

Most APIs worth proxying do not hand out long-lived keys. They hand out short-lived OAuth2
access tokens, minted from a client credential or a refresh token by a call to a token
endpoint, valid for an hour, and replaced thereafter. Supporting that means marshal has to
*obtain* a credential rather than read one: an outbound HTTP call, an expiry to track, a
refresh to schedule, and — for the interactive grants — a refresh token that has to survive a
restart.

Two places could hold it. `Injection::Oauth2` would follow the `SigV4` precedent
([ADR-0028](0028-sigv4-buffers-the-body.md)): a variant owning its own nested config, because
it needs more than one secret and does something more than set a static value. Or a third
`SecretSource`, composed with the `bearer` kind that already exists.

## Decision

OAuth2 is a `SecretSource`. Configuration is `source: { type: oauth2, ... }` alongside
`inject: { type: bearer }`, and `Injection` is untouched.

The division of the problem decides it. `SigV4` is genuinely an injection kind — it *presents*
a credential, in a way no other kind can express, by signing the request. OAuth2 presents its
credential as an ordinary bearer token; every interesting thing about it happens before that.
Putting it in `Injection` would have hard-coded `Authorization: Bearer` into a mechanism whose
whole difficulty is upstream of that choice, and would have made the five existing kinds
unavailable to it for no reason — an API that wants its OAuth2 token on `X-Api-Key` is not
exotic.

This means `SecretSource::resolve` may now do network I/O, on the request path. That is a real
widening of a trait that previously implied a local read, and the rest of the design is shaped
by it: minting is serialised per swap so a burst of requests makes one token call; a live
token is served from memory with no I/O at all; and nothing is minted at startup, so booting
the proxy never depends on an auth server being reachable.

`authorization_code` and `device_code` collapse into one runtime variant, `Enrolled`. They are
two ways for a human to obtain a refresh token; once one exists, what happens per request is
identical. The difference belongs entirely in the enrolment command.

## Alternatives considered

**`Injection::Oauth2`, following SigV4.** Rejected above: it fixes the presentation to bearer,
duplicates plumbing the sources already have, and puts the mechanism on the wrong side of the
source/kind split.

**A separate `oauth2:` top-level config section, referenced by name from a swap.** Genuinely
attractive — one token per credential is more natural than one per swap, and two swaps that
want the same credential for different hosts currently mint it twice. Rejected for now because
it adds a second place credentials are configured and a name-resolution step, to solve a
problem nobody has yet. The token store is keyed by swap name, so this remains addable without
breaking anything: named credentials would be a new key space, not a change to this one.

**A sidecar that mints tokens and writes them to a file, read by the existing `file` source.**
No new code at all, and it works. Rejected because it puts the credential on disk in cleartext
for something else to read, which is the exact property boundary injection exists to remove,
and because "run this other thing too" is a poor answer for the most common form of API
authentication there is.

**Minting eagerly, in the background, ahead of expiry.** Would remove the latency spike on the
first request after an expiry. Deferred rather than rejected: it needs a scheduler, it mints
credentials for swaps that may see no traffic for days, and the lazy path is required anyway
as the fallback. Worth revisiting if the spike proves to matter.

## Consequences

**A proxied request can now block on a third party.** Every layer before this one is local; a
token endpoint having a bad day now shows up as latency on the first request after each
expiry, and as a refusal if it is down. Failing closed is right — forwarding unauthenticated
would produce a confusing 401 from the upstream instead of an actionable 403 from marshal —
but it means an auth server outage stops traffic that a static API key would have carried.

**The blast radius of the token endpoint is the swap's host scope.** Unconditional injection
([ADR-0027](0027-secret-injection-is-unconditional-only.md)) already means every allowed
request in scope gets the credential. Now it also means every one of them can be refused by an
event outside marshal entirely.

**Marshal writes state for the first time.** The interactive grants need a refresh token to
survive a restart, so `state_dir` exists and holds live credentials. Until now the complete
answer to "what does bot-marshal persist?" was a CA key and an optional audit log; it is now a
directory that needs the same care as the CA key, and a backup story nobody had to think about
before.

**The token endpoint is behind the same `upstream` guard as agent traffic.** Defensible —
`deny_cidrs` is where an operator says "never talk to the metadata endpoint", and that should
hold for marshal's own calls too. But it couples two things an operator might reasonably want
to separate: an internal auth server on RFC1918 requires `allow_private: true`, which also
opens agent egress to private addresses. There is no per-source override, and adding one is a
config-surface decision deliberately left for when someone needs it.

**A rotating provider is only fully supported by the enrolled grants.** `grant: refresh_token`
reads from a source marshal does not own and must not rewrite, so a rotated token leaves the
configured value dead. Marshal warns at the moment the rotation is observed rather than
failing an hour later with an unexplained `invalid_grant`, but it cannot fix it.
