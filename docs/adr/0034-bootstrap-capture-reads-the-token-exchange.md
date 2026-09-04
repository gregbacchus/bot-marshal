# ADR 0034: Bootstrap capture reads the token exchange, and trusts the session

* **Status:** Accepted
* **Date:** 2026-09-04

## Context

[ADR-0032](0032-marshal-owns-the-pkce-verifier.md) lets marshal take over an authorization flow
an agent starts, by substituting its own PKCE challenge. That mechanism needs the provider's
`authorization_endpoint`, `token_endpoint` and `client_id` configured up front.

For a vendor's own CLI subscription login — `claude login`, Codex's ChatGPT sign-in — those
values belong to the vendor's OAuth application and are not published. The secret-injection
cookbook shipped `REPLACE-WITH-THE-REAL-...` placeholders for exactly this, which was an honest
admission that the feature did not reach the case people most wanted it for.

Capturing the *authorize* leg cannot solve it either, and not only because the endpoint is
unknown. Those CLIs hand off to the operator's own desktop browser: the tool starts a loopback
listener, shells out to `xdg-open`, and waits. The browser is a separate process that never sees
the proxy environment the CLI was given, and reaches the host browser through a D-Bus portal
rather than a network syscall — so network-namespacing the CLI does nothing to it. Making the
authorize request visible would mean asking the operator to proxy their whole browser.

But whatever route the code takes to get there, the client's **own process** must eventually POST
the token endpoint to redeem it. That is the only way it obtains anything usable. That request
goes out over the client's own network stack, which `HTTPS_PROXY` — or, properly, a network
namespace — does control. And it carries everything worth knowing: `code`, `code_verifier`,
`client_id`, `redirect_uri`, and, as its own destination, the token endpoint itself.

## Decision

A second capture mechanism, `marshal secrets oauth login <name> --wait` / `--run <cmd>`, which
intercepts the token exchange and nothing else. It requires no configuration for the credential
at all: `<name>` is a storage key, not a reference to a swap, because bootstrap runs precisely
when no swap exists yet. It reports the configuration it discovered so the operator can write
one afterwards.

It runs an ephemeral intercepting proxy — the same `Server`/`TlsEngine` as `serve`, using the
same configured CA so existing trust covers it — bound to a loopback port for the duration of
one exchange, under a timeout. `--run` additionally launches the command through
`marshal_launch::build_command_with`, the same primitive `marshal run` uses, so its egress can be
confined.

`--mode` selects what happens to the intercepted request, and **both behaviours are supported
rather than one being correct**:

* **`observe`** forwards it untouched. The provider answers normally, the tool's own login
  succeeds, and it keeps a working credential too — marshal simply also has one.
* **`steal`** redeems out of band and answers with a sentinel, so the client never holds a
  working credential.

This mechanism sits alongside ADR-0032 rather than replacing it. They answer different
questions: ADR-0032 excludes an adversarial agent structurally, and this one reads a login a
human deliberately performed.

## Alternatives considered

**Extend ADR-0032's broker to discover endpoints dynamically.** Rejected: it captures the
redirect, so it still needs whoever made the authorize request to be proxied — which for a
browser-handoff CLI means proxying the operator's browser. Discovering the endpoint would not
have made the traffic visible.

**Require the operator to extract the vendor's `client_id` by inspecting traffic themselves.**
What the cookbook effectively asked for. It works, and it is a miserable first-run experience for
something marshal can simply observe.

**`steal` as the only mode.** Consistent with every other part of this design, and rejected as a
default-by-fiat: the tool being bootstrapped reports its login as failed, because from its point
of view it did. For a supervised one-off enrolment that is confusing for no security benefit,
since the threat model here is not an adversarial client. Both are offered instead.

## Consequences

**In `observe` mode a live credential exists outside marshal.** The tool keeps whatever its own
login produced, in its own credential store, unmanaged. That is a real departure from ADR-0011's
premise, and it is the price of a bootstrap that does not break the tool being bootstrapped.
`steal` is there for anyone who wants the stricter property, and the docs say which is which.

**Matching is by shape, not by configured host and path.** Bootstrap matches any POST whose body
carries `grant_type=authorization_code` or the device-code grant URI, because it cannot know the
host in advance. That is safe here and would not be in a standing transform: this listener exists
for one exchange, in the foreground, with somebody watching. `--host` narrows it when more than
one thing is in flight.

**It constructs a permissive chain in code.** The ephemeral listener runs `Decision::Allow` with
no policy layers, built directly rather than through configuration — so it does not pass through
the `i_understand_this_is_allow_by_default` gate that [ADR-0004](0004-default-deny-lives-in-config.md)
exists to make default-allow legible. This is deliberate and worth stating plainly: the listener
is not policing an agent, it exists for one exchange under a timeout, and denying the provider
traffic the operator is trying to complete would defeat its purpose. The upstream guard still
applies. But it is a second place in this codebase where default-allow is chosen outside config,
and a future one should be scrutinised rather than waved through on this precedent.

**`refresh_token` exchanges are deliberately not captured**, though they would also yield a usable
credential. Capturing one means capturing a client already enrolled somewhere else, and under
`steal` that would break a working tool the operator never meant to touch.

**Device-code polling constrains the trigger.** Nearly every poll answers `authorization_pending`.
Capture therefore fires on the first *response carrying a token*, not the first matching request —
signalling on the request would end the session on the first poll and never see the one that
succeeds.
