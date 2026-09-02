# ADR 0011: Secrets are injected at the boundary, not held by the agent

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

An agent that calls the GitHub API needs a GitHub token. Conventionally it holds one, in its
environment or a config file.

That makes every agent compromise a credential compromise. A prompt injection that gets the
agent to read its own environment and send it somewhere costs a token rotation and whatever
happened in between. Egress filtering helps but cannot be complete: the token is a string in a
process that is allowed to make network requests.

The proxy is already terminating TLS and rewriting requests, so it is already in the one
position where the swap can happen.

## Decision

The agent holds a **placeholder**. The real credential lives in the proxy's environment or a
file it reads, and a `request_transforms.secrets` entry swaps placeholder for real value on the
way out, scoped to named hosts.

```yaml
secrets:
  - source: { type: env, var: GITHUB_TOKEN }
    proxy_value: "marshal-github-placeholder"
    match_headers: ["authorization"]
    require: true
    rules: [{ host: "api.github.com" }]
```

`require: true` fails the request when the real secret cannot be resolved, rather than
forwarding the placeholder. Secrets are redacted from every audit path and log line, and a
`response_transforms` `redact` closes the loop on a credential the upstream echoes back.

## Alternatives considered

**Let the agent hold the real token, and rely on DLP to catch exfiltration.** Detection rather
than prevention: it depends on recognising the credential in whatever encoding the agent sends
it, and the `dlp` layer exists for the credentials this scheme cannot cover, not as a
replacement for it.

**A separate credential-broker service the agent calls.** Cleaner separation, and the agent
still ends up holding whatever authenticates it to the broker.

**Short-lived tokens minted per request.** Better where the upstream supports it, and most do
not. Compatible with this design rather than an alternative to it.

## Consequences

**Compromising the agent no longer costs a rotation.** The real credential never exists in the
agent's process, environment or filesystem.

The proxy becomes a higher-value target, holding both the CA key and every injected
credential. This is the main reason [Production](../production.md) recommends running it as a
dedicated user with nothing else.

Scoping by `rules: [{ host: ... }]` matters more than it looks: without it, a credential would
be offered to any host the chain allows, which turns an allowlist gap into a credential leak.

`require: true` is the safe setting and not the default-by-omission, so a profile that forgets
it forwards a placeholder upstream and fails confusingly. Worth calling out in review.

Testing this needs the specific assertion that greps the entire audit output for the literal
secret value and asserts zero hits — noted in [AGENTS.md](../../AGENTS.md), because a redaction
bug is invisible to every other test.
