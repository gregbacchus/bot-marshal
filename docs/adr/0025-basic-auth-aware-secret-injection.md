# ADR 0025: Secret injection understands `Basic` auth, with no new config

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Boundary secret injection ([ADR-0011](0011-secrets-are-injected-at-the-boundary.md)) works by
substring replacement: find `proxy_value` inside a header, the query string, or the body, and
swap it for the real secret. That covers a bearer token or a custom API-key header, where the
placeholder appears in the request exactly as the operator wrote it.

It does not cover `Authorization: Basic base64("user:password")` — the scheme `git` over
HTTPS, most package registries (npm, pip, private cargo registries), and container registry
logins all normally use. The client base64-encodes the credential before it reaches the wire,
and base64 does not preserve substrings: encoding `"x-access-token:marshal-placeholder"`
does not contain the readable text `marshal-placeholder` anywhere in its output. Substring
matching against the raw header therefore never finds it, silently (or, with `require: true`,
the request is refused as if the placeholder were simply missing).

This meant the three workloads named directly in the question that prompted this ADR — git
clones, package manager installs, container pulls — were exactly the cases boundary injection
did not actually cover, despite being among the most common things an agent does.

## Decision

Header matching (`match_headers`) now recognises two shapes for the same configured swap, with
**no new configuration field**:

1. The placeholder appears directly in the header text — unchanged, existing behaviour.
2. The header value is a `Basic` challenge. It is decoded, the placeholder is looked for in the
   decoded `user:password` string, and — if found — replaced and the header re-encoded.

Both paths are tried for every header a swap is configured to scan; whichever one actually
finds the placeholder is the one that fires. The `require` check (does this request carry the
placeholder at all) is updated identically, so a Basic-encoded placeholder is recognised as
"present" for that purpose too.

```yaml
request_transforms:
  secrets:
    - name: GIT_TOKEN
      source: { type: env, var: GIT_TOKEN }
      proxy_value: "marshal-git-placeholder"
      require: true
      rules: [{ host: "github.com" }]
```

```bash
git clone https://x-access-token:marshal-git-placeholder@github.com/owner/repo
```

This is the identical config shape as the bearer-token case in
[ADR-0011](0011-secrets-are-injected-at-the-boundary.md)'s own example. The operator does not
declare which encoding a host uses; the swap tries both because recognising `Basic ` is
parsing a fixed, standard wire format ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)), not
guessing at one.

## Alternatives considered

**A config flag** (`basic_auth: true`) that opts a swap into decode-aware matching. Considered
and rejected during review: it asks the operator to already know and declare an implementation
detail of the upstream's auth scheme, for a header format that is unambiguous the moment you
look at it. The config a git-credential swap needs is identical to a bearer-token swap's; a
flag would be one more thing to get right for no expressive benefit.

**Route Basic-auth credentials through a different mechanism entirely** (a dedicated
`git_credential` transform, say). Rejected as unnecessary specialisation: the placeholder
model, host scoping, and `require` semantics are all identical to the existing case — only the
wire encoding differs, which is exactly the kind of detail the injector should absorb rather
than push onto a new, parallel configuration surface.

## Consequences

Git, npm, pip, and container registry logins can now be placeholder-injected the same way an
API bearer token already could, closing the gap that prompted this ADR.

The decode step is attempted only as a fallback, after the plain substring check misses — so
there is no behavioural change for any swap that was already working (a Bearer-style header
that happens to contain valid-looking base64 as a coincidence would still be matched by the
first, direct check, never reaching the Basic-decode path at all).

A header that decodes as Basic but does not carry the placeholder is left alone, indistinguishable
from before this change — the injector only ever acts on a match, so an unrelated service's
Basic-authenticated request routed through the same profile is not at risk of being touched by
a swap meant for a different host (host scoping via `rules` was already the boundary for that,
and remains so).

The base64 codec is hand-rolled directly in `marshal-secrets` (roughly the same twenty lines
`marshal-proxy`'s `httpfront` already carries for decoding a client's own `Proxy-Authorization`)
rather than a new external dependency or a cross-crate coupling between the two — consistent
with this project's existing choice not to pull in a crate for a parser this small.
