# ADR 0028: SigV4 injection buffers the body, capped, as a declared exception

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Secret injection ([ADR-0011](0011-secrets-are-injected-at-the-boundary.md),
[ADR-0027](0027-secret-injection-is-unconditional-only.md)) gained a `header` and `query`
injection kind alongside `basic`/`bearer`, and AWS Signature Version 4 was requested as a
fourth. SigV4 signs a request with an access key pair rather than setting one static
credential value: the signature covers the method, canonical URI, canonical query string, a
fixed set of headers, and — centrally — a SHA-256 hash of the request body
(`x-amz-content-sha256`), all folded into a derived HMAC chain
(`kSecret → kDate → kRegion → kService → kSigning → signature`).

That body hash is the problem. [ADR-0007](0007-bodies-stream-by-default.md) makes streaming
the default and requires any transform that needs bytes to declare a cap explicitly — never a
silent buffer. AWS does define an escape hatch, `UNSIGNED-PAYLOAD`, which skips the body hash
and lets the body keep streaming; S3 accepts it. But it is not a general answer: several AWS
services (API Gateway/`execute-api` request validation, some DynamoDB and IAM operations)
reject `UNSIGNED-PAYLOAD` outright, since the whole reason to sign the body is to prove it
wasn't tampered with in transit. Defaulting to unsigned payloads would silently produce a
weaker signature than a real AWS SDK would send, for a large share of the services this feature
exists to support.

## Decision

`Injection::SigV4` always hashes the real body. [`SecretInjector::body_requirement`] combines
`BodyRequirement::Buffered { cap }` into the transform's overall requirement whenever any
configured swap uses `sigv4` — cap taken from that swap's `max_body_bytes` (config field on
`inject: { type: sigv4, ... }`), defaulting to 1 MiB. This is exactly the same declared-cap
buffering pattern the `dlp` policy layer already uses for request body scanning; nothing new
architecturally, but the first `RequestTransform` (as opposed to `PolicyLayer`) to buffer.

A body that exceeds the cap is a hard failure: `sign_sigv4` returns `Error::BodyTooLarge`,
which — like any other transform error — the proxy turns into a structured deny response
([`mitm.rs`](../../crates/marshal-proxy/src/mitm.rs) refuses rather than skips a transform that
cannot do its job). There is no `UNSIGNED-PAYLOAD` fallback and no "sign what fit" partial
mode: an incompletely-hashed body would produce a signature AWS accepts but that does not
actually cover the whole request, which is worse than refusing outright.

## Alternatives considered

**`UNSIGNED-PAYLOAD` always.** Rejected: correct for S3, silently wrong (accepted by AWS,
but weaker than a real client would send) for services that expect a real body hash — and an
operator scoping a `sigv4` swap at a non-S3 host would have no way to know their requests were
being under-signed.

**`UNSIGNED-PAYLOAD` for GET/HEAD, buffered hash for bodies that exist.** Considered, since
most SigV4 traffic through an egress proxy will be simple reads with no body. Rejected as
premature optimisation: a GET with no body already hashes near-instantly (`SHA-256("")` is
one block), so the buffering cost this ADR is really about only applies when there is a body
to buffer in the first place — the distinction would add a branch without avoiding a real cost.

**Making `SigV4` a separate policy-layer-adjacent mechanism instead of a `RequestTransform`.**
Rejected: it is still fundamentally "set a credential on an allowed request," the same job
`Injection::Basic`/`Bearer`/`Header`/`Query` already do; splitting it into its own trait
implementation would duplicate host-scoping, evidence recording, and the swap list without
buying anything.

## Consequences

A profile with a `sigv4` swap gets a body-buffering transform for every request to that swap's
scoped hosts, same as a profile with `dlp.scan_request: true` already does — `marshal config
check` surfaces this the same way (a warning that responses/requests it applies to cannot
stream), and it composes correctly with `BodyRequirement::combine`, so a profile mixing a
`sigv4` swap with an unrelated streaming-only transform still buffers only as required.

The 1 MiB default cap is a judgment call, not a measured one: large enough for typical signed
API bodies (S3 object metadata operations, DynamoDB items, API Gateway payloads), too small for
signed large-object uploads to S3, which need `UNSIGNED-PAYLOAD` streaming semantics this
proxy's `sigv4` kind does not implement. An operator who needs large signed uploads to work
through this proxy needs a larger `max_body_bytes` (accepting the memory cost) or a swap scoped
away from that path entirely — there is no third option today.

Only `host`, `x-amz-content-sha256`, and `x-amz-date` are ever signed headers. AWS requires no
more than that; signing the full header set the client sent would tie the signature to
whatever an earlier transform in the same profile (a `headers.allow` filter, `set_headers`)
does to those headers, coupling two transforms that should stay independent.
