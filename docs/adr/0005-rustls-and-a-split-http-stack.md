# ADR 0005: rustls, and a deliberately split HTTP stack

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

A MITM proxy needs to terminate TLS from the client, mint a leaf certificate per SNI on the
fly, and originate its own TLS upstream. It also needs HTTP handling that can do things a
normal server framework actively hides: take over a connection after `CONNECT`, relay a
protocol upgrade bidirectionally, and stream a body without collecting it.

It separately needs a small management API, where none of that applies and ordinary
request/response ergonomics are exactly right.

## Decision

**TLS: `rustls` + `tokio-rustls`, with `rcgen` for leaf minting.** No OpenSSL.

**HTTP: `hyper` + `hyper-util` on the proxy path; `axum` only for the management API.**

## Alternatives considered

**OpenSSL / native-tls.** Mature and universally understood, at the cost of a C toolchain and
system library version in the build, and a much less pleasant certificate-generation story.
The single-static-binary property is worth more here than familiarity.

**axum for everything.** The management API is genuinely nicer in axum, and the proxy path
needs connection takeover, upgrade relaying and streaming control that a routing framework
exists to abstract away. Fighting the abstraction on the hot path costs more than running two
levels of the same stack.

**hyper for everything.** Would make the management API hand-rolled routing and manual JSON
for no benefit; it is an ordinary REST surface and should be written like one.

## Consequences

The binary is self-contained: no OpenSSL version to match against the host, which matters for
a tool meant to be dropped into a container or a CI image.

Two HTTP idioms live in one codebase, and a contributor has to know which half they are in.
The split is along a clean line — `marshal-proxy/src/management.rs` is the only axum
surface — but it is a thing to learn.

`rustls` is stricter than OpenSSL about certificates and protocol versions. That is mostly
desirable and occasionally surfaces as an upstream that OpenSSL would have talked to and this
will not; `tls.upstream_ca_certs` and `tls.passthrough` are the escape hatches.
