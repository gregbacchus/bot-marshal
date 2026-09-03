# Capture

Two ways traffic reaches the proxy, in decreasing order of how much the client must cooperate:

| mode | client must | strength |
|---|---|---|
| explicit | set `HTTP_PROXY` / use SOCKS5 | relies entirely on cooperation |
| DNS | point its resolver at the proxy | a convenience, not a boundary |

Both converge on one request representation, so policy is written once rather than once per
mode.

## Explicit

HTTP `CONNECT` and SOCKS5 on the same port; the protocol is sniffed from the first byte.

```yaml
listeners:
  explicit:
    listen: "127.0.0.1:8080"
    unix_socket: "/run/user/1000/marshal.sock"   # unlocks SO_PEERCRED identity
```

The Unix socket is what makes `SO_PEERCRED` reachable — see
[Identity](configuration/identity.md#so_peercred-and-the-unix-listener). It is also how a
`--isolation netns` agent reaches the proxy from inside a namespace with no network.

## DNS

```yaml
listeners:
  dns:
    enabled: true
    listen: "127.0.0.1:5353"
    proxy_ip: "127.0.0.1"
    passthrough: ["*.internal.corp", "localhost"]
```

DNS mode resolves every name to the proxy so unconfigured workloads arrive on their own.
Static records beat passthrough, which beats interception; TTLs are short so a stale answer
cannot outlive a policy change.

`examples/docker/` shows two containers captured with no proxy environment variables at all,
told apart purely by source address.

**Be clear about what DNS mode is not.** A client that ships its own resolver, uses
DNS-over-HTTPS, or connects to a literal address never asks us. It is for workloads that cannot
be configured. Where bypass actually matters, use
[`marshal run --isolation netns`](configuration/identity.md#netns-enforces-rather-than-identifies),
or the firewall rules.

## Transparent capture is not supported

An nftables/iptables-REDIRECT capture mode existed through M6 and was removed. It recovered
the hostname from TLS SNI or the HTTP `Host` header but never verified the redirected
destination actually belonged to it, and it byte-relayed the connection rather than
intercepting — so `rules`, `dlp`, `mcp`, `judge`, and every transform never ran on it. That is
the same gap [interception being mandatory](concepts.md#why-interception-is-mandatory) exists
to close for explicit traffic, so rather than rebuild transparent capture on top of the same
interception pipeline explicit traffic already gets, it was dropped. See
[ADR-0022](adr/0022-remove-transparent-capture.md).

For a workload that cannot be configured to use a proxy, DNS mode above is the supported
option — weaker (nothing stops a client with its own resolver from bypassing it), but honest
about that weakness rather than silently under-enforcing while appearing to intercept.

## The upstream guard

Independent of capture mode, every resolved IP is checked against `upstream.deny_cidrs` after
DNS and before connect:

```yaml
upstream:
  deny_cidrs:
    - "169.254.0.0/16"     # link-local, incl. cloud metadata endpoints
    - "127.0.0.0/8"
    - "::1/128"
  allow_private: false
  max_response_bytes: 0
```

The hostname is resolved once, each resulting address checked, and the connection made **to
that checked address** — never re-resolved between check and connect, which is what closes DNS
rebinding.

`allow_private: true` is needed when the proxy and its clients are on a private network the
proxy must also route out of — the docker example sets it for exactly that reason.
