# Capture

Three ways traffic reaches the proxy, in decreasing order of how much the client must
cooperate:

| mode | client must | strength |
|---|---|---|
| explicit | set `HTTP_PROXY` / use SOCKS5 | relies entirely on cooperation |
| transparent | nothing — nftables redirects it | holds while the firewall rules do |
| DNS | point its resolver at the proxy | a convenience, not a boundary |

All three converge on one request representation, so policy is written once rather than once
per mode.

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

## Transparent

```yaml
listeners:
  transparent:
    enabled: true
    listen: ["127.0.0.1:8081"]
```

Transparent interception recovers the pre-redirect destination from conntrack via
`SO_ORIGINAL_DST`, then recovers the *hostname* separately from the TLS SNI or the HTTP `Host`
header.

Both are needed: policy is written in terms of names, and an address is only what the client's
DNS happened to return, so a proxy that could see only `140.82.121.4` would be back to the
coarse filtering this project exists to improve on.

`deploy/nftables.conf` ships the ruleset, including the `filter` chain that makes the redirect
**binding rather than advisory** — without it, an agent using a non-standard port or QUIC
walks straight past. Point its `$MARSHAL_UID` at the uid the proxy runs as, so the ruleset
excludes the proxy's own egress from the redirect.

### Which chain did the redirect?

This determines what identity is available:

| chain | origin | uid available? | resolver |
|---|---|---|---|
| `nat OUTPUT` | same host as the proxy | yes — a local socket exists | `peer_cred` |
| `nat PREROUTING` | container, other netns, other host | no — and the socket table is per-netns | `source_ip` |

REDIRECT rewrites only the destination, so the client's source address and port survive and
the tuple lookup finds the client's own socket. The redirect is invisible to it.

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
