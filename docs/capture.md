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

## Containers (Docker/Podman)

Marshal has no container-specific code — a container is just another client — so both modes
above apply unchanged, and either works the same under Podman as under Docker (the compose
file in `examples/docker/` has nothing Docker-specific in it; `podman compose up` or
`podman-compose up` runs it as-is).

* **DNS capture, marshal as a sidecar** — the pattern in `examples/docker/`. The client
  container sets no proxy variables and knows nothing about marshal; its `dns:` entry (or the
  network's default resolver) points at marshal, so hostnames resolve to marshal's address and
  connections arrive on their own. Identity comes from `source_ip`, so give each container a
  static address — see [Identity](configuration/identity.md). Set `upstream.allow_private:
  true` since marshal must route out of the container network to the real internet, and mount
  marshal's CA cert into the client container for TLS interception.
* **Explicit proxy, marshal on the host** — set `HTTP_PROXY`/`HTTPS_PROXY` in the container to
  marshal's `listeners.explicit` address and mount the CA cert. If the container runs with
  `--network host`, it shares the host's network namespace, so `listeners.explicit.unix_socket`
  can be bind-mounted in and `peer_cred` identity (strongest — kernel-supplied uid/gid, see
  [Identity](configuration/identity.md#so_peercred-and-the-unix-listener)) works exactly as it
  would for a bare host process; with bridge networking, `source_ip` is the available resolver
  instead.

**Routing a container's egress through marshal with `iptables -m owner --uid-owner` plus
`REDIRECT` does not work, for two separate reasons.** First, `-m owner` matches the *local*
process that owns the socket at the point the rule evaluates it; a bridge-networked container's
packets are NAT'd/forwarded through a veth from a different network namespace, so the host's
uid-owner rule never sees the container process's uid at all — only host-network containers
expose a matchable uid. Second, and more fundamentally, even a REDIRECT that did match is the
transparent-capture mode described above, which marshal does not accept: it byte-relays rather
than terminating the connection, so `rules`, `dlp`, `mcp`, `judge`, and every transform never
run, regardless of what selected which packets to redirect. Use one of the two patterns above
instead — DNS capture needs no host firewall rule at all, and the explicit-proxy pattern gets
you the same per-uid identity a `uid-owner` rule was trying to provide, without the redirect.

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

When a name resolves to both IPv4 and IPv6 addresses, IPv4 is tried first — many real
deployments (containers, VPNs, IPv4-only networks) have no working route for an IPv6 address
DNS still happily returns, and a resolver's own answer order is not something to rely on. If
the whole attempt still fails, it is retried once with a fresh resolution, since a resolver
hiccup or a momentarily-unreachable address is common enough to be worth one retry; a blocked
address is never retried, since that is a policy decision rather than a network condition.

`allow_private: true` is needed when the proxy and its clients are on a private network the
proxy must also route out of — the docker example sets it for exactly that reason.

`max_response_bytes` is a deployment-wide fallback ceiling on response size, `0` meaning
uncapped. It only fills a gap: a profile that declares its own `response_transforms.body`
limit (see [Transforms](configuration/transforms.md)) uses that instead, entirely — the two
are not combined. Set here rather than per-profile, it protects a profile that scans or
forwards responses without ever having considered how large one could get.
