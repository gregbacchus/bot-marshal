# Capture

Clients reach marshal through an **explicit HTTP proxy or SOCKS5 connection**. Set
`HTTP_PROXY`/`HTTPS_PROXY`, or configure SOCKS5 in the client. These settings rely on client
cooperation; [`marshal run --isolation netns`](configuration/identity.md#netns-enforces-rather-than-identifies)
adds a network boundary that prevents direct egress.

## Explicit

HTTP `CONNECT`, absolute-form HTTP and SOCKS5 share a TCP port; marshal sniffs the protocol
from the first byte. HTTPS CONNECT and SOCKS5 tunnels are intercepted using the configured CA.
Plain HTTP requests receive request policy and request transforms, but their responses are
relayed without the TLS interception response pipeline. Use HTTPS when you need response
inspection or rewriting.

```yaml
listeners:
  explicit:
    listen: "127.0.0.1:8080"
    unix_socket: "/run/user/1000/marshal.sock"
```

The Unix socket supports HTTP proxy connections and
[`SO_PEERCRED` identity](configuration/identity.md#so_peercred-and-the-unix-listener).
It also carries a `netns` agent's egress through the in-namespace forwarder. Unlike the TCP
listener, it does not accept SOCKS5.

## DNS

The optional DNS server can return a configured proxy address, pass selected names to its
upstream resolver, or serve fixed address records:

```yaml
listeners:
  dns:
    enabled: true
    listen: "127.0.0.1:5353"
    proxy_ip: "127.0.0.1"
    passthrough: ["*.internal.corp", "localhost"]
    records:
      - name: "build.internal.corp"
        value: ["192.168.10.20"]
```

| field | default | meaning |
|---|---|---|
| `enabled` | `false` | start the DNS server |
| `listen` | required when the block exists | DNS bind address and port |
| `proxy_ip` | required | address returned for intercepted names |
| `passthrough` | `[]` | hostname patterns resolved normally |
| `records` | `[]` | fixed records; each has `name` and a list `value` (`values` is an alias) |

Fixed records take precedence over passthrough, which takes precedence over the proxy answer.
The listener serves DNS over UDP and TCP. A nonstandard port such as `5353` needs a resolver
client that can select that port.

**DNS answers alone do not capture ordinary HTTP/HTTPS traffic in this release.** An HTTPS
client still connects to port `443` and starts TLS directly. Marshal's explicit listener
expects CONNECT or SOCKS5 first, and there is no direct TLS/origin-HTTP ingress listener that
turns those DNS-directed connections into intercepted requests. Changing the explicit port to
`443` does not change its protocol. Use explicit proxy configuration for working egress;
the DNS service is a resolver feature, not a complete proxy-free capture workflow.

A client using another resolver, DNS-over-HTTPS, or literal IP addresses can also avoid this
DNS service. Network enforcement belongs to `netns` isolation or an operator-managed firewall.

## Transparent capture is not supported

The nftables/iptables REDIRECT capture mode was removed after M6. It did not run the full
interception pipeline and did not verify that the redirected destination belonged to the
hostname used for policy. See [ADR-0022](adr/0022-remove-transparent-capture.md).

Marshal has no supported transparent ingress for workloads that cannot use an explicit proxy.
Firewall rules may block bypass traffic, but redirecting raw HTTP/TLS into the explicit proxy
listener does not convert it into supported traffic.

## Containers (Docker/Podman)

The [container example](../examples/docker/README.md) configures explicit proxy variables,
mounts the CA certificate and attributes two clients by their static source addresses. It
keeps `upstream.allow_private: false` because its upstream APIs are public.

For a proxy running on the host, use an address reachable from the container; its loopback is
usually different from the host's. Bind marshal to a suitable host interface and restrict
access to the intended clients. `source_ip` attribution depends on the source address marshal
actually sees after container routing or NAT.

A bind-mounted Unix socket is another route where the client supports HTTP proxying over a
Unix socket. Its peer credentials are supplied by the kernel, subject to the container's user
namespace mappings; sharing the host network namespace is not required for a Unix socket.
Mount only the CA certificate into clients, not the private key or marshal's credential state.

Proxy variables are not containment. A container can ignore them and connect directly unless
its network/firewall policy prevents that. Host `iptables -m owner` rules do not identify
bridge-container processes from their forwarded packets. Use network-level controls suited to
your container runtime; marshal does not ship a firewall installation recipe.

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

`allow_private: true` permits **private upstream destinations**. It is not needed just because
marshal or its clients run on a private/container network: a public API still resolves to a
public destination, even when the route to it crosses a private gateway. Keep it `false` for
public-only egress. Explicit `deny_cidrs` still apply when private destinations are allowed.

`max_response_bytes` is a deployment-wide fallback ceiling on response size, `0` meaning
uncapped. It only fills a gap: a profile that declares its own `response_transforms.body`
limit (see [Transforms](configuration/transforms.md)) uses that instead, entirely — the two
are not combined. Set here rather than per-profile, it protects a profile that scans or
forwards responses without ever having considered how large one could get.
