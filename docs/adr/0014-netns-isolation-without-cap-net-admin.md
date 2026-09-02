# ADR 0014: Network-namespace isolation without `CAP_NET_ADMIN`

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Everything else in this tool **identifies** traffic. Nothing makes an agent actually use the
proxy. `HTTPS_PROXY` is a convention an agent can ignore, unset, or never read.

The gap was measured rather than assumed. The same agent, told to unset its proxy variables and
connect directly to a host its profile denies:

| isolation | result |
|---|---|
| `cgroup` | reaches the host — **bypassed** |
| `netns`  | `Could not resolve host` — no route out |

Identification without enforcement means a compromised agent — the threat model — simply
declines to participate.

The conventional way to give a process its own network namespace with working egress needs
`CAP_NET_ADMIN`, a veth pair, and NAT, or a userspace network stack like slirp4netns. Both are
substantial setup, and requiring root for a developer tool is most of the way to it not being
used.

## Decision

`marshal run --isolation netns` (the **default**) puts the agent in an unprivileged network
namespace that has loopback and nothing else. The proxy is reached over a **Unix domain
socket**, which is a filesystem object and therefore crosses the namespace boundary untouched;
a small forwarder inside the namespace bridges loopback to it.

No `CAP_NET_ADMIN`, no veth, no NAT, no slirp4netns, no root.

Only the network is isolated. The filesystem is passed through, because the agent needs its
workspace.

## Alternatives considered

**veth + NAT.** The standard approach, needs `CAP_NET_ADMIN` and per-launch teardown.

**slirp4netns.** Works unprivileged, adds a dependency and a userspace TCP stack in the data
path.

**cgroup isolation only.** Already available as `--isolation cgroup`, and it identifies without
enforcing, as the table above shows. Retained for cases where enforcement is not wanted.

**Firewall rules instead.** Effective, and system-wide, root-requiring configuration rather
than something a developer can run per agent.

## Consequences

**The proxy becomes the only route out**, which is the property nothing else here provides. It
is the default for `marshal run` for that reason.

DNS goes with it. A hostname is only ever resolved by the proxy, after policy has run — closing
DNS-based exfiltration that destination filtering never sees, and composing with
[ADR-0010](0010-resolve-once-connect-to-the-checked-address.md).

A tool that ignores proxy environment variables now gets **no network at all** rather than
silently bypassing. Failing closed is the point, and it does surface badly-behaved tooling as a
hard error rather than a quiet policy hole.

This requires a Unix listener to be configured. Without one there is nothing for the namespace
to reach.

**This is an egress firewall, not a sandbox.** The filesystem is untouched, so an agent can
still read and write everything its uid can. Anyone reading "namespace isolation" as
containment should stop at this paragraph.

`unshare --net --map-root-user` grants full `CAP_NET_ADMIN` *inside* the namespace with no root
outside it, which is also what makes the `SO_ORIGINAL_DST` transparent-mode tests exercisable
against a real kernel redirect in CI.
