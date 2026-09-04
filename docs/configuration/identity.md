# Identity

Which policy applies depends on *which agent* is connecting. Identity is derived from the
connection rather than asserted by the client — DNS [capture](../capture.md) gives a client no
way to present a credential.

## Resolvers are not equal

Resolvers are tried in order, first match wins. List them strongest-first, which is also the
order they should be tried:

| resolver | strength | limitation |
|---|---|---|
| `peer_cred` uid/gid | kernel-supplied, unspoofable | only separates agents running as different users/groups |
| `launched` | cgroup naming from `marshal run`, inherited by child processes | a process can move itself between delegated cgroups |
| `source_ip` | as trustworthy as the network | collapses when two agents share a namespace |
| `listener_port` | as trustworthy as whatever stops an agent reaching another agent's port | client-cooperative — nothing in the proxy itself prevents it |
| `proxy_auth` | client-asserted | an agent that can read another token can pick another profile |

These trust assumptions are load-bearing. `source_ip` holds when each agent owns a
netns/container and cannot rebind or forge a source address. `listener_port` identity holds
only if the agent cannot reach the other listeners directly — nothing in the proxy stops one
agent dialing another's port, so it needs either `marshal run --isolation netns` (which removes
the agent's route to anything but the port it was given) or an external firewall rule.

## Configuration

One `identities:` block: an ordered `resolvers` list, each entry mapping something the
connection carries to an `identity` name and a `profile`, plus `unidentified` for the fallback
when nothing matches.

```yaml
identities:
  resolvers:
    - type: peer_cred                 # kernel-supplied uid/gid — strongest, list it first
      enrich: true                    # needed for cgroup matching, and for gid over TCP —
                                      # uid/username don't need it either way
      map:
        - uid: 1001                   # numeric, or...
          identity: "bot-ci"
          profile: coding-agent
        - username: "bot-nightly"     # ...a name — resolved to a uid once at config load,
          identity: "bot-nightly"     # so matching still happens on the numeric id the
          profile: coding-agent       # kernel reports; exactly as strong as `uid:`
        - groupname: "agents"         # same idea for `gid:`/`groupname:`
          identity: "shared-agents"
          profile: llm-agent

    - type: launched                  # identities `marshal run` registers — no map needed,
                                      # the cgroup naming convention *is* the registration

    - type: source_ip                 # containers / netns: one IP per agent
      map:
        - cidr: "172.20.0.10/32"
          identity: "agent-a"
          profile: coding-agent

    - type: proxy_auth                # weakest — client-asserted — so it goes last
      credentials:
        - user: "agent-a"
          password_env: "MARSHAL_AGENT_A_PW"
          identity: "agent-a"
          profile: coding-agent

  unidentified:                       # nothing matched — falls through to the base config's
    action: allow_with_profile        # embedded `profile:` (the most restrictive one) by
                                      # default; or `deny`, for a hard-fail posture
```

`uid`/`username` are mutually exclusive on one entry (same for `gid`/`groupname`) — `marshal
config check` rejects setting both, and rejects an entry with none of `uid`, `username`,
`gid`, `groupname`, `cgroup` set, since it could never match anything.

A resolver can only target a **named** profile — one defined under `profiles/` — never the
embedded `profile:`, which has no name to reference. See [Profiles](profiles.md).

## `listener_port`

For agents sharing a host and uid, the proxy can bind more than one explicit port and tell
agents apart by which one they were pointed at — no firewall or redirect involved, just each
agent's own `HTTP_PROXY` naming a different port:

```yaml
listeners:
  explicit:
    listen: ["127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082"]
```

```yaml
identities:
  resolvers:
    - type: listener_port
      map:
        - { port: 8081, identity: "agent-a", profile: coding-agent }
        - { port: 8082, identity: "agent-b", profile: llm-agent }
```

Every listed address serves the identical CONNECT/SOCKS5/HTTP protocol — the only difference
is which one accepted the connection. `marshal config check` warns if a `listener_port` entry
names a port that `listeners.explicit.listen` doesn't actually bind, since that entry could
never match anything.

This is the documented fallback for when uid cannot separate the agents, not the primary path.
**It is client-cooperative, not enforced**: nothing stops agent A from also connecting to
agent B's port directly and picking up its profile. Where that matters, put agents under
[`marshal run --isolation netns`](#launching-an-agent) instead, which removes an agent's route
to anything but the address it's given, or add an external firewall rule.

## What lands in the audit record

Every audit record carries the resolved `identity`, which `resolver` matched, and
`attributed: false` when none did. That's what makes `attributed: false` a hard signal rather
than noise: it means every resolver missed and the request got the fallback profile.

Anything unresolved gets a synthetic identity, the embedded (most restrictive) profile, and
`attributed: false` — never a silent inheritance of a permissive one.

## `SO_PEERCRED` and the Unix listener

```yaml
listeners:
  explicit:
    unix_socket: "/run/user/1000/marshal.sock"
```

The Unix listener exists for `SO_PEERCRED`, which is the only same-host identity that is both
unspoofable and free of a lookup race — the kernel stamps pid/uid/gid at connect time, so
there is nothing to look up and nothing to race.

Over TCP, `peer_cred` falls back to a socket-table lookup of the connection's 4-tuple, which
yields the same uid but must find the socket while it is still open. That works in practice
because the lookup happens on the accepted connection, but it is a lookup rather than a
kernel-supplied fact.

`enrich: true` additionally resolves pid, cgroup and cmdline via `/proc`. That is genuinely
racy for short-lived processes and costs a directory walk, so it is **audit annotation
first** — knowing which agent binary made a call is valuable in the log even where it isn't
trustworthy enough to select a profile. It is required for cgroup matching and for gid over
TCP.

## Launching an agent

None of the above gets adopted if it has to be assembled by hand, so `marshal run` does it.
**`run` prepares the agent, it does not start the proxy** — a `marshal serve` on the same
config has to already be running before `run` is invoked, or the agent has nothing to talk to.

```bash
marshal run --profile coding-agent -- claude
```

The agent goes into a network namespace with no route out, inside a transient systemd scope
named `marshal-coding-agent-<id>.scope`. The scope supplies identity — the naming convention
*is* the registration, so the `launched` resolver reads the profile back out of the cgroup and
there is no control socket to get out of sync.

Because cgroups are inherited, the `git`, `npm` and `curl` processes the agent spawns — where
most of its egress actually comes from — are identified too. That gives distinct identities
for agents running as the *same* uid, which uid alone cannot do.

`--profile` can be omitted:

```bash
marshal run -- claude
```

The scope is then named `marshal-<id>.scope`, with no profile segment — a shape the `launched`
resolver does not recognise, so it declines to match, exactly as it does for any cgroup that
isn't its naming convention at all. The connection falls through to the ordinary unattributed
path and gets the embedded `profile:`, same as any other unattributed traffic. Isolation is
unaffected either way — `netns` still removes the agent's route out regardless of whether it
ends up identified.

### `netns` enforces rather than identifies

That is what separates it from every other mode. An unprivileged namespace has loopback and
nothing else; the proxy is reached over a Unix socket, which is a filesystem object and so
crosses the namespace boundary untouched. A small forwarder inside bridges loopback to it. No
`CAP_NET_ADMIN`, no veth, no slirp4netns.

That Unix socket is not optional plumbing — it is the only route out of the namespace, so
`listeners.explicit.unix_socket` (see [`SO_PEERCRED` and the Unix
listener](#so_peercred-and-the-unix-listener) above) must be set in the config `marshal run`
and `marshal serve` share. Without it, `marshal run --isolation netns` refuses to start rather
than silently falling back to TCP, which would put the agent's egress route back outside the
namespace:

```
error: netns isolation reaches the proxy through a Unix socket, so
`listeners.explicit.unix_socket` must be set in the config
```

`--isolation cgroup` and `--isolation none` have no such requirement — they reach the proxy
over TCP like anything else, so `unix_socket` is only mandatory when `--isolation netns` (the
default) is in play.

Setting `unix_socket` in the config is necessary but not sufficient: the socket file itself is
created by `marshal serve` at startup, not by `marshal run`. `marshal run --isolation netns`
only checks that the path already exists and refuses to start otherwise:

```
error: /run/user/1000/marshal.sock does not exist. netns isolation reaches the proxy through
this socket, so the proxy must be running with `listeners.explicit.unix_socket` configured.
```

So `marshal serve` (using a config with `unix_socket` set) has to already be running before
`marshal run --isolation netns` is invoked against the same config:

```bash
marshal --config config/marshal.yaml serve &
marshal --config config/marshal.yaml run --profile coding-agent -- claude
```

The difference is not theoretical. The same agent, told to unset its proxy variables and
connect directly to a host its profile denies:

| isolation | result |
|---|---|
| `cgroup` | reaches the host — **bypassed** |
| `netns`  | `Could not resolve host` — no route out |

Two consequences worth knowing. DNS is gone too, so a hostname is only ever resolved by the
proxy *after* policy has run, which closes DNS-based exfiltration that destination filtering
never sees. And a tool that ignores proxy environment variables gets no network at all rather
than silently bypassing — failing closed is the point, but it does surface badly-behaved
tooling as a hard error.

Only the network is isolated. The filesystem is **not** passed through wholesale: the agent
sees the workspace it was launched from, the standard read-only system directories, the CA
certificate, and the marshal socket — nothing else, and specifically not `/run` or the host's
real `/tmp`, which is where another process's Unix socket (Docker's, for instance) would
otherwise still be reachable from inside a namespace that was supposed to remove every other
route out. `--bind <path>` on `marshal run` opts a specific extra path in, explicitly, when an
agent genuinely needs one. **This is an egress firewall, not a general-purpose sandbox** —
the workspace itself is fully read-write, and nothing here defends against what the agent does
with the files it can already reach.

There is no `$HOME` bind, and the agent command itself is not exempt: a tool installed
somewhere user-local (`~/.local/bin`, a version manager, `npm -g`, `cargo install`, …) needs
`--bind` for its own path too, or `netns` isolation cannot find it — see [CLI › `marshal
run`](../cli.md#marshal-run---profile-name---isolation-netnscgroupnone---proxy-url---bind-path---bind-group-name---dry-run----command)
for the symlink caveat that usually makes one `--bind` insufficient.

```bash
marshal run --profile coding-agent --isolation cgroup -- claude   # identify only
marshal run --profile coding-agent --isolation none   -- claude   # env vars only
```

Both `cgroup` and `netns` go through `systemd-run --user`, which needs a running *user*
systemd instance — see [Production](../production.md) for the service-account gotcha.
