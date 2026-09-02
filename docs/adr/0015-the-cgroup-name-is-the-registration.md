# ADR 0015: The cgroup naming convention *is* the identity registration

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

[ADR-0009](0009-identity-is-derived-from-the-connection.md) leaves one gap: agents running as
the **same uid**. `peer_cred` cannot separate them, and interactive coding agents run as the
developer, not as service accounts. That is the common case, not an edge case.

Two facts about how agents actually behave shape the answer. Most egress does not come from the
agent process at all — it comes from the `git`, `npm`, `uv` and `curl` processes it spawns. And
cgroup membership is **inherited by children automatically**.

So a cgroup per agent identifies the whole process tree, which is what needs identifying.

The design question is how a running proxy learns that a new agent exists. The obvious answer
is a control socket: `marshal run` registers on start and deregisters on exit.

## Decision

`marshal run` launches the agent inside a transient systemd scope named
`marshal-<profile>-<id>.scope`. The `launched` resolver reads the profile back **out of the
cgroup path**.

There is no registration call and no control socket. **The naming convention is the
registration.**

## Alternatives considered

**A control socket with explicit register/deregister.** The conventional design, and it
introduces state that can desynchronise: an agent killed with `SIGKILL` never deregisters, a
proxy restart loses the table, and a crashed `marshal run` leaves a phantom identity that a
later process could inherit. Every one of those needs reconciliation logic, and reconciliation
against the cgroup tree is just reading the cgroup path — the thing this decision does
directly.

**A file or database of active agents.** Same desynchronisation, plus a file to clean up.

**An environment variable the agent passes through.** Client-asserted, and lost the moment the
agent spawns something that sanitises its environment.

## Consequences

**No state to get out of sync.** The identity exists exactly as long as the cgroup does, and
the kernel manages that lifetime. A killed agent's identity disappears because its scope does;
a proxy restart loses nothing because there was nothing cached.

Child processes are identified for free, which is where most agent egress comes from.

The cost is a **naming convention as an interface**. Renaming the scope format is a breaking
change on both sides, and it is expressed as a string parse rather than a typed protocol.
`parse_scope` is unit-tested against the launcher's own formatting for that reason.

`systemd-run --user` is required, which means a running user systemd instance. Interactive
sessions have one; bare service accounts do not without `loginctl enable-linger` — documented
in [Production](../production.md) because it fails at launch rather than degrading.

**Honest limitation:** with controllers delegated to `user.slice`, a process running as the
user can create cgroups and move itself between them. This is strong against a prompt-injected
agent — the realistic threat — and not against one deliberately impersonating another profile.
Where that distinction matters, use
[`--isolation netns`](0014-netns-isolation-without-cap-net-admin.md), which enforces rather
than identifies.
