# ADR 0020: Reload builds everything before swapping; a failure changes nothing

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Policy changes more often than the binary does. Restarting to pick up a config drops in-flight
connections, so a reload endpoint is wanted.

The dangerous way to implement it is incrementally: swap profiles as they parse, add resolvers
as they build. A config that fails halfway then leaves the proxy in a state matching no file —
some old policy, some new — and that state is not reproducible from anything on disk.

For a security control, a partially applied policy is worse than either version: it is a
configuration nobody wrote and nobody can inspect.

There is a second hazard. If a request in flight reads policy while it is being replaced, it
can be evaluated against a mixture of both.

## Decision

`POST /v1/reload` builds the **entire** new configuration — every chain, transform, resolver
and profile — before swapping a single pointer.

**A reload that fails changes nothing**, and says so:

```json
{ "status": "rejected",
  "error": "profiles.coding-agent.policy[0]: references unknown bundle `does-not-exist`",
  "note": "the previously loaded configuration is still in effect" }
```

A connection **reads the runtime once and keeps that view**, so a reload never changes the
rules under a request already in flight.

## Alternatives considered

**Incremental application.** Simpler and admits the half-applied state above.

**Drain, then reload.** Fully consistent, and it makes a policy update an availability event —
which discourages the frequent small updates a warn-mode rollout depends on.

**Watch the file and reload automatically.** Convenient, and it applies a half-written file the
moment an editor saves it. An explicit endpoint makes the operator choose the moment.

## Consequences

**Reload is atomic and safe to retry.** A rejected reload is a no-op, so the recovery is to fix
the config and call it again.

The error names the exact config path, because the person reading it is looking at a YAML file,
not at the code. This is the same diagnostic machinery `config check` uses, which is why
`config check` passing is a reliable predictor that a reload will succeed.

Building everything before swapping means transiently holding two full configurations in
memory. For realistic configs this is negligible.

A long-lived connection keeps the policy it started with until it closes. That is the correct
trade — the alternative is changing the rules mid-request — but it means a reload does not
immediately affect established tunnels, which can be surprising when tightening a policy in
response to something happening right now. Restart if that matters.

The binary is not reloadable, only the config. Upgrades are a restart, so
[Production](../production.md) recommends `config check` before one.
