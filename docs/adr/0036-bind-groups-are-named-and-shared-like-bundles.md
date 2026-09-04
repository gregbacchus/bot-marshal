# ADR 0036: Bind groups are named and shared, the same way bundles are

* **Status:** Accepted
* **Date:** 2026-09-05

## Context

[ADR-0024](0024-netns-binds-an-explicit-allowlist.md) replaced `bwrap --dev-bind / /` with an
explicit allowlist: workspace, fixed system directories, CA cert, marshal socket, and whatever
`--bind <path>` adds on the command line. That closed a real privilege-escalation path, but it
also means `--isolation netns` binds nothing under `$HOME` by default — not even the agent
binary itself, if it's installed somewhere user-local.

In practice, almost every real agent is user-local: `~/.local/bin`, a Node/Python version
manager, `npm -g`, `cargo install`. Worse, the common case is a symlink (`~/.local/bin/claude`
→ `~/.local/share/claude/versions/2.1.220`), and `bwrap` does not follow symlinks when deciding
what to bind — the symlink's directory and its resolved target are two different binds. A user
running `marshal run --profile coding-agent -- claude` for the first time gets `No such file or
directory` with no indication that the fix is `--bind`, twice, for two different paths (see
`docs/cli.md`'s `marshal run` section, added after exactly this happened).

`--bind` on its own does not scale past that first encounter: the same two or three paths (an
editor's install directory, a language runtime, a package manager cache) get retyped on every
invocation, for every agent that uses the same tool. That is the same shape of repetition
[bundles](bundles.md) solved for domain allowlists — a named, reusable set referenced from a
profile instead of copied into it.

## Decision

Bind groups: a named, reusable list of paths, resolved to their concrete list by `marshal
config check` and printed as such by `marshal run --dry-run` (never left opaque — a bind group
is filesystem access, not a label).

```yaml
# bind-groups/claude.yaml — the filename is the group's name
paths:
  - "~/.local/bin"
  - "~/.local/share/claude"
```

```yaml
# profiles/coding-agent.yaml
sandbox:
  bind_groups: [claude]
  extra_binds: ["~/.cache/uv"]   # ad hoc, not worth naming and sharing
```

Same rules as bundles throughout, deliberately:

* a bind group can also be declared inline under `bind_groups:` in the base config file, for
  the same reason bundles can — there's no embedded/named distinction worth protecting;
* a name defined both inline and as a file is a load error, not a silent pick;
* `--bind <path>` on the command line still works, unchanged, for the genuinely one-off case;
  a new `--bind-group <name>` flag adds a named group the same way.

Every path a bind group resolves to still goes through the same read-write bind `--bind`
already does — a bind group is sugar over `--bind`'s bind list, not a new capability or a new
trust tier.

## Alternatives considered

**Just document the symlink gotcha and leave `--bind` as the only mechanism.** What this repo
did until now. It does not fix the repetition: every profile that launches the same agent
retypes the same two paths, and a change to where that agent is installed means finding and
updating every invocation rather than one file.

**Put the paths on the profile directly** (`sandbox.extra_binds` with no grouping or naming).
Solves the repetition within one profile but not across profiles that both launch `claude` —
each would carry its own copy of the same two paths, and they drift the same way copy-pasted
domain lists did before bundles existed.

**Auto-resolve symlinks and bind the target transparently**, so a single `--bind ~/.local/bin`
also covers wherever `claude` actually resolves to. Rejected: silently widening one explicit
bind into a second, un-requested one is exactly the kind of implicit exposure ADR-0024 removed.
An agent's install directory and its actual payload directory are not always the same trust
boundary (a version manager's install root can hold many unrelated tools); binding both should
stay two visible entries, whether typed by hand or pulled in by a named group.

**Bind `$HOME` by default, or offer a broad "user tools" bind group that covers most installers
out of the box.** Rejected for the same reason ADR-0024 rejected binding `$HOME`: it routinely
holds credentials with no relationship to any given profile, and a broad default is exactly the
un-auditable convenience this project has consistently traded away for explicitness. A bind
group must still be *named and referenced* by every profile that wants it.

## Consequences

Profiles gain a `sandbox.bind_groups` key and bind groups become a new named, file-or-inline
config concept — a real schema surface, not a routine addition, which is why this needed an ADR
rather than a plain PR.

A bind group is not free to add: unlike a bundle, whose worst case is an over-broad network
allow, a bind group that lists too much or too widely-shared a path grants read-write
filesystem access to every profile that references it. `config check` resolving and printing
the concrete path list (rather than leaving `bind_groups: [claude]` opaque in review) is load-
bearing for this staying auditable, not a nice-to-have.

`--bind` and `extra_binds` do not go away — a bind group is for the reusable case, not a
replacement for the ad hoc one. A profile can mix both.

This does not change what `netns` isolation exposes by default; it only makes the explicit,
already-required opt-in easier to write correctly and keep consistent across profiles. The
disruption ADR-0024 accepted — that a tool outside the allowlist fails until someone binds it —
is unchanged; this ADR makes the fix for a recurring tool a one-time definition instead of a
retyped one.
