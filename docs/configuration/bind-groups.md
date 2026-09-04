# Bind groups

A bind group is a named, reusable list of filesystem paths — a set of `--bind`s a profile can
reference by name instead of repeating them on every `marshal run --isolation netns`
invocation. It exists for the same reason [bundles](bundles.md) exist for domain allowlists:
the same two or three paths (an editor's install directory, a language runtime, a package
manager cache) get retyped for every agent that uses the same tool, and drift the same way
copy-pasted domain lists did before bundles existed. See
[ADR-0036](../adr/0036-bind-groups-are-named-and-shared-like-bundles.md) for why.

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
```

```bash
marshal run --profile coding-agent -- claude
```

This repo ships a starting set under `config/bind-groups/` you can copy from for a common
install layout — check what `which <your-tool>` and `readlink -f "$(which <your-tool>)"`
actually resolve to on your system before trusting one of these as-is; install paths vary by
package manager and version manager.

## A bind group grants filesystem access, not just a label

Unlike a bundle, whose worst case is an over-broad network allow, a bind group that lists too
much or too widely-shared a path grants **read-write** filesystem access to every profile that
references it — the same read-write bind `--bind` already grants, since a bind group is sugar
over `--bind`'s bind list, not a new capability or a new trust tier. `marshal config check`
and `marshal run --dry-run` both resolve a bind group to its concrete path list rather than
leaving `bind_groups: [claude]` opaque in review — treat that resolved list as what you are
actually reviewing, not the name.

Only `--isolation netns` has anything to bind into — `cgroup` and `none` ignore
`sandbox.bind_groups`/`sandbox.extra_binds`/`--bind`/`--bind-group` entirely, the same way they
ignore plain `--bind` already (see [CLI › `marshal
run`](../cli.md#marshal-run---profile-name---isolation-netnscgroupnone---proxy-url---bind-path---bind-group-name---dry-run----command)).

## Inline bind groups

Unlike profiles, a bind group **can** also be declared inline under `bind_groups:` in the base
file — there's no embedded/named distinction to protect here, same as bundles:

```yaml
# config.yaml
bind_groups:
  internal-tool:
    paths: ["/opt/internal-tool"]
```

A name defined both inline and as a file is a load error, not a silent pick.

## On a profile: named groups plus ad hoc paths

```yaml
sandbox:
  bind_groups: [claude, node]      # shared, defined once, referenced by name
  extra_binds: ["~/.cache/uv"]     # specific to this profile, not worth naming
```

`sandbox.bind_groups` and `sandbox.extra_binds` apply automatically to every `marshal run`
invocation for that profile — no `--bind`/`--bind-group` needed on the command line. The CLI
flags still work, unchanged, for the genuinely one-off case, or to add a group beyond what the
profile already names:

```bash
marshal run --profile coding-agent --bind-group node --bind ~/.cache/uv -- pi
```

## `~/` expansion, and the symlink caveat

Same as everywhere else in this config: `~/` at the start of a path expands against `$HOME`.
Every path is resolved at `marshal run` time, against the invoking user's `$HOME` — not at
`marshal config check` time — so a bind group's paths are not required to exist on the machine
that validates the config, only on the machine that runs `marshal run`.

`bwrap` does not follow symlinks when deciding what to bind. If the tool a bind group is meant
to cover is installed as a symlink (common for version-managed tools: `~/.local/bin/claude` →
`~/.local/share/claude/versions/2.1.220`), the group needs **both** paths — the symlink's
directory and wherever it actually resolves to — or `marshal run` fails with `No such file or
directory` even though the group "looks" right:

```bash
which claude                   # ~/.local/bin/claude
readlink -f "$(which claude)"  # ~/.local/share/claude/versions/2.1.220
```

```yaml
paths:
  - "~/.local/bin"
  - "~/.local/share/claude"
```
