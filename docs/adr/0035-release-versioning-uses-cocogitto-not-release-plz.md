# ADR 0035: Release versioning uses cocogitto, not release-plz

* **Status:** Accepted
* **Date:** 2026-09-04

## Context

This workspace has twelve crates and releases exactly one artifact: the `marshal-cli` binary.
The other eleven are internal libraries — `publish = false` in `Cargo.toml`, never intended for
crates.io.

release-plz was the first release-automation tool used here, dispatched from the `version`
workflow on every push to `main` to open or update a "release pull request" bumping the version
and changelog ahead of tagging. It worked once, for the very first release, then failed on every
subsequent run with:

```
error: failed to verify manifest at `crates/marshal-audit/Cargo.toml`
  all dependencies must have a version requirement specified when packaging.
  dependency `marshal-core` does not specify a version
```

Tracing this into release-plz's own source (`process_git_only_package` in
`crates/release_plz_core/src/next_ver.rs`) showed the actual mechanism: because `marshal-cli` is
versioned from git tags rather than a registry lookup (it isn't published), release-plz's
`git_only` mode runs `cargo package --allow-dirty --workspace` — unconditionally, packaging
*every* workspace member — to materialize path dependencies as tarballs before it can read back
a version. This call is hardcoded, with no `--exclude` and no way to scope it to one crate.

Two fixes were tried and both dead-ended, confirmed empirically (installed the exact pinned
release-plz version locally and reproduced against real repository history, not just theorized
from source):

* Setting `publish = false` on every crate (already done, for other reasons) only blocks `cargo
  publish`. `cargo package`'s manifest verification runs regardless and still requires a
  `version` on every dependency, path-only ones included.
* Adding `version = "0.1.0"` next to `path = "..."` on the internal `workspace.dependencies`
  satisfies that verification, but the very next step tries to resolve `marshal-core` against
  crates.io to build the packaged tarball — and fails, because it genuinely isn't there.

Neither failure is a configuration mistake; `git_only` mode assumes every crate in the
dependency graph is either published or has no path dependencies. Reversing the decision not to
publish these crates (see `Cargo.toml`'s `publish = false`) would fix it, but that's a separate,
larger decision about what these crates promise as public API, not something to force as a side
effect of release plumbing.

## Decision

Replace release-plz with [cocogitto](https://github.com/cocogitto/cocogitto) for the one thing
this project actually needs from release automation: turn Conventional Commit history into a
version bump, a changelog entry, and a git tag. Cocogitto only reads git history and edits text
(`Cargo.toml`'s version line, `CHANGELOG.md`) — it never runs `cargo package` or resolves a
dependency graph, so it has no dependency on any crate being published anywhere.

Configuration lives in `cog.toml`. `pre_bump_hooks` edits `workspace.package.version` directly
with `sed` (the single field every crate inherits via `version.workspace = true`) and runs
`cargo check --workspace` to refresh `Cargo.lock`. `post_bump_hooks` pushes the bump commit and
tag. The `version` workflow (`.github/workflows/version.yml`) runs this directly on push to
`main` — no bot-authored pull request in between, since there's nothing left for a review step
to gate: cocogitto doesn't need a human merge to trigger a build the way release-plz's release
pull request did.

Removing that pull request also removes the problem the `ci: skip the release build on release
pull requests` hand-edit to `release.yml`'s `plan` job existed to work around (three artifact
builds per release, one gated behind manual approval): there is no bot-authored pull request left
to build redundantly, or to be gated behind approval. That hand-edit is reverted as part of this
change.

## Alternatives considered

* **Publish the eleven internal crates to crates.io.** Makes release-plz's assumptions hold, and
  is common practice for CLI tools with internal-only helper crates. Rejected for now — it's a
  decision about public API surface and versioning commitments for code never meant to be
  depended on externally, not something to adopt as a side effect of unblocking CI. Revisit if
  that calculus changes.
* **Keep release-plz, restrict `git_only` to just `marshal-cli`.** Tested and confirmed
  insufficient: `cargo package --allow-dirty --workspace` packages the whole workspace regardless
  of which single package triggered it.
* **`git-cliff` / hand-rolled version bump script.** Would work similarly to cocogitto (git-log
  based, no packaging), but cocogitto already ships the whole loop — commit linting, changelog
  templates, the bump command — as one maintained tool, so there was no reason to assemble the
  equivalent from smaller pieces.

## Consequences

* One class of failure (crates.io resolution during packaging) cannot recur, structurally —
  cocogitto has no code path that resolves a dependency graph.
* The breaking-change (`!`) release policy documented in `AGENTS.md` changed to match what
  cocogitto's default `commit_types` actually implement: only `feat`/`fix` (breaking or not)
  request a release. A `chore!:`/`docs!:`/etc. breaking commit — always a rare case — no longer
  triggers one; route a genuinely breaking change through `fix:` or `feat:` instead. Cocogitto
  does support per-type overrides (`[commit_types]` in `cog.toml`) if this needs revisiting.
* `CHANGELOG.md` was migrated once by hand to carry cocogitto's `- - -` insertion marker; the
  release-plz-authored `v0.1.0` entry was kept verbatim below it. Future entries are generated by
  `cog bump`.
* The version workflow now pushes directly to `main` and creates tags without any PR-based review
  step. A malformed Conventional Commit that release-plz's PR flow might have surfaced for review
  before tagging now only surfaces after the fact, in the pushed history.
