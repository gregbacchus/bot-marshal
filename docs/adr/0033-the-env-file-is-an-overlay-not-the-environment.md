# ADR 0033: The env file is an overlay, not the environment

* **Status:** Accepted
* **Date:** 2026-09-04

## Context

Boundary injection ([ADR-0011](0011-secrets-are-injected-at-the-boundary.md)) reads most
credentials from environment variables: `source: { type: env, var: SERVICE_API_KEY }`. That
leaves the operator to get the variable into marshal's environment, which is easy under systemd
(`EnvironmentFile=`) and tedious everywhere else — a wrapper script, a shell that exports before
launching, or a systemd unit written for a machine that has no systemd. The obvious convenience
is the one every other tool has: a `.env` file next to the config.

The obvious *implementation* is the one every dotenv library has: read the file and call
`setenv` for each pair. Three things make that wrong here.

* **`marshal run` spawns agents from this process.** A child inherits its parent's environment.
  Putting the file's credentials into marshal's real environment therefore hands every one of
  them to the agent — precisely the credentials the config went to the trouble of injecting at
  the boundary so the agent would never hold them. The feature would quietly undo the product's
  central guarantee, and nothing would report it: the requests still succeed.
* **`std::env::set_var` is unsound once a thread exists**, and the workspace lints `unsafe_code`.
  Any `setenv` design is a comment explaining why this particular call site is safe, plus an
  ordering constraint in `main` that a later refactor can silently break.
* **Precedence has to be decided anyway.** A variable that is already set and a file that also
  sets it is not an edge case; it is what happens the first time someone rotates a token by
  exporting it.

## Decision

`env_file:` names a `KEY=value` file, defaulting to `.env` beside the config. Its contents are
installed as a process-global *overlay* in `marshal_core::env`, and the process environment is
never modified. Every place that reads a variable *named by the config* — the `env` secret
source, a judge's `api_key_env`, `management.api_key_env`, an OAuth2 `password_env` — reads it
through `marshal_core::env::var`, which consults the real environment first and the overlay
second.

The real environment wins. A file that is absent when unnamed is not an error; one that is named
explicitly and missing is.

The parser is a small dialect, not a compatible one: no `${VAR}` interpolation, no inline `#`
comments, no unquoted escapes, and an error naming `file:line` for anything ambiguous. Every
convenience omitted is a way to silently mangle a credential — an inline comment truncates a
password containing a hash, interpolation rewrites a secret containing `$`.

## Alternatives considered

**`setenv` plus scrubbing in `marshal run`.** Set the variables for real, then `env_remove` each
one from the agent's command. It works — the set of names to remove is exactly the set that was
absent before, so removing them restores what the agent would have inherited anyway — and it was
implemented before this ADR. It loses on containment by default: the leak is prevented by
remembering to scrub at *every* future site that spawns a process, rather than by there being
nothing to leak. It also keeps the `unsafe` and the ordering constraint.

**A dotenv crate.** Rejected for the same reason plus one: every one of them calls `setenv`, and
their dialects are tuned for developer convenience over credential fidelity.

**Interpolation and inline comments.** Rejected above. Someone will eventually want
`BASE=https://x` / `URL=${BASE}/v1`; they can write it out twice.

## Consequences

The overlay only reaches variables read through `marshal_core::env::var`. Anything reading
`std::env::var` directly — a dependency consulting `AWS_*` or `HTTPS_PROXY` on its own, or a
future call site written without thinking about it — does not see the file, and the failure is
silent in the same way forgetting `Redactor::learn` is silent
([ADR-0029](0029-the-redaction-set-is-learned-at-runtime.md)). The rule is: a variable *named in
the config* is read through `marshal_core::env`.

`marshal-core` now holds a process-global `OnceLock`, in a crate whose value is that it has no
I/O and no global state. The overlay is installed once from parsed data before any work begins
and is read-only thereafter, which is the narrowest form this could take, but it is still a
global and tests that want to exercise it have to share one.

An operator cannot use `.env` to configure anything but marshal's own credential lookups. It is
not a general environment for the process, and it deliberately cannot be used to influence a
launched agent — which is the point, but it will surprise someone who expects dotenv semantics.
