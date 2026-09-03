# ADR 0024: `netns` isolation binds an explicit allowlist, not the whole host root

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

A security review found that `marshal run --isolation netns` bound the entire host filesystem
into the namespace with `bwrap --dev-bind / /`. The module doc justified this as "the agent
needs its workspace... this is an egress firewall, not a sandbox" — true as far as it went,
but it understated the actual exposure.

Unix-domain sockets cross a network-namespace boundary untouched — that is the mechanism this
project deliberately relies on to reach the marshal proxy itself from inside an otherwise
disconnected namespace (see [ADR-0014](0014-netns-isolation-without-cap-net-admin.md)). Binding
the whole root meant every *other* Unix socket reachable from the launching user was equally
reachable from inside the namespace: Docker's, Podman's, a systemd user service's, anything
else listening under `/run` or `/var/run` or the host's real `/tmp`. An agent that can reach
`docker.sock` can very plausibly get host-level code execution through it — a far larger
capability than the network route `netns` isolation exists to remove.

This undermined the specific claim [ADR-0014](0014-netns-isolation-without-cap-net-admin.md)
makes: that `netns` is the one isolation mode that *enforces* rather than merely identifies.
An agent with no network route out could still reach a control plane capable of creating its
own network route out, on a different host process's behalf.

## Decision

`bwrap --dev-bind / /` is replaced with an explicit bind allowlist, and nothing outside it:

* the workspace (the directory `marshal run` was invoked from), read-write;
* the standard read-only system directories (`/usr`, `/etc`, `/bin`, `/sbin`, `/lib`,
  `/lib64`), via `--ro-bind-try` so a merged-`/usr` system missing one as a real directory is
  not a hard failure;
* the CA certificate, read-only, bound as a **single file** — never its containing directory,
  which on the default config layout also holds the CA private key, and that key must never
  be readable from inside the sandbox;
* the `marshal` binary itself, read-only, as a single file — `marshal sandbox` re-execs this
  same binary inside the namespace, and a locally built binary run from an arbitrary path is
  not otherwise guaranteed to be reachable;
* the marshal Unix socket, read-write, as a single file — the only route out;
* `--bind <path>` on `marshal run`, repeatable — an explicit, visible opt-in for anything else
  a particular agent genuinely needs, rather than reopening the whole filesystem to get it.

`/dev` and `/tmp` are `bwrap`'s own synthetic, empty ones (`--dev`, `--tmpfs`), not the host's
real ones. `/proc` remains `bwrap`'s own mount, unchanged from before.

## Alternatives considered

**Keep `--dev-bind / /`, document the risk.** What the code did before this ADR. Documenting a
known privilege-escalation path is not a mitigation for it.

**Bind `$HOME` in addition to the workspace**, to cover `~/.ssh`, `~/.gitconfig`, package
manager caches, and similar tools commonly expect. Rejected as the default: the review's own
remediation scope was deliberately narrow (workspace, runtime essentials, CA, socket), and
`$HOME` routinely contains credentials (SSH keys, cloud CLI tokens, `.netrc`) with no
relationship to the current workspace. `--bind` covers the specific paths a real deployment
turns out to need, visibly, rather than granting all of `$HOME` by default on the chance some
of it is wanted.

**Detect and bind only sockets actually needed** (e.g., probe for and allow a package
manager's own socket). More precise in principle, and there is no reliable way to enumerate
"what this agent will turn out to need" ahead of running it — `--bind` on demand is simpler
and equally explicit.

## Consequences

**A tool that reads something outside the workspace and the bound system directories now
fails inside the namespace where it worked before.** This is the disruptive edge of the
change: `~/.cache/uv`, `~/.npm`, `~/.cargo`, an SSH key for a private git remote, are all now
invisible unless `--bind`ed explicitly. `--dry-run` prints the exact bind list precisely so
this is diagnosable — a missing path shows up as "not in this list" rather than a mysterious
failure — but it is still a real behavior change for anyone already using `--isolation netns`.

The properties this closes are worth that cost: an agent inside the namespace can no longer
reach `docker.sock`, another user service's control socket, or another process's files under
`/tmp`, regardless of what it does to its network route. `netns` isolation's claim to
*enforce* rather than *identify* is now actually true against this class of escape, not just
against direct network access.

The CA-cert-as-a-single-file and binary-as-a-single-file binds are narrow by construction:
each names exactly one file, so neither can accidentally widen into exposing a sibling file
(the CA private key next to the cert; anything else installed alongside the binary) the way
binding their containing directories would.
