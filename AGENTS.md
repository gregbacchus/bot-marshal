# AGENTS.md

Guidance for AI agents and humans working on the `bot-marshal` codebase.

## What this is

An egress firewall for AI agents: a MITM proxy that enforces default-deny per-request policy,
injects credentials at the boundary, and audits everything. Rust workspace, eleven crates.
See [docs/concepts.md](docs/concepts.md) for the model, and
[docs/roadmap.md](docs/roadmap.md#architecture) for what each crate does.

## Verification — run this before claiming anything works

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run --bin marshal -- --config config/marshal.yaml config check
```

All four are CI gates (`.github/workflows/ci.yml`), plus `cargo-deny`. **Clippy runs with
`-D warnings`; a warning is a build failure.**

Do not report a change as done until these pass. If a step fails or was skipped, say so
plainly with the output.

### Live verification

Unit tests do not prove the binary behaves. For anything touching the request path, config
schema, logging, or the CLI, run it for real:

```bash
# build a scratch config, then:
./target/debug/marshal --config <path> config check
./target/debug/marshal --config <path> serve --log-detail access --log-sink stdout --log-format pretty &
curl -x http://127.0.0.1:<port> http://example.com/ -o /dev/null -w '%{http_code}\n'
```

Check the log line actually shows what you expect. This has caught real breakage that a green
test suite did not.

## Architectural invariants

These are load-bearing. Breaking one is a design change, not a refactor — raise it rather than
working around it.

* **`marshal-core` depends on no other `marshal-*` crate.** No I/O in it either. This is what
  keeps the trait boundaries honest and the policy chain testable without a network.
* **Bodies stream by default.** A transform that needs the body buffered declares it, with a
  cap. Never silently buffer, never silently truncate. This is what makes SSE, WebSockets and
  large uploads work, and buffering regressions do not surface as errors — only as a stream
  that goes quiet and then delivers everything at once.
* **Default-deny lives in `default_action`, in config, not in code.** The `allow` case
  requires `i_understand_this_is_allow_by_default: true`.
* **Chain ordering is semantic.** Layers short-circuit on the first terminal verdict; that is
  what gives a `denylist` precedence over a later judge approval, with no special-casing.
* **Evidence is append-only.** A layer adds facts and flags; it never mutates or removes
  another layer's. The trail is emitted verbatim in the audit record.
* **Identity is derived from the connection, never asserted by the client.**
* **Resolve once, check every address, connect to the checked address.** Never re-resolve
  between the upstream guard's check and the connect — that is the DNS-rebinding hole.
* **Secrets never reach a log, an audit record, or the judge.** The judge sees method, host,
  path and header *names* only.
* **The three capture modes converge on one request representation.** Do not special-case the
  ingress mode downstream of that convergence.

## Conventions

* `thiserror` in libraries, `anyhow` in the binary.
* Comments explain *why*, not *what*. The existing prose density is the target — match it.
* Config validation errors name the exact config path (`identities.resolvers[0]`), because the
  user is looking at a YAML file, not at the code.
* Errors an agent will see (the 403 body) are part of the product: structured and actionable,
  never a bare status.
* `rustfmt.toml` is committed; do not hand-format around it.

## Keeping the docs current

**Documentation is part of the change, not a follow-up.** A PR that changes behaviour and not
the docs is incomplete. The docs describe user-facing behaviour precisely enough that stale
ones actively mislead.

When you change something, update the matching page:

| change | update |
|---|---|
| config schema — any key, any default | [docs/configuration/](docs/configuration/) — the page for that concept, plus the base-file example in [configuration/README.md](docs/configuration/README.md) |
| a policy layer's options or behaviour | [docs/configuration/policy-layers.md](docs/configuration/policy-layers.md) |
| a transform, secret source, or buffering rule | [docs/configuration/transforms.md](docs/configuration/transforms.md) |
| an identity resolver, or `marshal run` | [docs/configuration/identity.md](docs/configuration/identity.md) |
| a CLI flag, subcommand, or env var | [docs/cli.md](docs/cli.md) |
| log fields, levels, sinks, formats, metrics | [docs/observability.md](docs/observability.md) |
| a management API endpoint or response shape | [docs/operations.md](docs/operations.md) |
| capture modes, nftables, DNS, the upstream guard | [docs/capture.md](docs/capture.md) |
| service layout, systemd, file permissions | [docs/production.md](docs/production.md) |
| the request lifecycle, or an invariant above | [docs/concepts.md](docs/concepts.md) **and** this file |
| a milestone completed, or a decision not to build something | [docs/roadmap.md](docs/roadmap.md) |

Also check, every time:

* **The shipped configs** — `config/marshal.yaml`, `config/profiles/*`, `config/bundles/*`,
  `config/transforms/*`, `examples/docker/marshal.yaml`. A schema change breaks these, and
  `config check` is a CI gate, so a miss fails the build rather than shipping quietly.
* **`README.md`** — it is deliberately short and links into `docs/`. It should change only when
  the elevator pitch, the try-it snippet, or the docs index does.
* **Cross-links** — pages link to each other by relative path and by heading anchor. Renaming a
  heading breaks anchors silently.

### Verify the YAML you document

Every config snippet in the docs should be one that actually loads. Write it into a scratch
config and run `marshal config check` against it before committing the page. Documented YAML
that fails to parse is worse than no example.

## Testing expectations

* Unit-test the policy chain without a network — that is what `marshal-core`'s isolation is
  for.
* Integration tests live in `crates/*/tests/`. `crates/marshal-proxy/tests/` covers the request
  path end to end, including identity attribution and the management API.
* Streaming correctness needs its own tests: assert the *first byte* of an SSE response arrives
  well before the stream ends. A test that only checks the final body passes even when
  everything was buffered.
* For secret handling, grep the entire audit output for the literal secret value and assert
  zero hits.

## Commits

Commit at stable, verified points — all four verification commands green. Note breaking changes
explicitly in the message: config schema keys, audit JSON fields, management API shapes, and
metric names are all public interfaces that something downstream may depend on.

Use a `Co-Authored-By:` trailer when an agent authored the change.
