# ADR 0019: Log detail, sink and format are three independent axes

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

This one took several attempts, and the intermediate designs are instructive.

The proxy emits three kinds of thing: operational messages (startup, warnings, shutdown), a
summary line per request, and a full structured record per request with the evidence trail. It
runs in at least three contexts: a developer's terminal, a systemd unit, and a container whose
stdout a collector reads.

Successive designs tried `--log-sink` then `--trace-sink` plus `--audit-sink`, then
`--audit-sink-file` with `-` meaning stdout, then `--log-channels` as a *set* of enabled
channels. Each added a knob to cover a case the previous one made awkward, and the combinations
stopped being meaningful — "audit to a file but access to journald, in JSON, except when a
TTY" was expressible and nobody wanted it.

The mistake was treating three genuinely independent questions as one configuration surface.

## Decision

Three orthogonal flags, each answering one question.

**`--log-detail`** — *how much*. A **level**, not a set: `log` ⊂ `access` ⊂ `audit`, each a
strict superset of the one before. Default `access`.

**`--log-sink`** — *where*. `auto` (default) tries journald, then syslog, then stdout, each a
**real connection attempt rather than a guess**. Naming one forces it and errors if it is not
reachable.

**`--log-format`** — *how it renders*, stdout only, since journald and syslog format
themselves. `auto` checks whether stdout is a TTY: a human gets short coloured lines, a
collector gets one JSON object per line, with no flag needed.

`--audit-log <path>` is separate and additive: a durable, natively-nested JSON copy independent
of all three.

## Alternatives considered

**Channels as a set** (`--log-channels log,access`). Expressive, and most subsets are
incoherent — audit without access is a stream of detailed records with no summaries. A level
removes the incoherent combinations by construction.

**A sink per channel.** Maximum flexibility, combinatorial surface, and it was the design that
made the whole thing unmanageable.

**Always JSON, let the operator pipe it.** Honest, and it makes the interactive experience bad
enough that people stop watching the logs.

## Consequences

**The default needs no flags in any of the three contexts.** A terminal gets coloured lines, a
systemd unit gets journald with structured fields, a container gets JSON on stdout — because
each default is detected rather than assumed.

Under journald every field lands as a real journal field (`identity` → `F_IDENTITY`), so
`journalctl` is the query tool and no bespoke log management is needed. That was the point of
deferring to the OS rather than building a sink.

`tracing`'s fields are flat, so the audit evidence trail travels as a JSON *string* rather than
a nested value in journald and in the `json` stdout format. Still queryable
(`jq '.trail | fromjson'`), just not natively nested — which is why `--audit-log` exists for
the pristine copy.

Forcing a sink that is unreachable is an error rather than a silent fallback. Landing somewhere
unexpected is worse than failing to start.

Three flags is more than one, and the naming has to carry the distinction. That it took this
many iterations suggests the axes are not obvious until you have hit the combinations.
