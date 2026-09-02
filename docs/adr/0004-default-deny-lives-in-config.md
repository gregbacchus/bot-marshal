# ADR 0004: Default-deny lives in config, not in code

* **Status:** Accepted
* **Date:** 2026-09-02

## Context

Default-deny is the product's central guarantee. The question is where it is enforced.

Hard-coding it — "if no layer allowed, deny" — makes it unconditional, which is appealing. But
it makes the guarantee invisible: nothing in a config file says what happens when nothing
matches, and an operator reading a profile cannot tell whether it is default-deny or
default-allow without reading the source.

It also makes the [warn-mode rollout](../operations.md#rolling-it-out) awkward, and warn mode
is what makes adoption possible on an existing agent whose real dependency list nobody knows.

## Decision

A profile's terminal `default_action` decides when every layer returned `PASS`. It defaults to
`deny`. **This field is the single place the guarantee lives.**

Setting it to `allow` requires an adjacent acknowledgement:

```yaml
default_action: allow
i_understand_this_is_allow_by_default: true
```

`marshal config check` errors without it, and `serve` refuses to start.

## Alternatives considered

**Hard-code deny in the chain runner.** Unconditional, invisible, and leaves warn mode with
nowhere natural to live.

**A `--strict` flag.** Puts the guarantee on the command line, where it is set once by whoever
wrote the unit file and never seen again by whoever writes the profiles.

**`allow` with only a warning.** Warnings scroll past. A field someone has to type out is a
field they have to mean.

## Consequences

The guarantee is legible in the file an operator actually reads, and a profile that opts out
says so in terms that are hard to add by accident.

The cost is that default-deny is now config, and config can be wrong. That is mitigated by
`config check` being a CI gate here and the recommended pre-restart step, and by `serve`
applying identical rules at startup — a config that passes `check` will start, and one that
would disable default-deny silently will not.

The acknowledgement key is deliberately verbose. It reads badly, which is the point: it should
be uncomfortable to leave in a file someone else will inherit.
