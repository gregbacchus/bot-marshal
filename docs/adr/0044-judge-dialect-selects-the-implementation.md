# ADR 0044: Select the judge implementation directly from its dialect

* **Status:** Accepted
* **Date:** 2026-10-10
* **Supersedes:** [ADR-0043](0043-judge-mechanism-and-wire-dialect-are-separate.md)

## Context

Each supported dialect determines one judge mechanism: OpenAI and Anthropic use forced
verdict tool calls, and System One uses native choices. A separate mechanism type carries
no additional information and creates invalid type/dialect combinations. The router already
selects a wire format through `dialect` alone.

## Decision

Judge providers are tagged by `dialect`: `openai`, `anthropic`, or `system_one`. Remove the
redundant `type` field, without aliases. Each variant owns its supported options, and unknown
fields are rejected rather than ignored. Chat dialects retain required `api_key_env`, optional
`max_tokens`, and optional `base_url` with their established service defaults. System One
requires `base_url`, accepts optional `api_key_env`, and defaults `min_confidence` to 0.9.

Judge and router dialect names are consistent, while their configuration remains independent.
Native verdict validation, metadata isolation and routing boundaries remain unchanged.

## Alternatives considered

**Keep mechanism and dialect.** Could distinguish hypothetical mechanisms sharing one format,
but duplicates today's information and requires extra validation.

**Flatten all options into one struct.** Shares fields but permits irrelevant options unless
validation reimplements the variant-specific schema.

## Consequences

This is a breaking config change. Remove `type` from mechanism-plus-dialect configs. Older
chat configs rename `type` to `dialect`; older native configs choose `system_one` and supply
an explicit origin. Future mechanisms using the same wire format would require a new design
decision rather than relying on a speculative mechanism selector now.
