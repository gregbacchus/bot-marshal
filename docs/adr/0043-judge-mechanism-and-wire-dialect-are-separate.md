# ADR 0043: Separate the judge mechanism from its wire dialect and service

* **Status:** Superseded by [ADR-0044](0044-judge-dialect-selects-the-implementation.md)
* **Date:** 2026-10-10
* **Supersedes:** [ADR-0042](0042-native-decision-answers-may-replace-judge-tool-calls.md), only its service-specific provider naming and default decision origins

## Context

Judge provider names previously mixed wire formats and service selection. Two native
provider variants used the same implementation and differed only in their default origin.
This made it unclear whether a provider name selected an API, a model vendor or a gateway.
Local decision servers also need a service address without requiring a bearer credential.

## Decision

Judge provider types describe the mechanism: `llm` uses a forced verdict tool call, and
`decision` uses a validated native Choice answer. A required `dialect` selects the format:
`llm` accepts `openai` or `anthropic`; `decision` accepts `system_one`.
The router uses the same dialect names independently of judge configuration.

Decision providers require `base_url` and have no default service. Their optional
`api_key_env` enables bearer authentication; omission sends no Authorization header.
A configured key variable must exist. LLM providers retain required `api_key_env`, optional
`max_tokens` and dialect-specific default origins, overridable through `base_url`.

Remove the previous provider variants without compatibility aliases. Invalid mechanism and
format combinations are configuration errors naming `provider.dialect`. Native answer
validation, metadata isolation, confidence handling and routing boundaries from ADR-0042
remain in force.

## Alternatives considered

**Keep service-specific aliases.** Preserves old configs but retains the ambiguity and a
second way of expressing the same settings.

**Use only a dialect.** Simpler today but hides the different judge mechanisms and their
options, including native confidence thresholds versus generated-token limits.

**Require a service address for all judges.** Consistent, but removes useful established
chat defaults without resolving additional ambiguity in this change.

## Consequences

This is a breaking configuration change. Operators must replace old provider types with a
mechanism and dialect; native judges must supply their service address explicitly. Existing
native credentials are retained by setting `api_key_env`, while local services can omit it.
Tests and shipped profiles migrate together. The remaining chat service defaults mean
service selection is explicit for decision judges and optional for LLM judges.
