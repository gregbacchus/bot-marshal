# ADR 0042: A native decision answer may replace the judge's forced tool call

* **Status:** Accepted
* **Date:** 2026-10-02
* **Supersedes:** ADR-0012, only its requirement for a forced tool call and message-tag representation

## Context

The judge returns a bounded allow/deny/pass verdict. TypeSafe/Jev and DecisionsApi expose
System One choices natively rather than through generated text or a tool call. Keeping the
forced-tool envelope would exclude those APIs and their potential latency/cost advantages.
Their confidence signals are useful, but neither speed nor schema validity proves policy
accuracy. The independent DecisionsApi service also discusses an OpenAI preview whose actual
wire contract is not publicly documented; treating that as a live OpenAI endpoint would be
an unsupported assumption.

## Decision

Native providers receive the same reduced request metadata as other judges, separately from
the operator-owned question and policy. Their Choice answer is validated against exactly
allow/deny/pass, finite bounded confidence and normalized probabilities, with the selected
choice consistent with the distribution. There is no free-text parsing.

Below an operator-configured minimum confidence (default 0.9), return Pass. The existing
chain, default action, scope, cache, timeout and failure policies remain authoritative.
A low-confidence response does not override a deterministic refusal or silently allow traffic.

Support the documented TypeSafe and independent DecisionsApi origins with separate provider
names and optional base URL overrides. Do not advertise an official OpenAI adapter without
its published contract. The existing model router gains the System One dialect for native
agent requests. It may map within that dialect but refuses translation between decision and
chat families. Existing destination guarding, credential stripping/injection, audit facts
and bounded buffering apply.

## Alternatives considered

**Wrap decisions in chat tool calls.** Reuses envelopes but loses native decision semantics.
**Treat confidence as an allow probability.** Confidence and selected-option probability are
not interchangeable, and doing this would silently change policy semantics.
**Translate chat into decision questions automatically.** There is no faithful general
mapping from conversations/tool calls to independent bounded questions.
**Invent the OpenAI preview schema.** Faster to claim support, but impossible to verify and
likely to route data to the wrong service.

## Consequences

Native decisions may reduce request-path latency and cost, but require separate service
credentials, compatibility checks and accuracy evaluation. They cannot supply the prose
rationale the existing tool-call providers produce; audit reasons summarize the selected
option and confidence instead. Uncertainty passes and can still be allowed by later policy,
so operators needing refusal must keep a deny fallback. Probabilities are validated, not
assumed calibrated for marshal's policy tasks. Schema evolution may require changing or
removing the integration. No public API keys are required for local contract tests, but those
tests do not establish hosted account access or real model quality.
