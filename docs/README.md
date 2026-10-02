# bot-marshal documentation

Start here if you are new; each page below stands on its own once you have.

## Getting started

* **[Getting started](getting-started.md)** — install it, write a minimal config, generate a
  CA, put a request through it. Fifteen minutes, no agent required.
* **[Concepts](concepts.md)** — the model the rest of the documentation assumes: how a
  request travels from capture through identity, the policy chain, and transforms, and where
  default-deny actually lives.

## Find a feature

| I want to… | Start here |
|---|---|
| Permit reads but refuse unwanted writes | [Request rules](configuration/policy-layers.md#rules) |
| Use API keys without giving them to an agent | [Secret injection](configuration/transforms.md#secret-injection) and [provider examples](configuration/secret-injection-examples.md) |
| Capture a CLI login and renew tokens | [OAuth workflows](configuration/oauth2.md) and [bootstrap walkthrough](configuration/oauth2.md#from-bootstrap-to-an-authenticated-request) |
| Choose models and providers centrally | [LLM routing](configuration/llm-routing.md) |
| Restrict tools and their arguments | [MCP tool controls](configuration/policy-layers.md#mcp) |
| Detect credentials in outgoing requests | [DLP scanning](configuration/policy-layers.md#dlp) |
| Give each agent its own access and enforce routing | [Identity](configuration/identity.md) and [Linux containment](configuration/identity.md#netns-enforces-rather-than-identifies) |
| Judge requests with an LLM | [AI judge](configuration/policy-layers.md#judge) |
| Investigate a decision or roll out a policy gradually | [Audit log](observability.md#the-audit-log) and [warn mode](operations.md#rolling-it-out) |
| Set or filter request headers | [Header transforms](configuration/transforms.md#header-transforms) |
| Limit response bodies | [Response size limits](configuration/transforms.md#response-size-limits) |
| Check service health or reload policy | [Management API and reload](operations.md) |
| Understand streaming and buffering costs | [Streaming](concepts.md#bodies-stream-by-default) |

## Reference

* **[CLI](cli.md)** — every subcommand and global flag.
* **[Configuration](configuration/)** — the config file, and how it splits across
  `profiles/`, `bundles/` and `transforms/` directories.
  * [Profiles](configuration/profiles.md) — the unit of policy; embedded vs named.
  * [Policy layers](configuration/policy-layers.md) — `denylist`, `allowlist`, `rules`,
    `dlp`, `mcp`, `judge`.
  * [Bundles](configuration/bundles.md) — named, reusable allow-lists.
  * [Transforms](configuration/transforms.md) — header filtering, secret injection,
    response rewriting.
  * [Bind groups](configuration/bind-groups.md) — shared sandbox filesystem access.
  * [LLM routing](configuration/llm-routing.md) — model aliases and dialect translation.
  * [OAuth2 credentials](configuration/oauth2.md) — enrolment, capture and token lifecycle.
  * [Secret injection examples](configuration/secret-injection-examples.md) — provider cookbook.
  * [Identity](configuration/identity.md) — which agent is connecting, and `marshal run`.

## Running it

* **[Capture](capture.md)** — explicit proxy ingress, DNS resolver limitations and upstream checks.
* **[Observability](observability.md)** — logs, the audit trail, and what to watch.
* **[Operations](operations.md)** — the management API, hot reload, and rolling default-deny
  out with warn mode.
* **[Production](production.md)** — running as a dedicated service user under systemd.

* **[Troubleshooting](troubleshooting.md)** — startup, trust, attribution, policy and OAuth failures.

## Project

* **[Roadmap](roadmap.md)** — what is built, what is deliberately not, and why.
* **[Architecture decisions](adr/)** — why the design is the way it is: the constraints that
  forced each significant choice, and the alternatives rejected.
