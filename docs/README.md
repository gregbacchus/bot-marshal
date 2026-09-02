# bot-marshal documentation

Start here if you are new; each page below stands on its own once you have.

## Getting started

* **[Getting started](getting-started.md)** — build it, write a minimal config, generate a
  CA, put a request through it. Fifteen minutes, no agent required.
* **[Concepts](concepts.md)** — the model the rest of the documentation assumes: how a
  request travels from capture through identity, the policy chain, and transforms, and where
  default-deny actually lives.

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
  * [Identity](configuration/identity.md) — which agent is connecting, and `marshal run`.

## Running it

* **[Capture](capture.md)** — explicit proxy, transparent (nftables), and DNS interception.
* **[Observability](observability.md)** — logs, the audit trail, and what to watch.
* **[Operations](operations.md)** — the management API, hot reload, and rolling default-deny
  out with warn mode.
* **[Production](production.md)** — running as a dedicated service user under systemd.

## Project

* **[Roadmap](roadmap.md)** — what is built, what is deliberately not, and why.
* **[Architecture decisions](adr/)** — why the design is the way it is: the constraints that
  forced each significant choice, and the alternatives rejected.
