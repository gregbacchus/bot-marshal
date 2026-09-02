# Bundles

A bundle is a named, reusable allow-list — a set of domains a policy can reference by name
instead of repeating in every profile that needs them.

```yaml
# bundles/github.yaml — the filename is the bundle's name
domains:
  - "github.com"
  - "api.github.com"
  - "*.githubusercontent.com"
```

```yaml
# profiles/coding-agent.yaml
policy:
  - layer: allowlist
    allow: { bundles: [github, npm, pypi, crates-io] }
    on_match: allow
```

This repo ships a starting set under `config/bundles/` — `github.yaml`, `npm.yaml`,
`pypi.yaml`, `crates-io.yaml`, `llm-apis.yaml`.

## Inline bundles

Unlike profiles, a bundle **can** also be declared inline under `bundles:` in the base file —
there's no embedded/named distinction to protect here:

```yaml
# config.yaml
bundles:
  internal:
    domains: ["*.internal.corp"]
```

A name defined both inline and as a file is a load error, not a silent pick.

## Matching

Patterns are matched against the hostname. A leading `*.` matches any number of leading
labels; anything else is an exact match. `*.githubusercontent.com` matches
`raw.githubusercontent.com` but not `githubusercontent.com` itself — list both if you need
both.

An `allowlist` layer can combine bundles with its own domains and CIDRs:

```yaml
- layer: allowlist
  allow:
    bundles: [github]
    domains: ["*.githubusercontent.com"]
  on_match: allow
  on_miss: pass
```
