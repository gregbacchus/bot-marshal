# Profiles

A profile is the unit of policy: an ordered chain of [layers](policy-layers.md), a terminal
`default_action`, and the [transforms](transforms.md) that apply to what it allows.

## The embedded profile

The base config has exactly one embedded profile, `profile:` — the fallback applied to traffic
nobody could attribute. It's required, and it's not a name pointing at something else; it's
the profile's fields directly, so it's impossible to miss in the file someone opens first:

```yaml
# config.yaml
tls:
  ca_cert: "~/.config/bot-marshal/ca.crt"
  ca_key: "~/.config/bot-marshal/ca.key"

profile:
  default_action: deny
  policy:
    - layer: denylist
      deny: { domains: ["*.onion"] }
```

## Named profiles

Every other profile lives one-per-file under `profiles/` — there is no `profiles:` block in
the schema to hold them inline. The filename is the name:

```yaml
# profiles/coding-agent.yaml — just the profile's fields, no wrapping
# `profiles:` / `coding-agent:` keys
default_action: deny
policy:
  - layer: allowlist
    allow: { bundles: [github, npm] }
    on_match: allow
transforms: default-headers
```

A [resolver](identity.md) or `marshal run --profile <name>` can **only target a named
profile** — the embedded `profile:` has no name and can't be referenced from anywhere. A
connection nothing resolves falls through to it automatically, or
`identities.unidentified.profile: <name>` can point that fallback at a named one instead:

```yaml
identities:
  unidentified:
    action: allow_with_profile   # omit `profile:` to use the embedded one (the default);
                                 # set it to use a named profile instead
```

## `default_action`

The terminal applied when every layer in the chain returned `PASS`. **This is where
default-deny actually lives.**

```yaml
default_action: deny
```

Setting it to `allow` disables default-deny for every request that reaches the end of the
chain, so it requires an explicit acknowledgement:

```yaml
default_action: allow
i_understand_this_is_allow_by_default: true
```

`marshal config check` errors without that second line, and `serve` refuses to start.

## Warn mode

Turning default-deny on for an existing agent breaks everything it was quietly relying on, and
that list cannot be known in advance. Warn mode is how it gets discovered — see
[Operations › Rolling it out](../operations.md#rolling-it-out).

```yaml
# profiles/coding-agent.yaml
mode: warn      # run the whole chain, record refusals, forward anyway
```

## Ordering within the chain

Layers are evaluated in the order written, and the first terminal verdict wins. Put hard
denies first — a `denylist` at position 1 beats a later judge approval simply by being there.
`marshal config check` warns when an expensive layer precedes a cheap one, because that
mistake is invisible until the latency bill arrives.

See [Policy layers](policy-layers.md) for each layer's own configuration.
