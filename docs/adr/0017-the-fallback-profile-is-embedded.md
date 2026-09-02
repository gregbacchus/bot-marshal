# ADR 0017: The fallback profile is embedded, unnamed, and unreferenceable

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

Traffic that no resolver could attribute has to be governed by something. That fallback profile
is the most security-critical one in the config: it is what an unrecognised process gets, and
therefore what an attacker's traffic gets.

With every profile a named file under `profiles/`, the fallback was one of them, selected by
`identities.unidentified.profile: base`. Which meant the single most important policy in the
deployment was a name in one file pointing at a different file, indistinguishable at a glance
from any other profile — and easy to leave dangling or repoint.

## Decision

The base config carries **one embedded profile**, under the key `profile:`. Not a name pointing
elsewhere — the profile's fields directly, in the file someone opens first:

```yaml
profile:
  default_action: deny
  policy:
    - layer: denylist
      deny: { domains: ["*.onion"] }
```

It is **required**, **unnamed**, and **cannot be referenced from anywhere**. No resolver and no
`marshal run --profile` can target it, because it has no name to target.

Traffic nothing resolves falls through to it automatically. `identities.unidentified.profile:
<name>` can redirect that fallback to a named profile instead, and omitting it — the default —
uses the embedded one.

In the type system this is `Config.profile: Profile` (required, unnamed) alongside
`Config.profiles: BTreeMap<String, Profile>` (named, from `profiles/`), so the distinction is
enforced rather than conventional.

## Alternatives considered

**The fallback is a named profile like any other.** Uniform, and it buries the most important
policy among the others and lets the reference dangle.

**A hard-coded deny-all fallback.** Safe and inflexible: no way to permit the handful of hosts
that unattributed traffic legitimately needs, which pushes people toward disabling the whole
mechanism.

**Both — embedded, but also addressable by a reserved name.** Reintroduces the ability to point
a resolver at the fallback, which is the confusion this removes.

## Consequences

**The most security-critical policy is impossible to miss.** It is in the first file, written
out, not a name to follow.

It cannot be selected by accident. A resolver naming a profile that does not exist is an error
rather than a silent fall-through to the fallback.

The cost is a small asymmetry to learn: one profile is written inline and the rest are files.
`config check` enforces it — the embedded profile must be inline, and the tests cover that.

Sharing policy between the fallback and a named profile means duplicating it, since
[profiles do not inherit](0018-profiles-do-not-inherit.md). A shared `bundles/` entry or a named
transform bundle covers most of what would otherwise be duplicated.
