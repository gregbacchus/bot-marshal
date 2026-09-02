# ADR 0016: Config splits by fixed directory convention, not include globs

* **Status:** Accepted
* **Date:** 2026-09-03

## Context

A single config file stops working quickly. Curated allowlists (`github`, `npm`, `pypi`) are
worth sharing across profiles, and profiles themselves are long enough that several in one file
is unreadable.

The original design was an `include:` glob — `include: [bundles/*.yaml]` — merging arbitrary
files into the top-level document.

Two problems emerged in use. **An included file could set anything.** Nothing stopped
`bundles/github.yaml` from also defining `listeners:` or overriding `tls:`, because after
merging there is only one document and no record of which file contributed what. A stray key in
a bundle file silently reconfigured the proxy.

And **load order determined meaning**. Two globs matching the same file, or a merge conflict
between includes, resolved by whichever won — silently.

## Decision

A fixed convention, not an include mechanism. Three directories sit next to the config file:

```
marshal.yaml
profiles/coding-agent.yaml    ← the filename is the profile's name
bundles/github.yaml
transforms/default-headers.yaml
```

**The filename is the name**, and each file is deserialised as exactly one kind of thing — a
profile, a bundle, or a transform bundle. A profile file structurally cannot set `tls:` or
`listeners:`; `config check` rejects a stray field as a parse error rather than a silent no-op.

`profiles_path` / `bundles_path` / `transforms_path` relocate a directory without loosening
anything: a file found there is still deserialised as only that one kind of thing.

Bundles may additionally be declared inline under `bundles:`, since there is no
embedded/named distinction to protect there — see
[ADR-0017](0017-the-fallback-profile-is-embedded.md). A name defined both inline and as a file
is a load error, not a silent pick.

## Alternatives considered

**`include:` globs.** What this replaced. Flexible, and it makes every included file able to
set every key.

**Include with a schema restriction per glob.** Recovers the safety and keeps the ordering
ambiguity and the ceremony.

**One big file.** No ambiguity at all, and unusable past two or three profiles.

## Consequences

**A whole class of config mistake is now unrepresentable.** A bundle cannot reconfigure the
proxy because the type it deserialises into has nowhere to put that.

Names are unambiguous: the file *is* the name, so there is no place for two definitions of one
profile to disagree.

The cost is lost flexibility. There is no way to split one profile across files, no
conditional inclusion, and no sharing of a fragment smaller than a whole bundle or transform
set. This has not yet been a real constraint, and reversing it would mean reintroducing the
problems above.

Directory layout is now part of the interface. Moving a file changes its name and thus what
references it, which is more surprising than a broken `include:` path would be — and it fails
at `config check`, not at runtime.
