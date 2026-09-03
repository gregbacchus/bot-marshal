#!/usr/bin/env python3
"""Fail if any relative link in the docs points at something that is not there.

The docs cross-reference each other by relative path *and* by heading anchor, and both rot
silently: renaming a heading leaves every `#anchor` pointing at it broken, with nothing to
notice. AGENTS.md calls this out as something to check by hand on every change, which is
exactly the kind of rule that holds until someone is in a hurry.

Only relative links are checked. External URLs are somebody else's uptime.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Everything that participates in the cross-linked doc set.
FILES = sorted(ROOT.glob("docs/**/*.md")) + [ROOT / "AGENTS.md", ROOT / "README.md"]


def slug(heading: str) -> str:
    """GitHub's anchor derivation: lowercase, drop punctuation, spaces to hyphens.

    Underscores and hyphens survive, which matters — `state_dir` and `client_secret` are
    headings here, and stripping the underscore would report every link to them as broken.
    """
    s = re.sub(r"[`*\[\]():.,/+§]", "", heading.strip().lower())
    return re.sub(r"[^a-z0-9_\- ]", "", s).replace(" ", "-")


def main() -> int:
    anchors = {}
    for path in FILES:
        if path.exists():
            text = path.read_text()
            anchors[path] = {slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.*)$", text, re.M)}

    problems = []
    for path, _ in anchors.items():
        for match in re.finditer(r"\[[^\]]*\]\(([^)#\s]*)(#[^)\s]*)?\)", path.read_text()):
            target, anchor = match.group(1), (match.group(2) or "")[1:]
            # A bare `#anchor` link, or an external URL: not ours to check.
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (path.parent / target).resolve()
            rel = path.relative_to(ROOT)
            if not resolved.exists():
                problems.append(f"{rel}: `{target}` does not exist")
            elif anchor and resolved in anchors and anchor not in anchors[resolved]:
                problems.append(f"{rel}: `{target}#{anchor}` — no heading with that anchor")

    if problems:
        print("\n".join(sorted(problems)), file=sys.stderr)
        print(f"\n{len(problems)} broken documentation link(s)", file=sys.stderr)
        return 1
    print(f"all documentation links resolve ({len(anchors)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
