#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Checks that every relative link in the documentation resolves.

`api/` is a contract, and a downstream integrator following a link into
nothing pays for it in trust before they pay for it in time. Cross-file links
and in-page anchors both rot silently under an ordinary rename, so this runs in
CI where a rename is what breaks it.

Only relative links are checked. An external URL needs the network and a
different kind of review; those are fact-checked when written and recorded in
`docs/verification.md` when they carry a claim.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Markdown inline links: `[text](target)`. Reference-style links are not used
#: in this repository, so one pattern covers it.
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

#: An explicit anchor a heading cannot supply, e.g. `<a id="ceilings"></a>`.
EXPLICIT_ANCHOR = re.compile(r'<a\s+id="([^"]+)"')


def slugs(body: str) -> set[str]:
    """Every anchor a GitHub-rendered page offers.

    Headings become slugs the way GitHub makes them: lower-cased, everything
    but alphanumerics, spaces, hyphens and underscores dropped, spaces turned
    into hyphens. Explicit `<a id>` anchors count too, and are what a heading
    with punctuation in it should use.
    """
    found = set(EXPLICIT_ANCHOR.findall(body))
    for line in body.splitlines():
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            found.add(re.sub(r"[^a-z0-9 _-]", "", title.lower()).replace(" ", "-"))
    return found


def broken(page: Path) -> list[str]:
    """Every unresolvable link on one page. O(links x page size)."""
    faults = []
    body = page.read_text(encoding="utf-8")
    for target in LINK.findall(body):
        if target.startswith(("http://", "https://", "mailto:", "#!")):
            continue
        path_part, _, anchor = target.partition("#")
        resolved = (page.parent / path_part).resolve() if path_part else page
        if path_part and not resolved.exists():
            faults.append(f"{page.relative_to(ROOT)}: no such file: {target}")
            continue
        if (
            anchor
            and resolved.suffix == ".md"
            and anchor not in slugs(resolved.read_text(encoding="utf-8"))
        ):
            faults.append(f"{page.relative_to(ROOT)}: no such anchor: {target}")
    return faults


def main() -> int:
    pages = sorted(
        [*ROOT.glob("api/*.md"), *ROOT.glob("docs/*.md"), *ROOT.glob("*.md")]
    )
    faults = [fault for page in pages for fault in broken(page)]
    for fault in faults:
        print(fault, file=sys.stderr)
    print(f"checked {len(pages)} pages", file=sys.stderr)
    return 1 if faults else 0


if __name__ == "__main__":
    raise SystemExit(main())
