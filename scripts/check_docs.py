#!/usr/bin/env python3
"""Verify that the documentation describes files that actually exist.

Documentation drifts faster than code, and a README that points at a config file
nobody ever created is worse than no README: someone will edit the wrong thing and
wonder why nothing changed. This checks, across every Markdown file in the repo:

  * relative links resolve to a real file or directory
  * '#anchors' on those links match a heading in the target document
  * inline `backticked/paths.ext` that look like repo paths exist

Paths in a skill's own documentation resolve against that skill's directory first,
then the repository root, which is how a reader would interpret them.

Fenced code blocks are skipped. They hold example commands naming files that are
supposed to be the reader's, not the repository's.

Usage:
    python scripts/check_docs.py
    python scripts/check_docs.py --quiet

Exit 0 when everything resolves, 1 otherwise.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FENCE = re.compile(r"```.*?```", re.S)
LINK = re.compile(r"\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
INLINE_PATH = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|md|json|txt|sh|ps1|yml|yaml|eml|bin|zip|csv|jsonl|log))`")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.M)

# Directory prefixes that mean "this is a repository path", not a user's own file.
REPO_PREFIXES = ("scripts/", "references/", "assets/", "examples/", "docs/",
                 "templates/", "skills/", ".github/", ".claude-plugin/")


def slugify(heading: str) -> str:
    s = heading.lower()
    s = re.sub(r"`|\*|_", "", s)
    s = re.sub(r"[^a-z0-9 -]", "", s)
    return s.replace(" ", "-")


def anchors_of(path: Path) -> set[str]:
    try:
        return {slugify(h) for h in HEADING.findall(path.read_text(encoding="utf-8", errors="replace"))}
    except OSError:
        return set()


def check(path: Path) -> list[str]:
    rel = path.relative_to(ROOT).as_posix()
    raw = path.read_text(encoding="utf-8", errors="replace")
    text = FENCE.sub("", raw)
    problems: list[str] = []

    # A skill's own docs resolve paths against that skill, so a path naming a file that
    # lives in a *different* skill is a real defect: the reader looks in the wrong place.
    # Repository-level docs speak about skills generically ("edit references/environment.md"),
    # so for those a path counts as valid if any skill provides it.
    parts = path.relative_to(ROOT).parts
    in_skill = parts[0] == "skills" and len(parts) > 2
    if in_skill:
        bases = [ROOT / "skills" / parts[1], ROOT]
    else:
        bases = [path.parent, ROOT] + sorted(p for p in (ROOT / "skills").iterdir() if p.is_dir())

    for label, target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        frag = None
        if "#" in target:
            target, frag = target.split("#", 1)
        if not target:
            continue
        dest = (path.parent / target).resolve()
        if not dest.exists():
            problems.append(f"{rel}: broken link [{label}]({target})")
            continue
        if frag and dest.is_file() and dest.suffix == ".md" and frag not in anchors_of(dest):
            problems.append(f"{rel}: bad anchor [{label}]({target}#{frag})")

    for candidate in INLINE_PATH.findall(text):
        if not candidate.startswith(REPO_PREFIXES):
            continue
        if any((base / candidate).exists() for base in bases):
            continue
        problems.append(f"{rel}: inline path does not exist: {candidate}")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true", help="only print problems")
    args = ap.parse_args()

    docs = sorted(p for p in ROOT.rglob("*.md")
                  if ".git" not in p.parts and "node_modules" not in p.parts)
    problems: list[str] = []
    for d in docs:
        found = check(d)
        problems.extend(found)
        if not args.quiet and found:
            for f in found:
                print(f"  - {f}")

    print(f"{len(docs)} markdown files checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
