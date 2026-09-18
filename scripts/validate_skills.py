#!/usr/bin/env python3
"""Validate every skill under skills/ against the repository standard.

Checks:
  * SKILL.md exists and has YAML frontmatter with `name` and `description`
  * `name` equals the directory name and is lowercase-hyphenated
  * description is non-empty and under 1024 characters
  * references/environment.md exists (customization contract)
  * relative paths mentioned in SKILL.md (scripts/..., references/..., assets/...) exist
  * every scripts/*.py compiles and exits 0 on --help
  * no file contains obvious secrets (AWS keys, private key blocks, bearer tokens)

Usage:
    python scripts/validate_skills.py            # validate all
    python scripts/validate_skills.py --skill ioc-extraction
    python scripts/validate_skills.py --no-run   # skip executing --help

Exit code 0 when everything passes, 1 when any check fails.
"""
from __future__ import annotations

import argparse
import py_compile
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{30,}=*", re.I)),
    ("slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("github token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}")),
]

PATH_RE = re.compile(r"(?<![\w/])((?:scripts|references|assets|examples)/[\w./-]+)")


def parse_frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    block = text[3:end].strip("\n")
    data: dict[str, str] = {}
    key = None
    for line in block.splitlines():
        if re.match(r"^[A-Za-z_-]+:", line):
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if val in (">-", ">", "|", "|-"):
                data[key] = ""
            else:
                data[key] = val.strip("\"'")
        elif key and line.startswith((" ", "\t")):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data


def check_skill(skill_dir: Path, run_scripts: bool) -> list[str]:
    errors: list[str] = []
    name = skill_dir.name
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return [f"{name}: missing SKILL.md"]

    text = skill_md.read_text(encoding="utf-8", errors="replace")
    fm = parse_frontmatter(text)
    if fm is None:
        errors.append(f"{name}: SKILL.md has no YAML frontmatter")
    else:
        if fm.get("name") != name:
            errors.append(f"{name}: frontmatter name {fm.get('name')!r} != directory name")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            errors.append(f"{name}: directory name must be lowercase-hyphenated")
        desc = fm.get("description", "")
        if not desc:
            errors.append(f"{name}: description missing or empty")
        elif len(desc) > 1024:
            errors.append(f"{name}: description is {len(desc)} chars (max 1024)")

    body_lines = text.count("\n")
    if body_lines > 500:
        errors.append(f"{name}: SKILL.md is {body_lines} lines (ceiling 500); move material to references/")

    if not (skill_dir / "references" / "environment.md").is_file():
        errors.append(f"{name}: references/environment.md is required for customization")

    for rel in sorted(set(PATH_RE.findall(text))):
        rel = rel.rstrip(".")
        target = skill_dir / rel
        if not target.exists() and not any(target.parent.glob(target.name + "*")):
            errors.append(f"{name}: SKILL.md references {rel} which does not exist")

    scripts_dir = skill_dir / "scripts"
    if scripts_dir.is_dir():
        for script in sorted(scripts_dir.glob("*.py")):
            try:
                py_compile.compile(str(script), doraise=True)
            except py_compile.PyCompileError as exc:
                errors.append(f"{name}: {script.name} does not compile: {exc.msg}")
                continue
            if run_scripts:
                try:
                    proc = subprocess.run([sys.executable, str(script), "--help"], capture_output=True,
                                          text=True, timeout=30, cwd=str(skill_dir))
                    if proc.returncode != 0:
                        errors.append(f"{name}: {script.name} --help exited {proc.returncode}: "
                                      f"{proc.stderr.strip()[:200]}")
                except subprocess.TimeoutExpired:
                    errors.append(f"{name}: {script.name} --help timed out")

    for path in skill_dir.rglob("*"):
        if path.is_file() and path.suffix in {".md", ".py", ".txt", ".json", ".yml", ".yaml", ".csv", ".sh", ".ps1"}:
            content = path.read_text(encoding="utf-8", errors="replace")
            for label, pat in SECRET_PATTERNS:
                if pat.search(content):
                    errors.append(f"{name}: possible {label} in {path.relative_to(skill_dir)}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skill", help="validate only this skill directory name")
    ap.add_argument("--no-run", action="store_true", help="do not execute scripts with --help")
    args = ap.parse_args()

    dirs = [SKILLS / args.skill] if args.skill else sorted(p for p in SKILLS.iterdir() if p.is_dir())
    all_errors: list[str] = []
    for d in dirs:
        errs = check_skill(d, run_scripts=not args.no_run)
        status = "OK " if not errs else "ERR"
        print(f"[{status}] {d.name}")
        for e in errs:
            print(f"      - {e}")
        all_errors.extend(errs)

    print(f"\n{len(dirs)} skills checked, {len(all_errors)} problems")

    # Compiling only proves the scripts parse under the interpreter running right now.
    # The support floor is 3.10, and some syntax that 3.12+ accepts (notably reusing a quote
    # character inside an f-string expression, PEP 701) is a SyntaxError on 3.10 and 3.11.
    # CI tests the floor; say so here, because a green local run on a new interpreter is not
    # the same as a green CI run.
    if not args.no_run and sys.version_info[:2] >= (3, 12):
        print(f"note: ran on Python {sys.version_info.major}.{sys.version_info.minor}; "
              f"the support floor is 3.10 and CI tests it.\n"
              f"      check the floor locally with: "
              f"uv run --no-project --python 3.10 python scripts/validate_skills.py")

    return 1 if all_errors else 0


if __name__ == "__main__":
    sys.exit(main())
