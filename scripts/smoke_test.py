#!/usr/bin/env python3
"""Run every bundled script against the sample inputs in its skill's examples/ folder.

Each skill may declare its smoke tests in `examples/smoke.json`:

    [
      {"script": "extract_iocs.py", "args": ["examples/report.txt", "--format", "json"],
       "expect": ["evil-domain.example"]},
      {"script": "defang.py", "args": ["--defang", "examples/report.txt"]}
    ]

`args` are relative to the skill directory. `expect` is an optional list of substrings that
must appear in stdout. A script with no smoke entry is only checked with --help (that is
covered by validate_skills.py), so please add entries when you add scripts.

Usage:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --skill log-forensics

Exit 0 when every declared test passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"


def run_skill(skill_dir: Path) -> tuple[int, int, list[str]]:
    manifest = skill_dir / "examples" / "smoke.json"
    if not manifest.is_file():
        return 0, 0, []
    try:
        tests = json.loads(manifest.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return 0, 1, [f"{skill_dir.name}: smoke.json is not valid JSON: {exc}"]

    passed, failed, errors = 0, 0, []
    for t in tests:
        script = skill_dir / "scripts" / t["script"]
        cmd = [sys.executable, str(script), *t.get("args", [])]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=str(skill_dir),
                                  encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            failed += 1
            errors.append(f"{skill_dir.name}: {t['script']} timed out")
            continue
        problems = []
        if proc.returncode != t.get("exit", 0):
            problems.append(f"exit {proc.returncode} (stderr: {proc.stderr.strip()[:200]})")
        for needle in t.get("expect", []):
            if needle not in proc.stdout:
                problems.append(f"missing expected output {needle!r}")
        if problems:
            failed += 1
            errors.append(f"{skill_dir.name}: {t['script']} {' '.join(t.get('args', []))}: " + "; ".join(problems))
        else:
            passed += 1
    return passed, failed, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skill", help="only this skill directory name")
    args = ap.parse_args()
    dirs = [SKILLS / args.skill] if args.skill else sorted(p for p in SKILLS.iterdir() if p.is_dir())

    total_pass = total_fail = 0
    for d in dirs:
        p, f, errs = run_skill(d)
        total_pass += p
        total_fail += f
        if p or f:
            print(f"[{'OK ' if not f else 'ERR'}] {d.name}: {p} passed, {f} failed")
        for e in errs:
            print(f"      - {e}")
    print(f"\n{total_pass} smoke tests passed, {total_fail} failed")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
