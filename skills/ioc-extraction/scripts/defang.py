#!/usr/bin/env python3
"""Defang or refang every network indicator in a block of text.

Use this before pasting report excerpts into tickets or chat so nobody
accidentally clicks a live malicious link, and to reverse the process before
loading indicators into tooling.

Usage:
    python defang.py --defang < notes.txt
    python defang.py --refang ticket_excerpt.txt
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_iocs import PATTERNS, defang, refang  # noqa: E402

NETWORK_TYPES = {"url", "email", "ipv4", "ipv6", "domain"}


def defang_text(text: str) -> str:
    text = refang(text)  # normalise first so mixed input comes out consistent
    for ioc_type, pattern in PATTERNS:
        if ioc_type in NETWORK_TYPES:
            text = pattern.sub(lambda m, t=ioc_type: defang(m.group(0), t), text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--defang", action="store_true")
    g.add_argument("--refang", action="store_true")
    ap.add_argument("input", nargs="?", default="-", help="file path or - for stdin")
    a = ap.parse_args()
    if a.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(a.input).read_text(encoding="utf-8", errors="replace")
    sys.stdout.write(defang_text(text) if a.defang else refang(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
