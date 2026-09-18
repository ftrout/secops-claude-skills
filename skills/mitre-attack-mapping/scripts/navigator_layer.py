#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer from a technique list, or diff two lists.

Standard library only. Reads a CSV (columns: technique_id, score, comment,
color, tactic; only technique_id is required) or a JSON file (an array of
objects, or an object with a "techniques" array) and emits a Navigator layer
JSON document (layer format 4.5, Navigator 5.x). The ATT&CK version, domain,
gradient, and layer metadata are all configurable.

Diff mode takes two files, A and B, and colours every technique by whether it
appears in A only (gap), in both (covered), or in B only (extra). The usual
pairing is A = techniques the threat profile says matter, B = techniques
your detections or a purple-team exercise actually covered.

Usage:
    python navigator_layer.py mapping.csv --name "Incident 2026-0142" > layer.json
    python navigator_layer.py mapping.json --attack-version 17 --domain enterprise-attack
    cat mapping.csv | python navigator_layer.py - --score-max 5
    python navigator_layer.py --diff threat_profile.csv detections.csv --name "Coverage gaps"
    python navigator_layer.py mapping.csv --stats   # prints per-tactic counts to stderr

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path

MAX_INPUT_BYTES = 20 * 1024 * 1024  # a technique list should never be this large

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}(?:[0-9a-fA-F]{2})?$")

# Navigator uses the ATT&CK "shortname" for tactics inside a layer. Accept the
# human name, the shortname, or the TAxxxx ID and normalise to the shortname.
ENTERPRISE_TACTICS = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}
_TACTIC_LOOKUP: dict[str, str] = {}
for _short, (_id, _name) in ENTERPRISE_TACTICS.items():
    _TACTIC_LOOKUP[_short] = _short
    _TACTIC_LOOKUP[_id.lower()] = _short
    _TACTIC_LOOKUP[_name.lower()] = _short
    _TACTIC_LOOKUP[_name.lower().replace(" ", "_")] = _short
    _TACTIC_LOOKUP[_name.lower().replace(" ", "")] = _short

DIFF_COLORS = {"gap": "#e04a4a", "covered": "#4caf50", "extra": "#4a90e2"}


# --------------------------------------------------------------------------- input

def _read_text(spec: str) -> tuple[str, str]:
    """Return (text, label). '-' reads stdin."""
    if spec == "-":
        data = sys.stdin.read()
        if len(data.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
            raise ValueError("stdin input exceeds size limit")
        return data, "stdin"
    p = Path(spec)
    if not p.is_file():
        raise ValueError(f"{p} is not a file")
    if p.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"{p} exceeds size limit ({MAX_INPUT_BYTES} bytes)")
    return p.read_text(encoding="utf-8", errors="replace"), p.name


def _norm_tactic(value: str | None) -> str | None:
    if not value:
        return None
    key = value.strip().lower()
    if key in _TACTIC_LOOKUP:
        return _TACTIC_LOOKUP[key]
    raise ValueError(f"unknown tactic {value!r}; use a name, shortname, or TAxxxx ID")


def _norm_score(value) -> float | None:
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"score {value!r} is not numeric")
    return int(f) if f.is_integer() else f


def _norm_row(raw: dict, line_no: int) -> dict:
    """Validate one record and return a normalised technique entry."""
    # Tolerate common header spellings so analysts do not have to rename columns.
    lower = {str(k).strip().lower().replace(" ", "_"): v for k, v in raw.items() if k is not None}
    tid = (lower.get("technique_id") or lower.get("techniqueid") or lower.get("technique")
           or lower.get("id") or "")
    tid = str(tid).strip().upper()
    if not TECHNIQUE_RE.match(tid):
        raise ValueError(f"line {line_no}: technique_id {tid!r} is not of the form T1234 or T1234.001")
    color = str(lower.get("color") or lower.get("colour") or "").strip()
    if color and not COLOR_RE.match(color):
        raise ValueError(f"line {line_no}: color {color!r} must be #RRGGBB or #RRGGBBAA")
    return {
        "technique_id": tid,
        "score": _norm_score(lower.get("score")),
        "comment": str(lower.get("comment") or lower.get("notes") or lower.get("rationale") or "").strip(),
        "color": color,
        "tactic": _norm_tactic(str(lower.get("tactic") or "")),
    }


def load_techniques(text: str, label: str) -> list[dict]:
    """Parse CSV or JSON technique lists into normalised entries."""
    stripped = text.lstrip("﻿ \t\r\n")
    rows: list[dict] = []
    if stripped.startswith(("[", "{")):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label}: invalid JSON: {exc}")
        if isinstance(data, dict):
            data = data.get("techniques", [])
        if not isinstance(data, list):
            raise ValueError(f"{label}: JSON must be an array or an object with a 'techniques' array")
        for i, item in enumerate(data, 1):
            if isinstance(item, str):
                item = {"technique_id": item}
            if not isinstance(item, dict):
                raise ValueError(f"{label}: item {i} is not an object")
            # Accept Navigator's own field name so an exported layer can be re-imported.
            if "techniqueID" in item and "technique_id" not in item:
                item = dict(item, technique_id=item["techniqueID"])
            rows.append(_norm_row(item, i))
        return rows

    reader = csv.DictReader(io.StringIO(stripped))
    if not reader.fieldnames:
        raise ValueError(f"{label}: empty CSV")
    for i, raw in enumerate(reader, 2):
        if not any((v or "").strip() for v in raw.values() if isinstance(v, str)):
            continue
        rows.append(_norm_row(raw, i))
    if not rows:
        raise ValueError(f"{label}: no technique rows found")
    return rows


def merge(rows: list[dict]) -> list[dict]:
    """Collapse duplicate (technique, tactic) pairs: keep max score, join comments."""
    merged: dict[tuple[str, str | None], dict] = {}
    for r in rows:
        key = (r["technique_id"], r["tactic"])
        if key not in merged:
            merged[key] = dict(r)
            continue
        cur = merged[key]
        if r["score"] is not None and (cur["score"] is None or r["score"] > cur["score"]):
            cur["score"] = r["score"]
        if r["comment"] and r["comment"] not in cur["comment"]:
            cur["comment"] = (cur["comment"] + " | " + r["comment"]).strip(" |")
        if r["color"] and not cur["color"]:
            cur["color"] = r["color"]
    return sorted(merged.values(), key=lambda r: (r["technique_id"], r["tactic"] or ""))


# --------------------------------------------------------------------------- layer

def build_layer(rows: list[dict], *, name: str, description: str, domain: str, attack_version: str,
                navigator_version: str, layer_version: str, gradient_colors: list[str],
                score_min: float | None, score_max: float | None, platforms: list[str],
                legend: list[dict] | None = None, hide_disabled: bool = False,
                expand_subtechniques: str = "none") -> dict:
    scores = [r["score"] for r in rows if r["score"] is not None]
    if score_min is None:
        score_min = min(scores) if scores else 0
    if score_max is None:
        score_max = max(scores) if scores else 100
    if score_max <= score_min:
        score_max = score_min + 1

    techniques = []
    for r in rows:
        entry = {
            "techniqueID": r["technique_id"],
            "color": r["color"],
            "comment": r["comment"],
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }
        if r["tactic"]:
            entry["tactic"] = r["tactic"]
        if r["score"] is not None:
            entry["score"] = r["score"]
        techniques.append(entry)

    return {
        "name": name,
        "versions": {"attack": attack_version, "navigator": navigator_version, "layer": layer_version},
        "domain": domain,
        "description": description,
        "filters": {"platforms": platforms},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": expand_subtechniques,
        },
        "hideDisabled": hide_disabled,
        "techniques": techniques,
        "gradient": {"colors": gradient_colors, "minValue": score_min, "maxValue": score_max},
        "legendItems": legend or [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def diff_rows(a: list[dict], b: list[dict], a_label: str, b_label: str) -> tuple[list[dict], Counter]:
    """Classify techniques as gap (A only), covered (both), extra (B only).

    Comparison is by technique ID. A sub-technique in A counts as covered when B
    lists either the same sub-technique or its parent, because a detection on the
    parent usually fires on the sub-technique too (the reverse is not true).
    """
    a_ids = {r["technique_id"] for r in a}
    b_ids = {r["technique_id"] for r in b}
    b_parents = {t.split(".")[0] for t in b_ids}
    tactic_of: dict[str, str | None] = {}
    comment_of: dict[str, str] = {}
    for r in a + b:
        tactic_of.setdefault(r["technique_id"], r["tactic"])
        if r["comment"]:
            comment_of.setdefault(r["technique_id"], r["comment"])

    out: list[dict] = []
    counts: Counter = Counter()
    for tid in sorted(a_ids | b_ids):
        if tid in a_ids and (tid in b_ids or tid.split(".")[0] in b_parents):
            status = "covered"
        elif tid in a_ids:
            status = "gap"
        else:
            status = "extra"
        counts[status] += 1
        note = {"gap": f"GAP: in {a_label}, not in {b_label}",
                "covered": f"covered: in {a_label} and {b_label}",
                "extra": f"extra: in {b_label} only"}[status]
        if comment_of.get(tid):
            note += f" | {comment_of[tid]}"
        out.append({"technique_id": tid, "score": {"gap": 0, "covered": 2, "extra": 1}[status],
                    "comment": note, "color": DIFF_COLORS[status], "tactic": tactic_of.get(tid)})
    return out, counts


def stats(rows: list[dict]) -> str:
    by_tactic: Counter = Counter(r["tactic"] or "(no tactic given)" for r in rows)
    parents = {r["technique_id"].split(".")[0] for r in rows}
    subs = sum(1 for r in rows if "." in r["technique_id"])
    lines = [f"techniques: {len(rows)} entries, {len(parents)} distinct parent techniques, {subs} sub-techniques"]
    for tactic, n in sorted(by_tactic.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {tactic:<24} {n}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", nargs="?", help="CSV or JSON technique list, or - for stdin")
    ap.add_argument("--diff", nargs=2, metavar=("A", "B"),
                    help="diff mode: A = techniques required, B = techniques covered")
    ap.add_argument("--name", default=None, help="layer name (default: input filename)")
    ap.add_argument("--description", default="", help="layer description")
    ap.add_argument("--domain", default="enterprise-attack",
                    choices=["enterprise-attack", "mobile-attack", "ics-attack"])
    ap.add_argument("--attack-version", default="17", help="ATT&CK content version, e.g. 17 (default: 17)")
    ap.add_argument("--navigator-version", default="5.1.0", help="Navigator app version (default: 5.1.0)")
    ap.add_argument("--layer-version", default="4.5", help="layer file format version (default: 4.5)")
    ap.add_argument("--gradient", default="#ffffff,#ff6666",
                    help="comma-separated colour stops low..high (default: #ffffff,#ff6666)")
    ap.add_argument("--score-min", type=float, default=None, help="gradient minimum (default: min score seen)")
    ap.add_argument("--score-max", type=float, default=None, help="gradient maximum (default: max score seen)")
    ap.add_argument("--platforms", default="", help="comma-separated platform filter, e.g. Windows,Linux")
    ap.add_argument("--expand-subtechniques", default="none", choices=["none", "all", "annotated"],
                    help="which sub-technique rows Navigator expands on load")
    ap.add_argument("--hide-disabled", action="store_true", help="hide techniques with no annotation")
    ap.add_argument("--stats", action="store_true", help="print per-tactic counts to stderr")
    ap.add_argument("--compact", action="store_true", help="emit single-line JSON")
    args = ap.parse_args(argv)

    if bool(args.input) == bool(args.diff):
        ap.print_usage(sys.stderr)
        print("error: give exactly one of <input> or --diff A B", file=sys.stderr)
        return 2

    gradient = [c.strip() for c in args.gradient.split(",") if c.strip()]
    if len(gradient) < 2 or not all(COLOR_RE.match(c) for c in gradient):
        print("error: --gradient needs at least two #RRGGBB colours", file=sys.stderr)
        return 2
    platforms = [p.strip() for p in args.platforms.split(",") if p.strip()]

    try:
        legend = None
        if args.diff:
            a_text, a_label = _read_text(args.diff[0])
            b_text, b_label = _read_text(args.diff[1])
            a_rows = merge(load_techniques(a_text, a_label))
            b_rows = merge(load_techniques(b_text, b_label))
            rows, counts = diff_rows(a_rows, b_rows, a_label, b_label)
            name = args.name or f"Coverage diff: {a_label} vs {b_label}"
            description = args.description or (
                f"{counts['gap']} gaps (in {a_label} only), {counts['covered']} covered, "
                f"{counts['extra']} extra (in {b_label} only). Sub-techniques count as covered "
                f"when the parent technique is covered.")
            legend = [{"label": f"Gap: required by {a_label}, not covered", "color": DIFF_COLORS["gap"]},
                      {"label": "Covered", "color": DIFF_COLORS["covered"]},
                      {"label": f"Extra: only in {b_label}", "color": DIFF_COLORS["extra"]}]
            score_min, score_max = 0.0, 2.0
            if args.stats:
                print(f"gap={counts['gap']} covered={counts['covered']} extra={counts['extra']}", file=sys.stderr)
        else:
            text, label = _read_text(args.input)
            rows = merge(load_techniques(text, label))
            name = args.name or label
            description = args.description
            score_min, score_max = args.score_min, args.score_max
            if args.stats:
                print(stats(rows), file=sys.stderr)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    layer = build_layer(rows, name=name, description=description, domain=args.domain,
                        attack_version=str(args.attack_version), navigator_version=args.navigator_version,
                        layer_version=args.layer_version, gradient_colors=gradient,
                        score_min=score_min, score_max=score_max, platforms=platforms, legend=legend,
                        hide_disabled=args.hide_disabled, expand_subtechniques=args.expand_subtechniques)
    sys.stdout.write(json.dumps(layer, separators=(",", ":")) if args.compact else json.dumps(layer, indent=2))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
