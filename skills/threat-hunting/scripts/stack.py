#!/usr/bin/env python3
"""Stack counting and long-tail analysis over CSV or JSONL data.

Counts how often each value (or combination of values) of one or more columns
occurs, reports the percentage of all rows, optionally the number of distinct
groups (hosts, users, ...) the value appears on, and flags the rare ones.
Rarity is the hunting signal: a process that runs on one host out of 900, a
user agent seen twice, a parent/child pair nobody else has.

Input: CSV (delimiter sniffed; header row required) or JSON Lines / JSON array
(nested keys addressed with dots, e.g. `process.name`). Use `-` for stdin.

Usage:
    python stack.py events.csv --by process
    python stack.py events.csv --by parent,process --group host --rare-below 1%
    python stack.py dns.jsonl --by dns.query --group host --rare-groups 2 --rare-only
    python stack.py events.csv --by user --where host=WS-042 --format csv
    cat events.csv | python stack.py - --by cmdline --lower --top 50 --order asc

Options that change the analysis:
    --by COLS          columns to stack (comma-separated; combinations are counted together)
    --group COL        count distinct values of COL per stacked value (prevalence)
    --rare-below N|N%  flag values with count < N or share < N% (default 1%)
    --rare-groups N    with --group: also flag values present on <= N groups (default 1)
    --where COL=V      keep only rows where COL equals V (repeatable; COL!=V to exclude)
    --lower            case-fold values before counting
    --order asc|desc   sort by count (default desc; asc puts the long tail first)

Exit codes: 0 success, 2 bad input (missing file, unknown column, unreadable data).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 200_000_000
MAX_ROWS = 5_000_000
MAX_FIELD_LEN = 4096
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# --------------------------------------------------------------------------- loading


def _get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def _flatten_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, separators=(",", ":"))[:MAX_FIELD_LEN]
    return str(v)[:MAX_FIELD_LEN]


def load_rows(text: str, columns: list[str]) -> tuple[list[dict[str, str]], str]:
    """Return (rows restricted to `columns`, format) for CSV, JSONL, or JSON array input."""
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        rows: list[dict[str, str]] = []
        if stripped.startswith("["):
            data = json.loads(stripped)
            items = data if isinstance(data, list) else []
            fmt = "json"
        else:
            items = []
            for n, line in enumerate(stripped.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"line {n + 1}: invalid JSON ({exc.msg})") from exc
                if len(items) >= MAX_ROWS:
                    break
            fmt = "jsonl"
        for obj in items[:MAX_ROWS]:
            if isinstance(obj, dict):
                rows.append({c: _flatten_value(_get_path(obj, c)) for c in columns})
        if rows and all(all(r[c] == "" for r in rows) for c in columns):
            raise ValueError(f"none of the columns {columns} exist in the JSON objects")
        return rows, fmt

    sample = text[:65536]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    header = reader.fieldnames or []
    missing = [c for c in columns if c not in header]
    if missing:
        raise ValueError(f"column(s) {missing} not in header {header[:20]}")
    rows = []
    for n, row in enumerate(reader):
        if n >= MAX_ROWS:
            break
        rows.append({c: (row.get(c) or "")[:MAX_FIELD_LEN] for c in columns})
    return rows, "csv"


# --------------------------------------------------------------------------- analysis


def parse_threshold(spec: str, total: int) -> tuple[float, str]:
    """Return (absolute count threshold, human label)."""
    s = spec.strip()
    if s.endswith("%"):
        pct = float(s[:-1])
        if pct < 0 or pct > 100:
            raise ValueError("percentage must be between 0 and 100")
        return total * pct / 100.0, f"< {pct:g}%"
    n = int(s)
    if n < 0:
        raise ValueError("count threshold must be >= 0")
    return float(n), f"< {n}"


def parse_where(specs: list[str]) -> list[tuple[str, bool, str]]:
    out: list[tuple[str, bool, str]] = []
    for s in specs:
        m = re.fullmatch(r"([^=!]{1,200})(!=|=)(.*)", s, re.S)
        if not m:
            raise ValueError(f"--where must look like COL=VALUE or COL!=VALUE, got {s!r}")
        out.append((m.group(1).strip(), m.group(2) == "=", m.group(3)))
    return out


def stack(rows: list[dict[str, str]], by: list[str], group: str | None, lower: bool,
          sample_groups: int) -> tuple[list[dict[str, Any]], int]:
    counts: Counter[tuple[str, ...]] = Counter()
    groups: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for r in rows:
        key = tuple((r[c].lower() if lower else r[c]).strip() for c in by)
        counts[key] += 1
        if group:
            groups[key].add(r[group].strip())
    total = sum(counts.values())
    result: list[dict[str, Any]] = []
    for key, n in counts.items():
        item: dict[str, Any] = {c: (v if v != "" else "(empty)") for c, v in zip(by, key)}
        item["count"] = n
        item["percent"] = round(100.0 * n / total, 3) if total else 0.0
        if group:
            g = groups[key]
            item["groups"] = len(g)
            if sample_groups:
                item["sample_groups"] = ", ".join(sorted(g)[:sample_groups])
        result.append(item)
    return result, total


def flag_rare(result: list[dict[str, Any]], count_threshold: float, group_threshold: int | None) -> int:
    flagged = 0
    for item in result:
        rare = item["count"] < count_threshold
        if group_threshold is not None and "groups" in item and item["groups"] <= group_threshold:
            rare = True
        item["rare"] = rare
        flagged += int(rare)
    return flagged


# --------------------------------------------------------------------------- render


def _clean(s: Any) -> str:
    return _CTRL.sub("?", str(s)).replace("|", "\\|").replace("\n", " ")


def render_md(result: list[dict[str, Any]], by: list[str], group: str | None, total: int, distinct: int,
              flagged: int, label: str, shown: int, sample_groups: int) -> str:
    cols = list(by) + ["count", "percent"]
    if group:
        cols.append(f"groups ({group})")
        if sample_groups:
            cols.append("sample groups")
    cols.append("rare")
    lines = [f"**Rows:** {total}  **Distinct:** {distinct}  **Rare ({label}):** {flagged}  **Shown:** {shown}", "",
             "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for item in result:
        cells = [f"`{_clean(item[c])}`" for c in by]
        cells += [str(item["count"]), f"{item['percent']:.2f}%"]
        if group:
            cells.append(str(item["groups"]))
            if sample_groups:
                cells.append(_clean(item.get("sample_groups", "")))
        cells.append("RARE" if item["rare"] else "")
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def render_csv(result: list[dict[str, Any]], by: list[str], group: str | None, sample_groups: int) -> str:
    fields = list(by) + ["count", "percent"]
    if group:
        fields.append("groups")
        if sample_groups:
            fields.append("sample_groups")
    fields.append("rare")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for item in result:
        row = dict(item)
        row["rare"] = "true" if item["rare"] else "false"
        # neutralise spreadsheet formula injection in exported values
        for c in by:
            if isinstance(row[c], str) and row[c][:1] in "=+-@":
                row[c] = "'" + row[c]
        w.writerow(row)
    return buf.getvalue()


def render_json(result: list[dict[str, Any]], by: list[str], group: str | None, total: int, distinct: int,
                flagged: int, label: str) -> str:
    return json.dumps({"rows": total, "distinct": distinct, "rare": flagged, "rare_threshold": label,
                       "by": by, "group": group, "items": result}, indent=2)


# --------------------------------------------------------------------------- cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="CSV / JSONL / JSON array file, or - for stdin")
    ap.add_argument("--by", required=True, help="column(s) to stack, comma-separated")
    ap.add_argument("--group", help="column whose distinct values are counted per stacked value (e.g. host)")
    ap.add_argument("--rare-below", default="1%", help="count or percentage threshold for the rare flag (default 1%%)")
    ap.add_argument("--rare-groups", type=int, default=None,
                    help="with --group: flag values seen on <= N groups (default 1)")
    ap.add_argument("--where", action="append", default=[], help="COL=VALUE or COL!=VALUE row filter (repeatable)")
    ap.add_argument("--lower", action="store_true", help="case-fold values before counting")
    ap.add_argument("--order", choices=["desc", "asc"], default="desc", help="sort by count (default desc)")
    ap.add_argument("--top", type=int, help="show at most N rows after sorting")
    ap.add_argument("--rare-only", action="store_true", help="show only rows flagged rare")
    ap.add_argument("--sample-groups", type=int, default=3, help="list up to N group values per row (0 to hide)")
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md")
    args = ap.parse_args(argv)

    by = [c.strip() for c in args.by.split(",") if c.strip()]
    if not by:
        print("error: --by needs at least one column", file=sys.stderr)
        return 2
    try:
        where = parse_where(args.where)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    needed = list(dict.fromkeys(by + ([args.group] if args.group else []) + [w[0] for w in where]))

    if args.input == "-":
        text = sys.stdin.read(MAX_INPUT_BYTES)
    else:
        p = Path(args.input)
        if not p.is_file():
            print(f"error: {p} is not a file", file=sys.stderr)
            return 2
        if p.stat().st_size > MAX_INPUT_BYTES:
            print(f"error: {p} exceeds {MAX_INPUT_BYTES} bytes", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        print("error: input is empty", file=sys.stderr)
        return 2

    try:
        rows, fmt = load_rows(text, needed)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for col, equals, val in where:
        rows = [r for r in rows if (r[col] == val) == equals]
    if not rows:
        print("error: no rows left after --where filters (or input had no data rows)", file=sys.stderr)
        return 2

    result, total = stack(rows, by, args.group, args.lower, args.sample_groups)
    try:
        threshold, label = parse_threshold(args.rare_below, total)
    except ValueError as exc:
        print(f"error: --rare-below {exc}", file=sys.stderr)
        return 2
    group_threshold = None
    if args.group:
        group_threshold = 1 if args.rare_groups is None else args.rare_groups
        label += f" or on <= {group_threshold} {args.group}(s)"
    flagged = flag_rare(result, threshold, group_threshold)
    distinct = len(result)

    result.sort(key=lambda i: (i["count"], tuple(i[c] for c in by)), reverse=False)
    if args.order == "desc":
        result.sort(key=lambda i: -i["count"])
    if args.rare_only:
        result = [i for i in result if i["rare"]]
    if args.top is not None:
        result = result[:max(0, args.top)]

    if args.format == "csv":
        out = render_csv(result, by, args.group, args.sample_groups)
    elif args.format == "json":
        out = render_json(result, by, args.group, total, distinct, flagged, label)
    else:
        out = render_md(result, by, args.group, total, distinct, flagged, label, len(result), args.sample_groups)
    sys.stdout.write(out.rstrip("\n") + "\n")
    print(f"note: {fmt} input, {total} rows, {distinct} distinct value(s), {flagged} rare", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
