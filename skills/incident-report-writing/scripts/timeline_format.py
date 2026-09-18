#!/usr/bin/env python3
"""Normalize a list of incident events into a sorted UTC ISO 8601 timeline table.

Reads CSV, a JSON array (or an object with an "events" array), or JSON Lines.
Each event needs a timestamp plus any of source, actor, action, evidence. Column
names are configurable with --map. Timestamps in many common shapes (ISO 8601 with
or without offset, epoch seconds/milliseconds, "YYYY-MM-DD HH:MM:SS", US-style
"M/D/YYYY h:mm:ss AM", syslog "Sep 17 14:03:00") are converted to UTC; naive values
are interpreted in --assume-tz (default UTC) and flagged so the reader knows.

The output flags gaps longer than --gap-hours (a gap usually means missing logs
or missing notes, which the report must call out), entries that were out of
order in the input (a sign someone typed the timeline from memory), duplicate
rows, and rows whose timestamp could not be parsed (listed separately, never
silently dropped).

Standard library only. No network access. Writes to stdout.

Usage:
    python timeline_format.py events.csv
    python timeline_format.py events.json --format md --gap-hours 6
    cat events.jsonl | python timeline_format.py - --input-format jsonl --format csv
    python timeline_format.py events.csv --map "timestamp=Time,source=Log Source,action=Description"
    python timeline_format.py events.csv --assume-tz +02:00 --t0 2026-09-15T08:00:00Z

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIELDS = ["timestamp", "source", "actor", "action", "evidence"]
ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "event_time", "ts", "when", "utc"],
    "source": ["source", "log_source", "log", "system", "tool", "data_source"],
    "actor": ["actor", "user", "account", "who", "principal", "host", "subject"],
    "action": ["action", "event", "description", "activity", "what", "summary", "message"],
    "evidence": ["evidence", "reference", "ref", "artifact", "detail", "details", "notes", "citation"],
}
MAX_ROWS = 50_000
MAX_BYTES = 50_000_000
MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?"
    r"\s*(Z|z|UTC|[+-]\d{2}:?\d{2})?$")
_US_RE = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?)?$")
_SYSLOG_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
_EPOCH_RE = re.compile(r"^\d{9,13}(?:\.\d+)?$")


def parse_offset(tok: str) -> timezone:
    tok = tok.strip()
    if tok.upper() in ("Z", "UTC", ""):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", tok)
    if not m:
        raise ValueError(f"bad UTC offset {tok!r}")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def parse_timestamp(raw: str, assume_tz: timezone, date_order: str, assume_year: int) -> tuple[datetime | None, bool]:
    """Return (aware UTC datetime or None, tz_was_assumed)."""
    s = (raw or "").strip()
    if not s or len(s) > 64:
        return None, False

    if _EPOCH_RE.match(s):
        val = float(s)
        if val > 1e11:          # milliseconds
            val /= 1000.0
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc), False
        except (OverflowError, OSError, ValueError):
            return None, False

    m = _ISO_RE.match(s)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh = int(m.group(4) or 0)
        mi = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        frac = (m.group(7) or "").ljust(6, "0")[:6]
        us = int(frac) if frac else 0
        tz_tok = m.group(8)
        try:
            if tz_tok:
                dt = datetime(y, mo, d, hh, mi, ss, us, tzinfo=parse_offset(tz_tok))
                return dt.astimezone(timezone.utc), False
            dt = datetime(y, mo, d, hh, mi, ss, us, tzinfo=assume_tz)
            return dt.astimezone(timezone.utc), True
        except ValueError:
            return None, False

    m = _US_RE.match(s)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        mo, d = (a, b) if date_order == "mdy" else (b, a)
        hh = int(m.group(4) or 0)
        mi = int(m.group(5) or 0)
        ss = int(m.group(6) or 0)
        ampm = (m.group(7) or "").upper()
        if ampm == "PM" and hh < 12:
            hh += 12
        if ampm == "AM" and hh == 12:
            hh = 0
        try:
            return datetime(y, mo, d, hh, mi, ss, tzinfo=assume_tz).astimezone(timezone.utc), True
        except ValueError:
            return None, False

    m = _SYSLOG_RE.match(s)
    if m and m.group(1).lower() in MONTHS:
        try:
            dt = datetime(assume_year, MONTHS[m.group(1).lower()], int(m.group(2)),
                          int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=assume_tz)
            return dt.astimezone(timezone.utc), True
        except ValueError:
            return None, False

    return None, False


def iso_utc(dt: datetime) -> str:
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_delta(td: timedelta) -> str:
    total = int(td.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    d, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{sign}{d}d {h:02d}:{m:02d}:{s:02d}"
    return f"{sign}{h:02d}:{m:02d}:{s:02d}"


# --------------------------------------------------------------------------- input

def read_rows(text: str, input_format: str) -> list[dict]:
    if input_format == "csv":
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(r) for r in reader]
    elif input_format == "jsonl":
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    else:  # json
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("events", data.get("timeline", data.get("rows")))
        if not isinstance(data, list):
            raise ValueError("JSON input must be an array or an object with an 'events' array")
        rows = data
    if len(rows) > MAX_ROWS:
        raise ValueError(f"too many rows ({len(rows)} > {MAX_ROWS})")
    for r in rows:
        if not isinstance(r, dict):
            raise ValueError("every event must be an object / CSV row")
    return rows


def detect_format(path: str, explicit: str | None, text: str) -> str:
    if explicit and explicit != "auto":
        return explicit
    suffix = Path(path).suffix.lower() if path != "-" else ""
    if suffix in (".csv", ".tsv"):
        return "csv"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".json":
        return "json"
    head = text.lstrip()[:1]
    if head in ("[", "{"):
        return "jsonl" if head == "{" and "\n{" in text else "json"
    return "csv"


def resolve_map(columns: list[str], user_map: dict[str, str]) -> dict[str, str | None]:
    lowered = {c.lower().strip(): c for c in columns}
    out: dict[str, str | None] = {}
    for field in FIELDS:
        if field in user_map:
            out[field] = user_map[field]
            continue
        out[field] = None
        for alias in ALIASES[field]:
            if alias in lowered:
                out[field] = lowered[alias]
                break
    return out


def parse_map_arg(arg: str | None) -> dict[str, str]:
    if not arg:
        return {}
    out = {}
    for part in arg.split(","):
        if "=" not in part:
            raise ValueError(f"--map entries look like field=column, got {part!r}")
        k, v = part.split("=", 1)
        k = k.strip().lower()
        if k not in FIELDS:
            raise ValueError(f"--map field {k!r} must be one of {FIELDS}")
        out[k] = v.strip()
    return out


# --------------------------------------------------------------------------- core

def build_timeline(rows: list[dict], colmap: dict[str, str | None], *, assume_tz: timezone,
                   date_order: str, assume_year: int, gap_hours: float, t0: datetime | None) -> dict:
    parsed: list[dict] = []
    unparsed: list[dict] = []
    for idx, r in enumerate(rows, start=1):
        get = lambda f: str(r.get(colmap[f], "") if colmap[f] else "").strip()  # noqa: E731
        raw_ts = get("timestamp")
        dt, assumed = parse_timestamp(raw_ts, assume_tz, date_order, assume_year)
        rec = {"input_row": idx, "raw_timestamp": raw_ts, "source": get("source"),
               "actor": get("actor"), "action": get("action"), "evidence": get("evidence")}
        if dt is None:
            unparsed.append(rec)
            continue
        rec["utc"] = dt
        rec["tz_assumed"] = assumed
        parsed.append(rec)

    # Out-of-order: the row's timestamp is earlier than the previous parsed row in input order.
    prev = None
    for rec in parsed:
        rec["out_of_order"] = prev is not None and rec["utc"] < prev
        prev = rec["utc"]

    parsed.sort(key=lambda r: (r["utc"], r["input_row"]))
    seen: set[tuple] = set()
    gap = timedelta(hours=gap_hours) if gap_hours > 0 else None
    first = parsed[0]["utc"] if parsed else None
    ref = t0 or first
    for i, rec in enumerate(parsed):
        flags: list[str] = []
        delta_prev = rec["utc"] - parsed[i - 1]["utc"] if i else timedelta(0)
        rec["delta_prev"] = delta_prev
        rec["t_plus"] = rec["utc"] - ref if ref else timedelta(0)
        if gap and i and delta_prev > gap:
            flags.append(f"gap {fmt_delta(delta_prev)[1:]}")
        if rec["out_of_order"]:
            flags.append("out-of-order in source")
        if rec["tz_assumed"]:
            flags.append("tz assumed")
        key = (rec["utc"], rec["source"].lower(), rec["action"].lower())
        if key in seen:
            flags.append("duplicate")
        seen.add(key)
        rec["flags"] = flags

    summary = {
        "events": len(parsed),
        "unparsed": len(unparsed),
        "first": iso_utc(parsed[0]["utc"]) if parsed else None,
        "last": iso_utc(parsed[-1]["utc"]) if parsed else None,
        "span": fmt_delta(parsed[-1]["utc"] - parsed[0]["utc"])[1:] if parsed else None,
        "gaps_over_threshold": sum(1 for r in parsed if any(f.startswith("gap") for f in r["flags"])),
        "out_of_order": sum(1 for r in parsed if r["out_of_order"]),
        "tz_assumed": sum(1 for r in parsed if r["tz_assumed"]),
        "duplicates": sum(1 for r in parsed if "duplicate" in r["flags"]),
        "gap_threshold_hours": gap_hours,
        "t0": iso_utc(ref) if ref else None,
    }
    return {"summary": summary, "events": parsed, "unparsed": unparsed}


# --------------------------------------------------------------------------- output

def _md_cell(s: str) -> str:
    return re.sub(r"\s+", " ", s).replace("|", "\\|").strip()


def render_md(result: dict) -> str:
    s = result["summary"]
    lines = ["## Timeline (UTC, ISO 8601)", "",
             f"Events: {s['events']} | Span: {s['first']} to {s['last']} ({s['span']}) | T+ relative to {s['t0']}  ",
             f"Flags: {s['gaps_over_threshold']} gap(s) over {s['gap_threshold_hours']:g} h, "
             f"{s['out_of_order']} out-of-order in source, {s['tz_assumed']} with assumed time zone, "
             f"{s['duplicates']} duplicate(s), {s['unparsed']} unparsed", "",
             "| # | Time (UTC) | T+ | Source | Actor | Action | Evidence | Flags |",
             "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(result["events"], start=1):
        lines.append(f"| {i} | {iso_utc(r['utc'])} | {fmt_delta(r['t_plus'])} | {_md_cell(r['source'])} | "
                     f"{_md_cell(r['actor'])} | {_md_cell(r['action'])} | {_md_cell(r['evidence'])} | "
                     f"{_md_cell(', '.join(r['flags']))} |")
    if result["unparsed"]:
        lines += ["", "### Unparsed timestamps (fix the source and re-run)", "",
                  "| Input row | Raw timestamp | Source | Action |", "|---|---|---|---|"]
        for r in result["unparsed"]:
            lines.append(f"| {r['input_row']} | {_md_cell(r['raw_timestamp'])} | {_md_cell(r['source'])} | "
                         f"{_md_cell(r['action'])} |")
    return "\n".join(lines)


def render_csv(result: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["seq", "time_utc", "t_plus", "source", "actor", "action", "evidence", "flags", "raw_timestamp", "input_row"])
    for i, r in enumerate(result["events"], start=1):
        w.writerow([i, iso_utc(r["utc"]), fmt_delta(r["t_plus"]), r["source"], r["actor"], r["action"],
                    r["evidence"], ";".join(r["flags"]), r["raw_timestamp"], r["input_row"]])
    for r in result["unparsed"]:
        w.writerow(["", "", "", r["source"], r["actor"], r["action"], r["evidence"], "unparsed",
                    r["raw_timestamp"], r["input_row"]])
    return buf.getvalue()


def render_json(result: dict) -> str:
    events = []
    for i, r in enumerate(result["events"], start=1):
        events.append({"seq": i, "time_utc": iso_utc(r["utc"]), "t_plus": fmt_delta(r["t_plus"]),
                       "source": r["source"], "actor": r["actor"], "action": r["action"],
                       "evidence": r["evidence"], "flags": r["flags"],
                       "raw_timestamp": r["raw_timestamp"], "input_row": r["input_row"]})
    return json.dumps({"summary": result["summary"], "events": events, "unparsed": result["unparsed"]}, indent=2)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="CSV/JSON/JSONL file, or - for stdin")
    ap.add_argument("--input-format", choices=["auto", "csv", "json", "jsonl"], default="auto")
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md")
    ap.add_argument("--map", dest="colmap", help="field=column pairs, e.g. timestamp=Time,action=Description")
    ap.add_argument("--gap-hours", type=float, default=4.0, help="flag gaps longer than this (0 disables)")
    ap.add_argument("--assume-tz", default="Z", help="offset for naive timestamps, e.g. +02:00 (default UTC)")
    ap.add_argument("--assume-year", type=int, default=datetime.now(timezone.utc).year,
                    help="year for syslog-style timestamps with no year")
    ap.add_argument("--date-order", choices=["mdy", "dmy"], default="mdy", help="for slash dates like 9/17/2026")
    ap.add_argument("--t0", help="ISO 8601 reference time for the T+ column (default: first event)")
    args = ap.parse_args(argv)

    try:
        assume_tz = parse_offset(args.assume_tz)
        user_map = parse_map_arg(args.colmap)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    t0 = None
    if args.t0:
        t0, _ = parse_timestamp(args.t0, assume_tz, args.date_order, args.assume_year)
        if t0 is None:
            print(f"error: cannot parse --t0 {args.t0!r}", file=sys.stderr)
            return 2

    try:
        if args.input == "-":
            text = sys.stdin.read(MAX_BYTES + 1)
        else:
            p = Path(args.input)
            if not p.is_file():
                print(f"error: {p} is not a file", file=sys.stderr)
                return 2
            if p.stat().st_size > MAX_BYTES:
                print("error: input too large", file=sys.stderr)
                return 2
            text = p.read_text(encoding="utf-8", errors="replace")
        if len(text) > MAX_BYTES:
            print("error: input too large", file=sys.stderr)
            return 2
        if text.startswith("﻿"):
            text = text[1:]
        fmt = detect_format(args.input, args.input_format, text)
        rows = read_rows(text, fmt)
    except (ValueError, json.JSONDecodeError, csv.Error) as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    if not rows:
        print("error: no events found", file=sys.stderr)
        return 2

    columns: list[str] = []
    for r in rows:
        for k in r.keys():
            if k not in columns:
                columns.append(str(k))
    colmap = resolve_map(columns, user_map)
    if not colmap["timestamp"]:
        print(f"error: no timestamp column found in {columns}; use --map timestamp=<column>", file=sys.stderr)
        return 2
    missing = [c for c in colmap.values() if c and c not in columns]
    if missing:
        print(f"error: mapped columns not in input: {missing}; columns are {columns}", file=sys.stderr)
        return 2

    result = build_timeline(rows, colmap, assume_tz=assume_tz, date_order=args.date_order,
                            assume_year=args.assume_year, gap_hours=args.gap_hours, t0=t0)
    if not result["events"]:
        print("error: no event had a parseable timestamp", file=sys.stderr)
        return 2

    out = {"md": render_md, "csv": render_csv, "json": render_json}[args.format](result)
    sys.stdout.write(out)
    if not out.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
