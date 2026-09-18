#!/usr/bin/env python3
"""Turn an indicator list into ready-to-run `in`-list queries per SIEM platform.

Reads the CSV / JSON / plain-list output of the `ioc-extraction` skill (or any
one-indicator-per-line file), normalizes and de-duplicates the values, then
emits query skeletons for each platform with the right field for each
indicator type, chunked so no single query exceeds the platform's comfortable
list size:

  kql        Microsoft Sentinel / Defender XDR advanced hunting  (`field in~ (...)`)
  spl        Splunk, CIM data models via tstats                  (`field IN (...)`)
  elastic    Elastic / Kibana KQL over ECS fields                (`field:(a or b)`)
  sql        Athena SQL over CloudTrail / VPC flow / Route 53     (`field IN (...)`)
  chronicle  Google SecOps (Chronicle) UDM search                (`field = "a" or ...`)

The indicator-type -> table/field mapping lives in a JSON file
(default: references/field-map.json next to this script's skill) so teams can
add their own tables and field names without editing the script.

Input formats (detected automatically):
  * JSON: `{"indicators": [{"indicator": ..., "type": ...}, ...]}` (extract_iocs output),
    a bare list of such objects, or a list of strings
  * CSV with an `indicator` column and optional `type` column
  * plain text, one indicator per line; `# ipv4` style comment lines set the type for
    the lines that follow; other `#` lines are ignored; untyped values are classified
    by shape (IP, hash length, email, URL, domain)

Usage:
    python ioc_to_query.py iocs.csv
    python ioc_to_query.py iocs.json --platform kql,spl --lookback 90d
    cat iocs.txt | python ioc_to_query.py - --platform elastic --types domain,url
    python ioc_to_query.py iocs.csv --format md --chunk 200 --map my-fields.json
    python ioc_to_query.py iocs.csv --platform kql --kql-let      # dynamic() lists

Exit codes: 0 success, 2 bad input or no usable indicators.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 20_000_000
MAX_VALUE_LEN = 2048
PLATFORMS = ("kql", "spl", "elastic", "sql", "chronicle")
DEFAULT_MAP = Path(__file__).resolve().parent.parent / "references" / "field-map.json"

# --------------------------------------------------------------------------- normalize

_REFANG = [
    (re.compile(r"\bhxxps?://", re.I), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\[://\]|\(://\)"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
]
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_IPV6 = re.compile(r"^[0-9A-Fa-f:]{3,39}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_EMAIL = re.compile(r"^[^\s@]{1,128}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$")
_URL = re.compile(r"^(?:https?|ftp|ftps|sftp)://\S{1,2000}$", re.I)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9]{2,59})$", re.I)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}
LOWER_TYPES = {"domain", "email", "md5", "sha1", "sha256", "sha512"}
# types whose shape we can verify; a declared type that fails its shape check is re-classified
SHAPE_CHECKED = {"ipv4", "ipv6", "md5", "sha1", "sha256", "email", "url", "domain"}
KNOWN_TYPES = SHAPE_CHECKED | {"sha512", "cve", "registry", "windows_path", "unix_path", "artifact",
                               "ip", "hostname", "fqdn", "hash", "mac", "btc", "eth"}


def refang(value: str) -> str:
    for pat, repl in _REFANG:
        value = pat.sub(repl, value)
    return value


def classify(value: str) -> str | None:
    if _IPV4.match(value):
        return "ipv4"
    if ":" in value and _IPV6.match(value) and value.count(":") >= 2:
        return "ipv6"
    if _HEX.match(value) and len(value) in HASH_TYPES:
        return HASH_TYPES[len(value)]
    if _URL.match(value):
        return "url"
    if _EMAIL.match(value):
        return "email"
    if _DOMAIN.match(value):
        return "domain"
    return None


def normalize(value: str, ioc_type: str | None) -> tuple[str, str] | None:
    value = refang(value.strip().strip("\"'`"))
    if not value or len(value) > MAX_VALUE_LEN or _CTRL.search(value):
        return None
    t = (ioc_type or "").strip().lower() or None
    if t in {"ip", "ipaddr", "ip-dst", "ip-src"}:
        t = "ipv4" if _IPV4.match(value) else "ipv6"
    if t in {"hostname", "fqdn"}:
        t = "domain"
    if t in {"hash", "sha-256", "sha-1"}:
        t = None
    if t in SHAPE_CHECKED and classify(value) != t:
        t = None  # declared type does not match the value's shape; trust the shape
    if t is None:
        t = classify(value)
    if t is None:
        return None
    if t in LOWER_TYPES:
        value = value.lower()
    return value, t


# --------------------------------------------------------------------------- input


def _parse_json(text: str) -> list[tuple[str, str | None]]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("indicators", data.get("iocs", []))
    out: list[tuple[str, str | None]] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, str):
            out.append((item, None))
        elif isinstance(item, dict):
            val = item.get("indicator") or item.get("value") or item.get("ioc")
            if isinstance(val, str):
                out.append((val, item.get("type") if isinstance(item.get("type"), str) else None))
    return out


def _parse_csv(text: str) -> list[tuple[str, str | None]]:
    reader = csv.DictReader(io.StringIO(text))
    cols = {c.lower(): c for c in (reader.fieldnames or [])}
    ind_col = cols.get("indicator") or cols.get("value") or cols.get("ioc")
    type_col = cols.get("type") or cols.get("ioc_type")
    if not ind_col:
        return []
    out: list[tuple[str, str | None]] = []
    for row in reader:
        val = row.get(ind_col)
        if val:
            out.append((val, row.get(type_col) if type_col else None))
    return out


def _parse_list(text: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    current: str | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            word = s.lstrip("#").strip().lower()
            current = word if word in KNOWN_TYPES else None  # any other comment resets the type
            continue
        # tolerate "value,type" or "value type" pairs
        m = re.match(r"^(\S+)[,\s]+([a-z0-9_-]{2,16})$", s, re.I)
        if m and classify(refang(m.group(1))) is not None:
            out.append((m.group(1), m.group(2)))
        else:
            out.append((s.split(",")[0], current))
    return out


def load_indicators(text: str) -> list[tuple[str, str | None]]:
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            return _parse_json(stripped)
        except json.JSONDecodeError:
            pass
    first = stripped.splitlines()[0].lower() if stripped else ""
    if "indicator" in first and "," in first:
        rows = _parse_csv(stripped)
        if rows:
            return rows
    return _parse_list(text)


# --------------------------------------------------------------------------- quoting


def q_double(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def q_single(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


# --------------------------------------------------------------------------- render


def _chunks(values: list[str], size: int) -> list[list[str]]:
    size = max(1, size)
    return [values[i:i + size] for i in range(0, len(values), size)]


def _lookback(spec: str) -> tuple[int, str]:
    m = re.fullmatch(r"(\d{1,5})([dhm])", spec.strip().lower())
    if not m:
        raise ValueError("lookback must look like 30d, 12h or 90m")
    return int(m.group(1)), m.group(2)


def render_kql(entries: list[dict[str, Any]], ioc_type: str, chunk: list[str], idx: int, total: int,
               lookback: str, use_let: bool) -> str:
    n, unit = _lookback(lookback)
    by_source: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    lines: list[str] = []
    if use_let:
        var = f"ioc_{ioc_type}_{idx}"
        lines.append(f"let {var} = dynamic([{', '.join(q_double(v) for v in chunk)}]);")
    for source, ents in by_source.items():
        tf = ents[0].get("time", "TimeGenerated")
        preds = []
        for e in ents:
            op = e.get("op", "in~")
            if use_let:
                preds.append(f"{e['field']} {op} ({var})")
            else:
                preds.append(f"{e['field']} {op} ({', '.join(q_double(v) for v in chunk)})")
        lines.append(f"// {ioc_type}: {len(chunk)} values, chunk {idx}/{total}")
        lines.append(source)
        lines.append(f"| where {tf} > ago({n}{unit})")
        lines.append("| where " + " or ".join(preds))
        lines.append("| summarize count(), first_seen=min(" + tf + "), last_seen=max(" + tf + ") by " +
                     ", ".join(dict.fromkeys(e["field"] for e in ents)))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_spl(entries: list[dict[str, Any]], ioc_type: str, chunk: list[str], idx: int, total: int,
               lookback: str) -> str:
    n, unit = _lookback(lookback)
    earliest = f"-{n}{unit}"
    by_source: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    lines: list[str] = []
    vals = ", ".join(q_double(v) for v in chunk)
    for source, ents in by_source.items():
        preds = " OR ".join(f"{e['field']} IN ({vals})" for e in ents)
        fields = ", ".join(dict.fromkeys(e["field"] for e in ents))
        lines.append(f"``` {ioc_type}: {len(chunk)} values, chunk {idx}/{total} ```")
        if source.startswith("datamodel="):
            lines.append(f"| tstats count min(_time) as first_seen max(_time) as last_seen "
                         f"from {source} where earliest={earliest} ({preds}) by {fields}")
        else:
            lines.append(f"{source} earliest={earliest} ({preds}) "
                         f"| stats count min(_time) as first_seen max(_time) as last_seen by {fields}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_elastic(entries: list[dict[str, Any]], ioc_type: str, chunk: list[str], idx: int, total: int) -> str:
    by_source: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    lines: list[str] = []
    vals = " or ".join(q_double(v) for v in chunk)
    for source, ents in by_source.items():
        lines.append(f"# {ioc_type}: {len(chunk)} values, chunk {idx}/{total}; index pattern: {source}; "
                     "set the time range in the picker")
        lines.append(" or ".join(f"{e['field']}:({vals})" for e in ents))
        lines.append("")
    return "\n".join(lines).rstrip()


def render_sql(entries: list[dict[str, Any]], ioc_type: str, chunk: list[str], idx: int, total: int,
               lookback: str) -> str:
    n, unit = _lookback(lookback)
    days = max(1, math.ceil(n / 24) if unit == "h" else math.ceil(n / 1440) if unit == "m" else n)
    by_source: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_source.setdefault(e["source"], []).append(e)
    lines: list[str] = []
    vals = ", ".join(q_single(v) for v in chunk)
    for source, ents in by_source.items():
        preds = " OR ".join(f"{e['field']} IN ({vals})" for e in ents)
        time_clause = ents[0].get("time", "").replace("{days}", str(days))
        fields = ", ".join(dict.fromkeys(e["field"] for e in ents))
        lines.append(f"-- {ioc_type}: {len(chunk)} values, chunk {idx}/{total}")
        lines.append(f"SELECT {fields}, COUNT(*) AS hits")
        lines.append(f"FROM {source}")
        where = f"WHERE ({preds})"
        if time_clause:
            where += f"\n  AND {time_clause}"
        lines.append(where)
        lines.append(f"GROUP BY {fields}")
        lines.append("ORDER BY hits DESC;")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_chronicle(entries: list[dict[str, Any]], ioc_type: str, chunk: list[str], idx: int, total: int) -> str:
    lines = [f"// {ioc_type}: {len(chunk)} values, chunk {idx}/{total}; UDM search, set the time range in the UI"]
    preds = []
    for e in entries:
        preds.append("(" + " or ".join(f"{e['field']} = {q_double(v)}" for v in chunk) + ")")
    lines.append(" or ".join(preds))
    return "\n".join(lines)


def build(indicators: dict[str, list[str]], fmap: dict[str, Any], platforms: list[str], chunk_override: int | None,
          lookback: str, kql_let: bool) -> tuple[list[dict[str, Any]], list[str]]:
    blocks: list[dict[str, Any]] = []
    notes: list[str] = []
    default_chunks = fmap.get("chunk_size", {})
    for platform in platforms:
        pmap = fmap.get(platform, {})
        size = chunk_override or int(default_chunks.get(platform, 500))
        for ioc_type, values in indicators.items():
            entries = pmap.get(ioc_type)
            if not entries:
                notes.append(f"{platform}: no field mapping for type `{ioc_type}` ({len(values)} values skipped)")
                continue
            chunks = _chunks(values, size)
            for i, ch in enumerate(chunks, 1):
                if platform == "kql":
                    text = render_kql(entries, ioc_type, ch, i, len(chunks), lookback, kql_let)
                elif platform == "spl":
                    text = render_spl(entries, ioc_type, ch, i, len(chunks), lookback)
                elif platform == "elastic":
                    text = render_elastic(entries, ioc_type, ch, i, len(chunks))
                elif platform == "sql":
                    text = render_sql(entries, ioc_type, ch, i, len(chunks), lookback)
                else:
                    text = render_chronicle(entries, ioc_type, ch, i, len(chunks))
                blocks.append({"platform": platform, "type": ioc_type, "chunk": i, "chunks": len(chunks),
                               "values": len(ch), "query": text})
    return blocks, notes


def render_output(blocks: list[dict[str, Any]], notes: list[str], fmt: str, summary: dict[str, int]) -> str:
    if fmt == "json":
        return json.dumps({"summary": summary, "notes": notes, "queries": blocks}, indent=2)
    out: list[str] = []
    head = "Indicators: " + ", ".join(f"{t}={n}" for t, n in summary.items())
    if fmt == "md":
        out.append(f"**{head}**\n")
        cur = None
        for b in blocks:
            if b["platform"] != cur:
                cur = b["platform"]
                out.append(f"## {cur}\n")
            lang = {"kql": "kusto", "spl": "spl", "elastic": "text", "sql": "sql", "chronicle": "text"}[cur]
            out.append(f"```{lang}\n{b['query']}\n```\n")
        if notes:
            out.append("**Not generated:**\n" + "\n".join(f"- {n}" for n in notes))
        return "\n".join(out)
    out.append(head)
    cur = None
    for b in blocks:
        if b["platform"] != cur:
            cur = b["platform"]
            out.append(f"\n{'=' * 12} {cur} {'=' * 12}")
        out.append(b["query"])
        out.append("")
    if notes:
        out.append("Not generated:")
        out.extend(f"  - {n}" for n in notes)
    return "\n".join(out)


# --------------------------------------------------------------------------- cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="indicator file (CSV, JSON, or plain list) or - for stdin")
    ap.add_argument("--platform", default=",".join(PLATFORMS),
                    help=f"comma-separated subset of {', '.join(PLATFORMS)} (default: all)")
    ap.add_argument("--types", help="comma-separated indicator types to include, e.g. ipv4,domain,sha256")
    ap.add_argument("--chunk", type=int, help="max values per query (overrides the per-platform default)")
    ap.add_argument("--lookback", default="30d", help="time window for platforms that bound in-query (default 30d)")
    ap.add_argument("--map", type=Path, default=DEFAULT_MAP, help="field-map JSON (default: references/field-map.json)")
    ap.add_argument("--format", choices=["text", "md", "json"], default="text")
    ap.add_argument("--kql-let", action="store_true", help="emit KQL `let x = dynamic([...])` lists instead of inline")
    args = ap.parse_args(argv)

    platforms = [p.strip().lower() for p in args.platform.split(",") if p.strip()]
    bad = [p for p in platforms if p not in PLATFORMS]
    if bad:
        print(f"error: unknown platform(s) {bad}; choose from {list(PLATFORMS)}", file=sys.stderr)
        return 2
    try:
        _lookback(args.lookback)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

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

    if not args.map.is_file():
        print(f"error: field map {args.map} not found", file=sys.stderr)
        return 2
    try:
        fmap = json.loads(args.map.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        print(f"error: field map is not valid JSON: {exc}", file=sys.stderr)
        return 2

    wanted = {t.strip().lower() for t in args.types.split(",")} if args.types else None
    indicators: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    skipped = 0
    for raw, t in load_indicators(text):
        norm = normalize(raw, t)
        if norm is None:
            skipped += 1
            continue
        value, ioc_type = norm
        if wanted and ioc_type not in wanted:
            continue
        if (ioc_type, value) in seen:
            continue
        seen.add((ioc_type, value))
        indicators.setdefault(ioc_type, []).append(value)

    if not indicators:
        print("error: no usable indicators found in input", file=sys.stderr)
        return 2
    if skipped:
        print(f"note: {skipped} line(s) skipped (unrecognized type or malformed value)", file=sys.stderr)

    blocks, notes = build(indicators, fmap, platforms, args.chunk, args.lookback, args.kql_let)
    summary = {t: len(v) for t, v in indicators.items()}
    sys.stdout.write(render_output(blocks, notes, args.format, summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
