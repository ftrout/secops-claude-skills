#!/usr/bin/env python3
"""Merge log exports from different sources into one UTC-normalized super-timeline.

Standard library only. Accepts CSV/TSV, JSON arrays (or objects that wrap a list under
Records/value/events/hits/data/results), JSON Lines, and plain text logs (syslog, Apache/
nginx, auditd, ISO-prefixed lines). Timestamps in ISO 8601 (any precision, with or without
zone), epoch seconds/milliseconds/microseconds/nanoseconds, Windows FILETIME, US
"M/D/YYYY h:mm:ss AM/PM", syslog "Mon DD HH:MM:SS", Apache "DD/Mon/YYYY:HH:MM:SS +0000",
RFC 2822, "YYYY/MM/DD HH:MM:SS", "DD.MM.YYYY HH:MM:SS", and compact YYYYMMDDHHMMSS forms are
normalized to UTC. Naive timestamps get --assume-tz (default UTC) and are counted so you know
how many rows relied on that assumption.

Each input takes a --map in the same order as the inputs:

    source_label=timestamp_field[,actor_field,action_field,detail_field[,host_field]]

Field names may use dots for nested JSON (EventData.CommandLine). A detail field may join
several with '+' (Message+CommandLine). Omit the --map (or leave fields blank) to let the
script guess from common column names.

Usage:
    python timeline_builder.py win.csv linux.jsonl --map "winsec=TimeCreated,SubjectUserName,EventID,Message,Computer" --map "auth=@timestamp,user,program,message,host"
    python timeline_builder.py win.csv --assume-tz=-04:00 --format md     # naive local times were US Eastern (EDT)
    python timeline_builder.py a.csv b.jsonl c.log --from 2026-09-15T18:00:00Z --to 2026-09-15T19:00:00Z --grep "powershell|schtasks"
    python timeline_builder.py access.log --map "proxy=" --flag-gaps 60 --format csv > timeline.csv
    cat events.jsonl | python timeline_builder.py - --map "edr=timestamp,user,event,cmdline,hostname"

Exit code 0 on success, 2 on bad input or when no events could be parsed.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

MAX_ROWS_PER_INPUT = 500_000
MAX_LINE = 65_536
MAX_INPUT_BYTES = 512 * 1024 * 1024

TS_CANDIDATES = ["@timestamp", "timestamp", "TimeCreated", "TimeGenerated", "EventTime", "UtcTime", "SystemTime", "time", "_time",
                 "datetime", "date", "ts", "eventTime", "Timestamp", "created", "StartTime", "time_generated", "LogTime", "ReceivedTime",
                 "event.created", "TimeCreated.SystemTime", "Time", "CreationTime", "activityDateTime", "createdDateTime"]
ACTOR_CANDIDATES = ["user", "username", "UserName", "SubjectUserName", "TargetUserName", "actor", "account", "AccountName",
                    "userIdentity.arn", "src_user", "principal", "UserId", "InitiatedBy", "user.name", "User", "AccountDomain",
                    "userPrincipalName", "Identity", "InitiatingProcessAccountName", "acct", "auid", "UserID"]
ACTION_CANDIDATES = ["action", "EventID", "EventId", "event_id", "eventName", "EventName", "event", "EventType", "activity",
                     "operation", "Operation", "ActivityDisplayName", "category", "type", "event.action", "ActionType", "program",
                     "Channel", "syscall", "method", "cs-method", "status", "Category"]
DETAIL_CANDIDATES = ["message", "Message", "details", "detail", "CommandLine", "description", "Description", "msg", "raw", "_raw",
                     "RenderedDescription", "ProcessCommandLine", "InitiatingProcessCommandLine", "cs-uri-stem", "request", "url",
                     "TargetFilename", "QueryName", "DestinationIp", "log", "text"]
HOST_CANDIDATES = ["Computer", "host", "hostname", "Hostname", "ComputerName", "DeviceName", "agent.hostname", "host.name", "dvc",
                   "src_host", "s-computername", "node", "MachineName", "Device", "sourceComputer"]

MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

RE_ISO = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?)?\s*(Z|z|[+-]\d{2}:?\d{2}|UTC|GMT)?\s*$")
RE_SLASH_YMD = re.compile(r"^\s*(\d{4})/(\d{2})/(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?\s*$")
RE_US = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*([AaPp][Mm])?\s*(Z|[+-]\d{2}:?\d{2})?\s*$")
RE_DOTTED_DMY = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4})[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(Z|[+-]\d{2}:?\d{2})?\s*$")
RE_SYSLOG = re.compile(r"^\s*([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?\s*$")
RE_APACHE = re.compile(r"^\s*\[?(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]?\s*$")
RE_COMPACT = re.compile(r"^\s*(\d{4})(\d{2})(\d{2})T?(\d{2})(\d{2})(\d{2})(?:[.,]?(\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?\s*$")
RE_EPOCH = re.compile(r"^\s*(\d{9,19})(?:\.(\d{1,9}))?\s*$")
RE_AUDIT = re.compile(r"audit\((\d{10})\.(\d{3}):\d+\)")

# text-line prefixes, tried in order
RE_LINE_ISO = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?\s*(?:Z|[+-]\d{2}:?\d{2})?)\s*[:\-|]?\s*(.*)$")
RE_LINE_SYSLOG = re.compile(r"^\s*(?:<\d{1,3}>)?([A-Za-z]{3}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?)\s+(?:(\S+)\s+)?(?:([A-Za-z0-9_./-]+)(?:\[(\d+)\])?:\s*)?(.*)$")
RE_LINE_APACHE = re.compile(r"^\s*(\S+)\s+\S+\s+(\S+)\s+\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]\s+\"([^\"]{0,4096})\"\s+(\d{3})\s+(\S+)(?:\s+\"([^\"]{0,2048})\"\s+\"([^\"]{0,2048})\")?")
RE_LINE_IIS = re.compile(r"^\s*(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)$")
RE_LINE_EPOCH = re.compile(r"^\s*(\d{10}(?:\.\d{1,9})?)\s+(.*)$")


# --------------------------------------------------------------------------- timestamps


def _frac_to_us(frac: str | None) -> int:
    if not frac:
        return 0
    return int((frac + "000000")[:6])


def _tz(tzs: str | None, assume: timezone) -> tuple[timezone, bool]:
    """Return (tzinfo, was_assumed)."""
    if not tzs:
        return assume, True
    t = tzs.strip()
    if t.upper() in ("Z", "UTC", "GMT"):
        return timezone.utc, False
    sign = 1 if t[0] == "+" else -1
    body = t[1:].replace(":", "")
    hours, minutes = int(body[:2]), int(body[2:4] or 0)
    return timezone(sign * timedelta(hours=hours, minutes=minutes)), False


def parse_offset(spec: str) -> timezone:
    s = spec.strip()
    if s.upper() in ("Z", "UTC", "GMT", ""):
        return timezone.utc
    if s.lower() == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})?", s)
    if not m:
        raise ValueError(f"bad timezone offset {spec!r}; use +HH:MM, -HH:MM, Z, or local")
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0)))


def parse_ts(value, assume: timezone, default_year: int) -> tuple[datetime | None, bool]:
    """Parse many timestamp shapes. Returns (utc datetime or None, tz_was_assumed)."""
    if value is None:
        return None, False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _epoch(float(value)), False
    s = str(value).strip().strip("\"'")
    if not s or s.lower() in ("null", "none", "nan", "-"):
        return None, False
    if len(s) > 64:
        s = s[:64]

    if re.fullmatch(r"(?:19|20)\d{6}(?:T?\d{6}(?:[.,]?\d{1,9})?)?\s*(?:Z|[+-]\d{2}:?\d{2})?", s):
        m = RE_COMPACT.match(s) or re.match(r"^(\d{4})(\d{2})(\d{2})()()()()()$", s)
        if m:
            y, mo, d, hh, mi, ss, frac, tzs = m.groups()
            tz, assumed = _tz(tzs, assume)
            try:
                return datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0), _frac_to_us(frac), tzinfo=tz).astimezone(timezone.utc), assumed
            except ValueError:
                pass  # not a valid calendar date; fall through to the epoch interpretation

    m = RE_EPOCH.match(s)
    if m:
        digits = m.group(1)
        if len(digits) >= 17:  # Windows FILETIME, 100ns since 1601
            try:
                return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(digits) // 10)), False
            except OverflowError:
                return None, False
        return _epoch(float(digits + ("." + m.group(2) if m.group(2) else ""))), False

    m = RE_ISO.match(s)
    if m:
        y, mo, d, hh, mi, ss, frac, tzs = m.groups()
        tz, assumed = _tz(tzs, assume)
        try:
            dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0), _frac_to_us(frac), tzinfo=tz)
        except ValueError:
            return None, False
        return dt.astimezone(timezone.utc), assumed

    for rx in (RE_SLASH_YMD,):
        m = rx.match(s)
        if m:
            y, mo, d, hh, mi, ss, frac, tzs = m.groups()
            tz, assumed = _tz(tzs, assume)
            try:
                return datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss), _frac_to_us(frac), tzinfo=tz).astimezone(timezone.utc), assumed
            except ValueError:
                return None, False

    m = RE_US.match(s)
    if m:
        mo, d, y, hh, mi, ss, frac, ampm, tzs = m.groups()
        hour = int(hh)
        if ampm:
            hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
        tz, assumed = _tz(tzs, assume)
        try:
            return datetime(int(y), int(mo), int(d), hour, int(mi), int(ss or 0), _frac_to_us(frac), tzinfo=tz).astimezone(timezone.utc), assumed
        except ValueError:
            return None, False

    m = RE_DOTTED_DMY.match(s)
    if m:
        d, mo, y, hh, mi, ss, frac, tzs = m.groups()
        tz, assumed = _tz(tzs, assume)
        try:
            return datetime(int(y), int(mo), int(d), int(hh), int(mi), int(ss or 0), _frac_to_us(frac), tzinfo=tz).astimezone(timezone.utc), assumed
        except ValueError:
            return None, False

    m = RE_SYSLOG.match(s)
    if m:
        mon, d, y, hh, mi, ss, frac, tzs = m.groups()
        month = MONTHS.get(mon.lower())
        if not month:
            return None, False
        tz, assumed = _tz(tzs, assume)
        try:
            return datetime(int(y or default_year), month, int(d), int(hh), int(mi), int(ss), _frac_to_us(frac), tzinfo=tz).astimezone(timezone.utc), assumed
        except ValueError:
            return None, False

    m = RE_APACHE.match(s)
    if m:
        d, mon, y, hh, mi, ss, tzs = m.groups()
        month = MONTHS.get(mon.lower())
        if not month:
            return None, False
        tz, assumed = _tz(tzs, assume)
        try:
            return datetime(int(y), month, int(d), int(hh), int(mi), int(ss), tzinfo=tz).astimezone(timezone.utc), assumed
        except ValueError:
            return None, False

    m = RE_AUDIT.search(s)
    if m:
        return _epoch(float(f"{m.group(1)}.{m.group(2)}")), False

    if "," in s and re.match(r"^[A-Za-z]{3},", s):
        try:
            dt = parsedate_to_datetime(s)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=assume).astimezone(timezone.utc), True
            return dt.astimezone(timezone.utc), False
        except (TypeError, ValueError, IndexError):
            return None, False
    return None, False


def _epoch(v: float) -> datetime | None:
    try:
        if v > 1e17:      # nanoseconds
            v /= 1e9
        elif v > 1e14:    # microseconds
            v /= 1e6
        elif v > 1e11:    # milliseconds
            v /= 1e3
        return datetime.fromtimestamp(v, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------- records


def get_field(rec: dict, path: str):
    if not path:
        return None
    if path in rec:
        return rec[path]
    cur = rec
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def lower_keys(rec: dict) -> dict:
    return {str(k).lower(): k for k in rec.keys()}


def guess_field(rec: dict, candidates: list[str]) -> str | None:
    lk = lower_keys(rec)
    for c in candidates:
        if c in rec:
            return c
        if c.lower() in lk:
            return lk[c.lower()]
        if "." in c and get_field(rec, c) is not None:
            return c
    return None


def flatten_value(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))[:4000]
    return str(v)


class Mapping:
    def __init__(self, spec: str | None, fallback_label: str):
        self.label = fallback_label
        self.ts = self.actor = self.action = self.detail = self.host = ""
        if spec:
            label, _, fields = spec.partition("=")
            self.label = label.strip() or fallback_label
            parts = [p.strip() for p in fields.split(",")] if fields else []
            parts += [""] * (5 - len(parts))
            self.ts, self.actor, self.action, self.detail, self.host = parts[:5]

    def resolve(self, sample: dict) -> None:
        """Fill blanks by guessing from the first record."""
        self.ts = self.ts or guess_field(sample, TS_CANDIDATES) or ""
        self.actor = self.actor or guess_field(sample, ACTOR_CANDIDATES) or ""
        self.action = self.action or guess_field(sample, ACTION_CANDIDATES) or ""
        self.detail = self.detail or guess_field(sample, DETAIL_CANDIDATES) or ""
        self.host = self.host or guess_field(sample, HOST_CANDIDATES) or ""


# --------------------------------------------------------------------------- readers


def sniff_kind(name: str, head: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    stripped = head.lstrip("﻿ \t\r\n")
    if ext in ("jsonl", "ndjson") or (stripped.startswith("{") and "\n{" in stripped[:20000]):
        return "jsonl"
    if ext == "json" or stripped.startswith("[") or stripped.startswith("{"):
        return "json"
    if ext in ("csv", "tsv"):
        return "csv"
    first = stripped.split("\n", 1)[0]
    if ("," in first or "\t" in first) and not RE_LINE_SYSLOG.match(first) and not RE_LINE_APACHE.match(first) and not RE_LINE_ISO.match(first):
        return "csv"
    return "text"


def read_structured(text: str, kind: str) -> list[dict]:
    if kind == "csv":
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        except csv.Error:
            dialect = csv.excel
        rows = []
        for i, row in enumerate(csv.DictReader(io.StringIO(text), dialect=dialect)):
            if i >= MAX_ROWS_PER_INPUT:
                break
            rows.append({(k or "").strip(): v for k, v in row.items()})
        return rows
    if kind == "jsonl":
        rows = []
        for i, line in enumerate(text.splitlines()):
            if i >= MAX_ROWS_PER_INPUT:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj.get("_source", obj) if isinstance(obj.get("_source"), dict) else obj)
        return rows
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("Records", "value", "events", "hits", "data", "results", "items", "logs", "Events"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
            if isinstance(data.get(key), dict) and isinstance(data[key].get("hits"), list):
                data = data[key]["hits"]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        raise ValueError("JSON input is neither a list nor a wrapper around one")
    out = []
    for obj in data[:MAX_ROWS_PER_INPUT]:
        if isinstance(obj, dict):
            out.append(obj.get("_source", obj) if isinstance(obj.get("_source"), dict) else obj)
    return out


def read_text_lines(text: str) -> list[dict]:
    rows = []
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_ROWS_PER_INPUT:
            break
        line = line[:MAX_LINE].rstrip()
        if not line.strip() or line.startswith("#"):
            continue
        rec = {"raw": line, "ts": None, "actor": "", "action": "", "host": "", "detail": line}
        m = RE_LINE_APACHE.match(line)
        if m:
            rec.update(ts=m.group(3), actor=m.group(2) if m.group(2) != "-" else "", action=f"{m.group(4).split(' ')[0]} {m.group(5)}",
                       host=m.group(1), detail=(m.group(4) + (f" ua={m.group(8)}" if m.group(8) else "") + f" bytes={m.group(6)}"))
            rows.append(rec)
            continue
        m = RE_LINE_SYSLOG.match(line)
        if m:
            rec.update(ts=m.group(1), host=m.group(2) or "", action=m.group(3) or "", detail=m.group(5))
            rows.append(rec)
            continue
        m = RE_LINE_ISO.match(line)
        if m:
            rec.update(ts=m.group(1), detail=m.group(2))
            rows.append(rec)
            continue
        m = RE_LINE_IIS.match(line)
        if m:
            rec.update(ts=f"{m.group(1)}T{m.group(2)}Z", detail=m.group(3))
            rows.append(rec)
            continue
        m = RE_AUDIT.search(line)
        if m:
            rec.update(ts=m.group(0), action=(re.search(r"type=(\S+)", line) or [None, ""])[1] if re.search(r"type=(\S+)", line) else "",
                       actor=(re.search(r"\b(?:acct|auid|uid)=\"?([^\s\"]+)", line) or [None, ""])[1] if re.search(r"\b(?:acct|auid|uid)=", line) else "")
            rows.append(rec)
            continue
        m = RE_LINE_EPOCH.match(line)
        if m:
            rec.update(ts=m.group(1), detail=m.group(2))
            rows.append(rec)
            continue
        rows.append(rec)  # unparsed timestamp; kept if --keep-unparsed
    return rows


# --------------------------------------------------------------------------- build


def load_input(path: str, mapping: Mapping, assume: timezone, default_year: int) -> tuple[list[dict], dict]:
    if path == "-":
        text = sys.stdin.read(MAX_INPUT_BYTES + 1)
        name = "stdin"
    else:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"{p} is not a file")
        if p.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{p} exceeds {MAX_INPUT_BYTES} bytes")
        text = p.read_text(encoding="utf-8", errors="replace")
        name = p.name
    if not mapping.label:
        mapping.label = name.rsplit(".", 1)[0]
    kind = sniff_kind(name, text[:20000])
    stats = {"input": name, "kind": kind, "rows": 0, "parsed": 0, "unparsed": 0, "tz_assumed": 0, "source": mapping.label}
    events = []
    if kind == "text":
        rows = read_text_lines(text)
        for r in rows:
            stats["rows"] += 1
            dt, assumed = parse_ts(r["ts"], assume, default_year) if r["ts"] else (None, False)
            ev = {"timestamp_utc": dt, "source": mapping.label, "host": r["host"], "actor": r["actor"], "action": r["action"],
                  "detail": r["detail"], "original_ts": r["ts"] or ""}
            _account(stats, dt, assumed)
            events.append(ev)
        return events, stats
    rows = read_structured(text, kind)
    if rows:
        mapping.resolve(rows[0])
    if not mapping.ts:
        raise ValueError(f"{name}: could not determine the timestamp field; pass --map \"{mapping.label}=<timestamp_field>,...\"")
    stats["fields"] = {"ts": mapping.ts, "actor": mapping.actor, "action": mapping.action, "detail": mapping.detail, "host": mapping.host}
    for r in rows:
        stats["rows"] += 1
        raw_ts = get_field(r, mapping.ts)
        dt, assumed = parse_ts(raw_ts, assume, default_year)
        detail = " | ".join(flatten_value(get_field(r, f)) for f in mapping.detail.split("+") if f) if mapping.detail else ""
        ev = {"timestamp_utc": dt, "source": mapping.label, "host": flatten_value(get_field(r, mapping.host)),
              "actor": flatten_value(get_field(r, mapping.actor)), "action": flatten_value(get_field(r, mapping.action)),
              "detail": detail, "original_ts": flatten_value(raw_ts)}
        _account(stats, dt, assumed)
        events.append(ev)
    return events, stats


def _account(stats: dict, dt, assumed: bool) -> None:
    if dt is None:
        stats["unparsed"] += 1
    else:
        stats["parsed"] += 1
        if assumed:
            stats["tz_assumed"] += 1


def fmt_ts(dt: datetime | None) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def render(events: list[dict], fmt: str, *, keep_original: bool, detail_max: int, gap_minutes: float | None) -> str:
    cols = ["timestamp_utc", "source", "host", "actor", "action", "detail"] + (["original_ts"] if keep_original else [])
    rows = []
    prev = None
    for ev in events:
        if gap_minutes and prev is not None and ev["timestamp_utc"] and prev and (ev["timestamp_utc"] - prev).total_seconds() > gap_minutes * 60:
            gap = ev["timestamp_utc"] - prev
            rows.append({"timestamp_utc": fmt_ts(prev), "source": "[gap]", "host": "", "actor": "", "action": "gap",
                         "detail": f"no events for {gap.total_seconds() / 3600:.1f} h (until {fmt_ts(ev['timestamp_utc'])})", "original_ts": ""})
        rows.append({**ev, "timestamp_utc": fmt_ts(ev["timestamp_utc"])})
        if ev["timestamp_utc"]:
            prev = ev["timestamp_utc"]
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow(r)
        return buf.getvalue()
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        cells = []
        for c in cols:
            v = str(r.get(c, "")).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
            if c == "detail" and detail_max and len(v) > detail_max:
                v = v[:detail_max] + "..."
            cells.append(v)
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- cli


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="CSV/TSV, JSON array, JSON Lines, or text log files; - for stdin")
    ap.add_argument("--map", action="append", default=[], metavar="SPEC",
                    help="source=ts_field[,actor,action,detail[,host]] for the input in the same position (repeatable)")
    ap.add_argument("--assume-tz", default="UTC", help="zone for naive timestamps: +HH:MM, -HH:MM, Z, or local (default UTC)")
    ap.add_argument("--year", type=int, default=datetime.now(timezone.utc).year, help="year for syslog timestamps that lack one")
    ap.add_argument("--from", dest="from_ts", help="keep events at or after this time (ISO 8601; naive = UTC)")
    ap.add_argument("--to", dest="to_ts", help="keep events at or before this time (ISO 8601; naive = UTC)")
    ap.add_argument("--grep", help="case-insensitive regex; keep events whose host/actor/action/detail match")
    ap.add_argument("--source", action="append", default=[], help="keep only these source labels (repeatable)")
    ap.add_argument("--format", choices=["csv", "md"], default="md")
    ap.add_argument("--keep-original", action="store_true", help="include the original timestamp string as a column")
    ap.add_argument("--keep-unparsed", action="store_true", help="append rows whose timestamp could not be parsed (at the end)")
    ap.add_argument("--flag-gaps", type=float, metavar="MINUTES", help="insert a [gap] row where consecutive events are further apart than this")
    ap.add_argument("--detail-max", type=int, default=200, help="truncate detail in md output to this many chars (0 = no limit)")
    ap.add_argument("--limit", type=int, help="emit at most N events")
    # argparse treats "-04:00" as an option; fold "--assume-tz -04:00" into "--assume-tz=-04:00"
    argv = list(sys.argv[1:] if argv is None else argv)
    for i in range(len(argv) - 1):
        if argv[i] == "--assume-tz" and argv[i + 1].startswith("-"):
            argv[i:i + 2] = [f"--assume-tz={argv[i + 1]}"]
            break
    args = ap.parse_args(argv)

    try:
        assume = parse_offset(args.assume_tz)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if len(args.map) > len(args.inputs):
        print("error: more --map entries than inputs", file=sys.stderr)
        return 2
    if args.grep:
        try:
            grep = re.compile(args.grep, re.I)
        except re.error as exc:
            print(f"error: bad --grep regex: {exc}", file=sys.stderr)
            return 2
    else:
        grep = None
    lo = hi = None
    if args.from_ts:
        lo, _ = parse_ts(args.from_ts, timezone.utc, args.year)
        if lo is None:
            print(f"error: cannot parse --from {args.from_ts!r}", file=sys.stderr)
            return 2
    if args.to_ts:
        hi, _ = parse_ts(args.to_ts, timezone.utc, args.year)
        if hi is None:
            print(f"error: cannot parse --to {args.to_ts!r}", file=sys.stderr)
            return 2

    events: list[dict] = []
    all_stats = []
    for i, path in enumerate(args.inputs):
        spec = args.map[i] if i < len(args.map) else None
        mapping = Mapping(spec, fallback_label="")
        try:
            evs, stats = load_input(path, mapping, assume, args.year)
        except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        all_stats.append(stats)
        events.extend(evs)

    parsed = [e for e in events if e["timestamp_utc"] is not None]
    unparsed = [e for e in events if e["timestamp_utc"] is None]
    if not parsed:
        print("error: no events with a parseable timestamp; check --map and the timestamp format", file=sys.stderr)
        for s in all_stats:
            print(f"  {s['input']}: kind={s['kind']} rows={s['rows']} fields={s.get('fields')}", file=sys.stderr)
        return 2
    parsed.sort(key=lambda e: e["timestamp_utc"])  # stable: ties keep input order

    def keep(e: dict) -> bool:
        if args.source and e["source"] not in args.source:
            return False
        if lo and e["timestamp_utc"] and e["timestamp_utc"] < lo:
            return False
        if hi and e["timestamp_utc"] and e["timestamp_utc"] > hi:
            return False
        if grep and not grep.search(" ".join((e["host"], e["actor"], e["action"], e["detail"]))):
            return False
        return True

    selected = [e for e in parsed if keep(e)]
    if args.keep_unparsed:
        selected += [e for e in unparsed if keep(e)]
    if args.limit:
        selected = selected[:args.limit]

    sys.stdout.write(render(selected, args.format, keep_original=args.keep_original, detail_max=args.detail_max, gap_minutes=args.flag_gaps))

    first, last = (parsed[0]["timestamp_utc"], parsed[-1]["timestamp_utc"]) if parsed else (None, None)
    print(f"timeline: {len(selected)} events emitted of {len(parsed)} parsed ({len(unparsed)} unparsed); "
          f"range {fmt_ts(first)} .. {fmt_ts(last)}; naive timestamps assumed {args.assume_tz}", file=sys.stderr)
    for s in all_stats:
        extra = f" fields={s['fields']}" if s.get("fields") else ""
        print(f"  {s['source']:<16} {s['input']} kind={s['kind']} rows={s['rows']} parsed={s['parsed']} unparsed={s['unparsed']} tz_assumed={s['tz_assumed']}{extra}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
