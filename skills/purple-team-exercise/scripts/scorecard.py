#!/usr/bin/env python3
"""Turn purple-team observation records into a detection scorecard.

Input is a CSV with one row per executed emulation test. Required columns:

    technique_id     ATT&CK technique or sub-technique ID, e.g. T1003.001
    technique        technique name
    tactic           tactic name (comes from your test plan; this script does not look it up)
    test_name        emulation test name or ID (Atomic Red Team test name, Stratus ID, ...)
    expected_source  the data source / log that should have seen it (Sysmon 10, CloudTrail, ...)
    observed         alert | logged | none   (alerted, detected -> alert; visible, telemetry -> logged)
    ttd_minutes      minutes from execution to alert (blank unless observed = alert)
    notes            free text

Optional columns: test_id, platform, priority (1 = highest, 5 = lowest, or high/medium/low),
target, run_at, rule_name. Unknown columns are carried through to JSON output.

Produces coverage percentages, a per-tactic breakdown, a per-technique rollup (best
outcome across that technique's tests), time-to-detect statistics against an SLA, a
prioritized gap list, and a detection backlog block ready to hand to detection-engineering.
With --previous it also lists what improved or regressed since the last run.

Standard library only. Read-only.

Usage:
    python scorecard.py results.csv
    python scorecard.py results.csv --format json
    python scorecard.py results.csv --name "Q3 ransomware precursor exercise" --ttd-sla 30
    python scorecard.py results.csv --previous q2_results.csv
    cat results.csv | python scorecard.py - --format md

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

MAX_ROWS = 200_000

REQUIRED = ["technique_id", "technique", "tactic", "test_name", "expected_source", "observed"]

OBSERVED_MAP = {
    "alert": "alert", "alerted": "alert", "detected": "alert", "detection": "alert", "prevented": "alert",
    "blocked": "alert", "a": "alert",
    "logged": "logged", "log": "logged", "visible": "logged", "telemetry": "logged", "seen": "logged",
    "logged only": "logged", "l": "logged",
    "none": "none", "no": "none", "missed": "none", "not visible": "none", "invisible": "none",
    "blind": "none", "n": "none", "": "none",
}

# Kill-chain order for sorting tactic tables and gap lists. Names as in ATT&CK Enterprise
# v17 (2025). Anything not listed sorts after these, alphabetically.
TACTIC_ORDER = [
    "reconnaissance", "resource development", "initial access", "execution", "persistence",
    "privilege escalation", "defense evasion", "credential access", "discovery", "lateral movement",
    "collection", "command and control", "exfiltration", "impact",
]

PRIORITY_WORDS = {"critical": 1, "high": 2, "medium": 3, "med": 3, "low": 4, "info": 5}

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# --------------------------------------------------------------------------- input

def norm_observed(value: str) -> str | None:
    v = (value or "").strip().lower()
    return OBSERVED_MAP.get(v)


def norm_priority(value: str) -> int:
    v = (value or "").strip().lower()
    if not v:
        return 3
    if v.isdigit():
        return min(max(int(v), 1), 5)
    return PRIORITY_WORDS.get(v, 3)


def tactic_rank(tactic: str) -> tuple[int, str]:
    t = tactic.strip().lower().replace("-", " ")
    return (TACTIC_ORDER.index(t), t) if t in TACTIC_ORDER else (len(TACTIC_ORDER), t)


def read_rows(text: str) -> tuple[list[dict], list[str]]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("empty input or missing header")
    header = [h.strip().lower().replace(" ", "_") for h in reader.fieldnames]
    reader.fieldnames = header
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise ValueError(f"missing required column(s) {missing}; header is {header}")

    rows: list[dict] = []
    problems: list[str] = []
    for n, raw in enumerate(reader, start=2):
        if len(rows) >= MAX_ROWS:
            problems.append(f"stopped after {MAX_ROWS} rows")
            break
        row = {k: (v or "").strip()[:2000] for k, v in raw.items() if k}
        if not any(row.values()):
            continue
        tid = row.get("technique_id", "").upper()
        if not _TID_RE.match(tid):
            problems.append(f"line {n}: technique_id {tid!r} is not Txxxx or Txxxx.xxx")
        obs = norm_observed(row.get("observed", ""))
        if obs is None:
            problems.append(f"line {n}: observed {row.get('observed')!r} not in alert/logged/none; treated as none")
            obs = "none"
        ttd_raw = row.get("ttd_minutes", "")
        ttd: float | None = None
        if ttd_raw:
            try:
                ttd = float(ttd_raw)
                if ttd < 0:
                    raise ValueError
            except ValueError:
                problems.append(f"line {n}: ttd_minutes {ttd_raw!r} is not a non-negative number; ignored")
                ttd = None
        if obs != "alert" and ttd is not None:
            problems.append(f"line {n}: ttd_minutes set but observed is {obs}; ttd ignored")
            ttd = None
        row.update({
            "technique_id": tid, "observed": obs, "ttd_minutes": ttd,
            "tactic": row.get("tactic", "").strip() or "unknown",
            "priority": norm_priority(row.get("priority", "")),
            "_line": n,
        })
        rows.append(row)
    if not rows:
        raise ValueError("no data rows")
    return rows, problems


# --------------------------------------------------------------------------- scoring

OUTCOME_RANK = {"alert": 2, "logged": 1, "none": 0}


def pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


def build(rows: list[dict], *, ttd_sla: float, previous: list[dict] | None) -> dict:
    total = len(rows)
    counts = Counter(r["observed"] for r in rows)
    alert_n, logged_n, none_n = counts["alert"], counts["logged"], counts["none"]

    ttds = [r["ttd_minutes"] for r in rows if r["observed"] == "alert" and r["ttd_minutes"] is not None]
    ttd_stats = {
        "alerts_with_ttd": len(ttds),
        "median_minutes": round(statistics.median(ttds), 1) if ttds else None,
        "mean_minutes": round(statistics.fmean(ttds), 1) if ttds else None,
        "max_minutes": max(ttds) if ttds else None,
        "sla_minutes": ttd_sla,
        "over_sla": sum(1 for t in ttds if t > ttd_sla),
    }

    # per tactic
    by_tactic: dict[str, Counter] = defaultdict(Counter)
    tactic_ttd: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        by_tactic[r["tactic"]][r["observed"]] += 1
        if r["observed"] == "alert" and r["ttd_minutes"] is not None:
            tactic_ttd[r["tactic"]].append(r["ttd_minutes"])
    tactics = []
    for t in sorted(by_tactic, key=tactic_rank):
        c = by_tactic[t]
        n = sum(c.values())
        tactics.append({
            "tactic": t, "tests": n, "alert": c["alert"], "logged": c["logged"], "none": c["none"],
            "coverage_pct": pct(c["alert"], n), "visibility_pct": pct(c["alert"] + c["logged"], n),
            "median_ttd": round(statistics.median(tactic_ttd[t]), 1) if tactic_ttd[t] else None,
        })

    # per technique (best outcome across its tests)
    by_tech: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_tech[r["technique_id"]].append(r)
    techniques = []
    for tid, trs in by_tech.items():
        best = max(trs, key=lambda r: OUTCOME_RANK[r["observed"]])
        tt = [r["ttd_minutes"] for r in trs if r["observed"] == "alert" and r["ttd_minutes"] is not None]
        techniques.append({
            "technique_id": tid, "technique": best.get("technique", ""),
            "tactic": best["tactic"], "tests": len(trs),
            "alert": sum(1 for r in trs if r["observed"] == "alert"),
            "logged": sum(1 for r in trs if r["observed"] == "logged"),
            "none": sum(1 for r in trs if r["observed"] == "none"),
            "best": best["observed"], "best_ttd": min(tt) if tt else None,
            "priority": min(r["priority"] for r in trs),
        })
    techniques.sort(key=lambda x: (tactic_rank(x["tactic"]), x["technique_id"]))
    tech_counts = Counter(t["best"] for t in techniques)

    # gap list: none first, then logged; within group by priority, then partially-covered
    # techniques last (a technique with one alerting test is less urgent than a blind one)
    tech_best = {t["technique_id"]: t["best"] for t in techniques}
    gaps = []
    for r in rows:
        if r["observed"] == "alert":
            continue
        gaps.append({
            "technique_id": r["technique_id"], "technique": r.get("technique", ""), "tactic": r["tactic"],
            "test_name": r.get("test_name", ""), "test_id": r.get("test_id", ""),
            "expected_source": r.get("expected_source", ""), "observed": r["observed"],
            "priority": r["priority"], "technique_best": tech_best[r["technique_id"]],
            "platform": r.get("platform", ""), "notes": r.get("notes", ""),
            "action": ("confirm the data source is onboarded and the event is generated, then write a rule"
                       if r["observed"] == "none" else
                       "telemetry exists: write or tune a detection rule and add a unit test"),
        })
    gaps.sort(key=lambda g: (OUTCOME_RANK[g["observed"]], g["priority"],
                             OUTCOME_RANK[g["technique_best"]], tactic_rank(g["tactic"]), g["technique_id"]))
    for i, g in enumerate(gaps, start=1):
        g["rank"] = i

    # source health: which expected sources went blind most often
    src: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        src[r.get("expected_source", "") or "unspecified"][r["observed"]] += 1
    sources = sorted(
        ({"source": s, "tests": sum(c.values()), "alert": c["alert"], "logged": c["logged"], "none": c["none"]}
         for s, c in src.items()),
        key=lambda x: (-x["none"], -x["tests"], x["source"]))

    changes = None
    if previous is not None:
        prev_best: dict[str, str] = {}
        for r in previous:
            cur = prev_best.get(r["technique_id"], "none")
            if OUTCOME_RANK[r["observed"]] > OUTCOME_RANK.get(cur, -1):
                prev_best[r["technique_id"]] = r["observed"]
        improved, regressed, new, dropped = [], [], [], []
        for t in techniques:
            tid = t["technique_id"]
            if tid not in prev_best:
                new.append(tid)
            elif OUTCOME_RANK[t["best"]] > OUTCOME_RANK[prev_best[tid]]:
                improved.append({"technique_id": tid, "from": prev_best[tid], "to": t["best"]})
            elif OUTCOME_RANK[t["best"]] < OUTCOME_RANK[prev_best[tid]]:
                regressed.append({"technique_id": tid, "from": prev_best[tid], "to": t["best"]})
        dropped = sorted(set(prev_best) - set(tech_best))
        prev_alert = sum(1 for v in prev_best.values() if v == "alert")
        changes = {
            "previous_techniques": len(prev_best), "previous_coverage_pct": pct(prev_alert, len(prev_best)),
            "improved": improved, "regressed": regressed, "new_techniques": new, "not_retested": dropped,
        }

    return {
        "tests": total, "techniques": len(techniques), "tactics": len(tactics),
        "test_outcomes": {"alert": alert_n, "logged": logged_n, "none": none_n},
        "test_coverage_pct": pct(alert_n, total), "test_visibility_pct": pct(alert_n + logged_n, total),
        "test_blind_pct": pct(none_n, total),
        "technique_outcomes": {"alert": tech_counts["alert"], "logged": tech_counts["logged"], "none": tech_counts["none"]},
        "technique_coverage_pct": pct(tech_counts["alert"], len(techniques)),
        "technique_visibility_pct": pct(tech_counts["alert"] + tech_counts["logged"], len(techniques)),
        "ttd": ttd_stats, "by_tactic": tactics, "by_technique": techniques, "gaps": gaps,
        "sources": sources, "changes": changes,
    }


# --------------------------------------------------------------------------- render

def _e(s: object) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _m(v: float | None) -> str:
    return "n/a" if v is None else f"{v:g}"


def render_md(s: dict, name: str, problems: list[str]) -> str:
    out = [f"# Purple team scorecard: {name}", ""]
    o, t = s["test_outcomes"], s["technique_outcomes"]
    out.append(f"- Tests executed: **{s['tests']}** across **{s['techniques']}** techniques and {s['tactics']} tactics")
    out.append(f"- Test outcomes: alert {o['alert']}, logged only {o['logged']}, not visible {o['none']}")
    out.append(f"- **Detection coverage (alert): {s['test_coverage_pct']}% of tests, "
               f"{s['technique_coverage_pct']}% of techniques (best test per technique)**")
    out.append(f"- Visibility (alert or logged): {s['test_visibility_pct']}% of tests, "
               f"{s['technique_visibility_pct']}% of techniques; blind: {s['test_blind_pct']}% of tests")
    td = s["ttd"]
    out.append(f"- Time to detect (alerts with a TTD, n={td['alerts_with_ttd']}): median {_m(td['median_minutes'])} min, "
               f"mean {_m(td['mean_minutes'])} min, max {_m(td['max_minutes'])} min; "
               f"{td['over_sla']} over the {td['sla_minutes']:g} min SLA")
    if problems:
        out.append(f"- Data quality notes: {len(problems)} (see end)")
    out.append("")

    out.append("## By tactic")
    out.append("")
    out.append("| Tactic | Tests | Alert | Logged | None | Coverage | Visibility | Median TTD (min) |")
    out.append("|---|---|---|---|---|---|---|---|")
    for x in s["by_tactic"]:
        out.append(f"| {_e(x['tactic'])} | {x['tests']} | {x['alert']} | {x['logged']} | {x['none']} "
                   f"| {x['coverage_pct']}% | {x['visibility_pct']}% | {_m(x['median_ttd'])} |")
    out.append("")

    out.append("## By technique")
    out.append("")
    out.append("| Technique | Name | Tactic | Tests | Best outcome | Best TTD (min) | A/L/N |")
    out.append("|---|---|---|---|---|---|---|")
    for x in s["by_technique"]:
        out.append(f"| {x['technique_id']} | {_e(x['technique'])} | {_e(x['tactic'])} | {x['tests']} | **{x['best']}** "
                   f"| {_m(x['best_ttd'])} | {x['alert']}/{x['logged']}/{x['none']} |")
    out.append("")

    out.append(f"## Gap list ({len(s['gaps'])}), prioritized")
    out.append("")
    if s["gaps"]:
        out.append("| # | Technique | Test | Tactic | Expected source | Observed | Pri | Technique best | Notes |")
        out.append("|---|---|---|---|---|---|---|---|---|")
        for g in s["gaps"]:
            test = g["test_name"] + (f" ({g['test_id']})" if g["test_id"] else "")
            out.append(f"| {g['rank']} | {g['technique_id']} {_e(g['technique'])} | {_e(test)} | {_e(g['tactic'])} "
                       f"| {_e(g['expected_source'])} | {g['observed']} | {g['priority']} | {g['technique_best']} | {_e(g['notes'])} |")
    else:
        out.append("_Every test produced an alert. Re-check that the tests actually ran and that the alerts fired on the test, not on the tooling._")
    out.append("")

    out.append("## Data source health")
    out.append("")
    out.append("| Expected source | Tests | Alert | Logged | None |")
    out.append("|---|---|---|---|---|")
    for x in s["sources"]:
        out.append(f"| {_e(x['source'])} | {x['tests']} | {x['alert']} | {x['logged']} | {x['none']} |")
    out.append("")

    if s["changes"]:
        c = s["changes"]
        out.append("## Changes since previous run")
        out.append("")
        out.append(f"- Previous: {c['previous_techniques']} techniques, {c['previous_coverage_pct']}% technique coverage; "
                   f"now {s['techniques']} techniques, {s['technique_coverage_pct']}%")
        out.append("- Improved: " + (", ".join(f"{i['technique_id']} ({i['from']} -> {i['to']})" for i in c["improved"]) or "none"))
        out.append("- Regressed: " + (", ".join(f"{i['technique_id']} ({i['from']} -> {i['to']})" for i in c["regressed"]) or "none"))
        out.append("- New this run: " + (", ".join(c["new_techniques"]) or "none"))
        out.append("- Not retested: " + (", ".join(c["not_retested"]) or "none"))
        out.append("")

    out.append("## Detection backlog (hand to detection-engineering)")
    out.append("")
    if s["gaps"]:
        for g in s["gaps"]:
            out.append(f"- [ ] **{g['technique_id']}** {_e(g['technique'])} / {_e(g['test_name'])} "
                       f"(source: {_e(g['expected_source'])}, currently {g['observed']}): {g['action']}")
    else:
        out.append("- nothing outstanding")
    if problems:
        out.append("")
        out.append("## Data quality notes")
        out.append("")
        for p in problems[:50]:
            out.append(f"- {p}")
    return "\n".join(out)


# --------------------------------------------------------------------------- cli

def _read_text(spec: str) -> str:
    if spec == "-":
        return sys.stdin.read()
    p = Path(spec)
    if not p.is_file():
        raise FileNotFoundError(spec)
    return p.read_text(encoding="utf-8-sig", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="results CSV, or - for stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--name", help="exercise name for the title (default: input filename)")
    ap.add_argument("--ttd-sla", type=float, default=60.0, help="time-to-detect SLA in minutes (default 60)")
    ap.add_argument("--previous", help="results CSV from an earlier run, to report improvements and regressions")
    args = ap.parse_args(argv)

    try:
        rows, problems = read_rows(_read_text(args.input))
        previous = None
        if args.previous:
            previous, prev_problems = read_rows(_read_text(args.previous))
            problems.extend(f"previous: {p}" for p in prev_problems)
    except FileNotFoundError as exc:
        print(f"error: {exc} is not a file", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.ttd_sla <= 0:
        print("error: --ttd-sla must be positive", file=sys.stderr)
        return 2

    name = args.name or (Path(args.input).stem if args.input != "-" else "exercise")
    summary = build(rows, ttd_sla=args.ttd_sla, previous=previous)
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)

    if args.format == "json":
        summary["name"] = name
        summary["problems"] = problems
        summary["rows"] = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
        sys.stdout.write(json.dumps(summary, indent=2))
    else:
        sys.stdout.write(render_md(summary, name, problems))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
