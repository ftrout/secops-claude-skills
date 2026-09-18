#!/usr/bin/env python3
"""Summarize a STIX 2.1 bundle so an analyst can see what is in it before reading it.

Standard library only. Reads a bundle JSON (file path or - for stdin) and reports:
object counts by type, threat actors and intrusion sets with aliases, campaigns,
malware and tools, attack patterns with their ATT&CK external IDs and kill-chain
phases, indicators grouped by the observable type in their pattern (values
defanged by default), vulnerabilities, reports, relationships summarised by
type with names resolved, and TLP markings with the number of objects carrying
each. Output is Markdown (default) or JSON.

The script parses only. It never resolves URLs, never executes anything, and
treats every string in the bundle as untrusted data.

Usage:
    python stix_summary.py bundle.json
    python stix_summary.py bundle.json --format json
    cat bundle.json | python stix_summary.py - --refang --max-list 50
    python stix_summary.py bundle.json --indicators-only

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

MAX_INPUT_BYTES = 200 * 1024 * 1024  # bundles from a TIP can be large; still bounded
MAX_OBJECTS = 500_000

ATTACK_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack", "mitre-pre-attack"}

# STIX comparison expression: [object-type:property OP 'value']. The value group is
# bounded so a hostile pattern cannot make the regex crawl.
COMPARISON_RE = re.compile(
    r"([a-z0-9-]{1,64}):([A-Za-z0-9_.'\-\[\]*]{1,128})\s*"
    r"(=|!=|>=|<=|>|<|LIKE|MATCHES|ISSUBSET|ISSUPERSET|IN)\s*"
    r"'((?:[^'\\]|\\.){0,2048})'")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# TLP marking-definition IDs fixed by the STIX 2.1 spec (TLP 1.0) and by the
# oasis-open TLP 2.0 extension. Used as a fallback when a bundle references a
# marking it does not include.
KNOWN_TLP_IDS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:WHITE",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "TLP:CLEAR",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "TLP:GREEN (2.0)",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "TLP:AMBER (2.0)",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "TLP:AMBER+STRICT",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "TLP:RED (2.0)",
}

# Map STIX observable object paths to the short indicator type used in output.
PATH_TYPES = [
    (("ipv4-addr", "value"), "ipv4"),
    (("ipv6-addr", "value"), "ipv6"),
    (("domain-name", "value"), "domain"),
    (("url", "value"), "url"),
    (("email-addr", "value"), "email"),
    (("email-message", "subject"), "email-subject"),
    (("email-message", "from_ref"), "email"),
    (("file", "hashes.md5"), "md5"),
    (("file", "hashes.'md5'"), "md5"),
    (("file", "hashes.'sha-1'"), "sha1"),
    (("file", "hashes.sha1"), "sha1"),
    (("file", "hashes.'sha-256'"), "sha256"),
    (("file", "hashes.sha256"), "sha256"),
    (("file", "hashes.'sha-512'"), "sha512"),
    (("file", "hashes.ssdeep"), "ssdeep"),
    (("file", "name"), "filename"),
    (("file", "parent_directory_ref.path"), "path"),
    (("directory", "path"), "path"),
    (("windows-registry-key", "key"), "registry"),
    (("mutex", "name"), "mutex"),
    (("process", "command_line"), "command-line"),
    (("network-traffic", "dst_port"), "port"),
    (("x509-certificate", "hashes.'sha-256'"), "cert-sha256"),
    (("user-agent", "value"), "user-agent"),
    (("autonomous-system", "number"), "asn"),
]


# --------------------------------------------------------------------------- helpers

def _s(value, limit: int = 300) -> str:
    """Coerce any JSON value to a bounded, single-line string."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def defang(value: str, kind: str) -> str:
    if kind == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.I).replace("://", "[://]", 1)
        return value.replace(".", "[.]")
    if kind in {"ipv4", "domain"}:
        return value.replace(".", "[.]")
    if kind == "ipv6":
        return value.replace(":", "[:]")
    if kind == "email":
        local, _, dom = value.rpartition("@")
        return f"{local}[@]{dom.replace('.', '[.]')}"
    return value


def classify_path(obj_type: str, prop: str) -> str:
    prop_l = prop.lower()
    for (t, p), kind in PATH_TYPES:
        if obj_type == t and prop_l == p:
            return kind
    return f"{obj_type}:{prop}"


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Return (kind, value) pairs from a STIX pattern string. Only 'stix' patterns."""
    out = []
    for m in COMPARISON_RE.finditer(pattern[:20_000]):
        obj_type, prop, _op, value = m.groups()
        out.append((classify_path(obj_type, prop), value.replace("\\'", "'").replace("\\\\", "\\")))
    return out


def attack_ids(obj: dict) -> list[str]:
    ids = []
    for ref in obj.get("external_references", []) or []:
        if isinstance(ref, dict) and ref.get("source_name") in ATTACK_SOURCES and ref.get("external_id"):
            ids.append(_s(ref["external_id"], 32))
    return ids


def cve_ids(obj: dict) -> list[str]:
    ids = set()
    for ref in obj.get("external_references", []) or []:
        if isinstance(ref, dict):
            for key in ("external_id", "url", "description"):
                for m in CVE_RE.finditer(_s(ref.get(key), 2000)):
                    ids.add(m.group(0).upper())
    for m in CVE_RE.finditer(_s(obj.get("name"), 500)):
        ids.add(m.group(0).upper())
    return sorted(ids)


def tlp_label(marking: dict) -> str | None:
    """Return a TLP label for a marking-definition object, or None if it is not TLP."""
    if marking.get("definition_type") == "tlp":
        val = (marking.get("definition") or {}).get("tlp")
        if isinstance(val, str):
            return "TLP:" + val.upper()
    name = _s(marking.get("name"), 64)
    if name.upper().startswith("TLP:"):
        return name.upper()
    ext = marking.get("extensions") or {}
    if isinstance(ext, dict):
        for ext_body in ext.values():
            if isinstance(ext_body, dict) and isinstance(ext_body.get("tlp_2_0"), str):
                return "TLP:" + ext_body["tlp_2_0"].upper()
    return KNOWN_TLP_IDS.get(marking.get("id", ""))


# --------------------------------------------------------------------------- core

def summarize(bundle: dict, *, do_defang: bool = True, max_list: int = 25) -> dict:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("bundle has no 'objects' array")
    if len(objects) > MAX_OBJECTS:
        raise ValueError(f"bundle has {len(objects)} objects; limit is {MAX_OBJECTS}")
    objs = [o for o in objects if isinstance(o, dict) and isinstance(o.get("type"), str)]

    by_id: dict[str, dict] = {o["id"]: o for o in objs if isinstance(o.get("id"), str)}
    counts = Counter(o["type"] for o in objs)

    def name_of(ref: str) -> str:
        o = by_id.get(ref)
        if not o:
            return ref.split("--")[0] + ":<not in bundle>"
        label = _s(o.get("name") or o.get("value") or o.get("pattern") or ref, 80)
        return f"{o['type']}:{label}"

    # Markings
    markings: dict[str, str] = {}
    for o in objs:
        if o["type"] == "marking-definition":
            label = tlp_label(o)
            markings[o["id"]] = label or _s(o.get("name") or o.get("definition_type") or "statement", 60)
    marking_use: Counter = Counter()
    unmarked = 0
    for o in objs:
        if o["type"] == "marking-definition":
            continue
        refs = o.get("object_marking_refs") or []
        if not refs:
            unmarked += 1
            continue
        for r in refs:
            if isinstance(r, str):
                marking_use[markings.get(r) or KNOWN_TLP_IDS.get(r) or f"<unknown {r[:40]}>"] += 1
    tlp_values = {v for v in marking_use if v.startswith("TLP:")}

    def simple(o: dict, extra: tuple[str, ...] = ()) -> dict:
        rec = {"name": _s(o.get("name"), 120)}
        if o.get("aliases"):
            rec["aliases"] = [_s(a, 60) for a in o["aliases"][:max_list]]
        for key in extra:
            val = o.get(key)
            if val in (None, "", []):
                continue
            if isinstance(val, list):
                rec[key] = [_s(v, 60) for v in val[:max_list]]
            elif isinstance(val, (int, float, bool)):
                rec[key] = val
            else:
                rec[key] = _s(val, 200)
        if o.get("description"):
            rec["description"] = _s(o["description"], 240)
        if o.get("object_marking_refs"):
            rec["marking"] = [markings.get(r, KNOWN_TLP_IDS.get(r, "?")) for r in o["object_marking_refs"] if isinstance(r, str)]
        return rec

    actors = [simple(o, ("threat_actor_types", "sophistication", "resource_level", "primary_motivation"))
              for o in objs if o["type"] == "threat-actor"]
    intrusion_sets = [simple(o, ("first_seen", "last_seen", "resource_level")) for o in objs if o["type"] == "intrusion-set"]
    campaigns = [simple(o, ("first_seen", "last_seen", "objective")) for o in objs if o["type"] == "campaign"]
    malware = [simple(o, ("malware_types", "is_family", "capabilities")) for o in objs if o["type"] == "malware"]
    tools = [simple(o, ("tool_types",)) for o in objs if o["type"] == "tool"]
    identities = [simple(o, ("identity_class", "sectors")) for o in objs if o["type"] == "identity"]
    reports = [simple(o, ("report_types", "published")) | {"object_refs": len(o.get("object_refs") or [])}
               for o in objs if o["type"] == "report"]
    coas = [simple(o) for o in objs if o["type"] == "course-of-action"]

    attack_patterns = []
    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        phases = sorted({_s(p.get("phase_name"), 40) for p in o.get("kill_chain_phases") or [] if isinstance(p, dict)})
        attack_patterns.append({"name": _s(o.get("name"), 120), "attack_ids": attack_ids(o), "tactics": phases})
    attack_patterns.sort(key=lambda r: (r["attack_ids"] or ["~"], r["name"]))

    vulns = [{"name": _s(o.get("name"), 120), "cves": cve_ids(o)} for o in objs if o["type"] == "vulnerability"]

    indicators_by_type: dict[str, list[dict]] = defaultdict(list)
    unparsed = 0
    for o in objs:
        if o["type"] != "indicator":
            continue
        ptype = o.get("pattern_type", "stix")
        pattern = o.get("pattern") if isinstance(o.get("pattern"), str) else ""
        pairs = parse_pattern(pattern) if ptype == "stix" else []
        if not pairs:
            unparsed += 1
            indicators_by_type[f"unparsed ({ptype})"].append({
                "value": _s(pattern, 200), "name": _s(o.get("name"), 80)})
            continue
        for kind, value in pairs:
            shown = defang(value, kind) if do_defang else value
            indicators_by_type[kind].append({
                "value": _s(shown, 300),
                "name": _s(o.get("name"), 80),
                "indicator_types": [_s(t, 40) for t in o.get("indicator_types") or []],
                "valid_from": _s(o.get("valid_from"), 32),
                "valid_until": _s(o.get("valid_until"), 32),
                "confidence": o.get("confidence") if isinstance(o.get("confidence"), int) else None,
            })
    indicator_counts = {k: len(v) for k, v in sorted(indicators_by_type.items())}
    for k in indicators_by_type:
        indicators_by_type[k] = indicators_by_type[k][:max_list]

    rel_types: Counter = Counter()
    rel_edges: Counter = Counter()
    rel_examples: list[str] = []
    for o in objs:
        if o["type"] != "relationship":
            continue
        rtype = _s(o.get("relationship_type"), 40)
        src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
        if not isinstance(src, str) or not isinstance(tgt, str):
            continue
        rel_types[rtype] += 1
        rel_edges[f"{src.split('--')[0]} -{rtype}-> {tgt.split('--')[0]}"] += 1
        if len(rel_examples) < max_list * 2:
            rel_examples.append(f"{name_of(src)} -{rtype}-> {name_of(tgt)}")
    sightings = sum(1 for o in objs if o["type"] == "sighting")

    return {
        "bundle_id": _s(bundle.get("id"), 80),
        "object_count": len(objs),
        "counts_by_type": dict(sorted(counts.items())),
        "tlp": sorted(tlp_values) or ["(none)"],
        "marking_use": dict(marking_use.most_common()),
        "unmarked_objects": unmarked,
        "threat_actors": actors[:max_list],
        "intrusion_sets": intrusion_sets[:max_list],
        "campaigns": campaigns[:max_list],
        "malware": malware[:max_list],
        "tools": tools[:max_list],
        "attack_patterns": attack_patterns[:max_list * 4],
        "attack_ids": sorted({i for ap in attack_patterns for i in ap["attack_ids"]}),
        "vulnerabilities": vulns[:max_list],
        "identities": identities[:max_list],
        "reports": reports[:max_list],
        "courses_of_action": coas[:max_list],
        "indicator_counts": indicator_counts,
        "indicators_unparsed": unparsed,
        "indicators": dict(indicators_by_type),
        "relationship_types": dict(rel_types.most_common()),
        "relationship_edges": dict(rel_edges.most_common()),
        "relationship_examples": rel_examples,
        "sightings": sightings,
        "defanged": do_defang,
    }


# --------------------------------------------------------------------------- output

def _md_list(rows: list[dict], fields: tuple[str, ...]) -> list[str]:
    out = []
    for r in rows:
        bits = [f"**{r.get('name') or '(unnamed)'}**"]
        for f in fields:
            v = r.get(f)
            if v not in (None, "", [], {}):
                bits.append(f"{f}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
        if r.get("description"):
            bits.append(r["description"])
        out.append("- " + "; ".join(bits))
    return out or ["- (none)"]


def render_md(s: dict, indicators_only: bool = False) -> str:
    L: list[str] = []
    if not indicators_only:
        L += [f"# STIX bundle summary", f"**Bundle:** `{s['bundle_id'] or '(no id)'}`  ",
              f"**Objects:** {s['object_count']}  ", f"**TLP:** {', '.join(s['tlp'])}  ",
              f"**Indicators:** {'defanged' if s['defanged'] else 'LIVE (refanged)'}", ""]
        L += ["## Objects by type", "| Type | Count |", "|---|---|"]
        L += [f"| {t} | {n} |" for t, n in s["counts_by_type"].items()]
        L += ["", "## Markings"]
        L += [f"- {m}: {n} objects" for m, n in s["marking_use"].items()] or ["- (no object markings)"]
        L.append(f"- unmarked objects: {s['unmarked_objects']}")
        L += ["", "## Threat actors"] + _md_list(s["threat_actors"], ("aliases", "threat_actor_types", "sophistication", "resource_level", "primary_motivation", "marking"))
        L += ["", "## Intrusion sets"] + _md_list(s["intrusion_sets"], ("aliases", "first_seen", "last_seen"))
        if s["campaigns"]:
            L += ["", "## Campaigns"] + _md_list(s["campaigns"], ("aliases", "first_seen", "last_seen", "objective"))
        L += ["", "## Malware"] + _md_list(s["malware"], ("aliases", "malware_types", "is_family"))
        if s["tools"]:
            L += ["", "## Tools"] + _md_list(s["tools"], ("aliases", "tool_types"))
        L += ["", "## Attack patterns (ATT&CK)", "| ATT&CK ID | Name | Tactic(s) |", "|---|---|---|"]
        L += [f"| {', '.join(ap['attack_ids']) or '-'} | {ap['name']} | {', '.join(ap['tactics']) or '-'} |"
              for ap in s["attack_patterns"]] or ["| - | (none) | - |"]
        if s["attack_ids"]:
            L += ["", f"Technique IDs for `mitre-attack-mapping`: `{' '.join(s['attack_ids'])}`"]
        if s["vulnerabilities"]:
            L += ["", "## Vulnerabilities"] + [f"- {v['name']} ({', '.join(v['cves']) or 'no CVE id'})" for v in s["vulnerabilities"]]
        L.append("")
    L += ["## Indicators", "| Type | Count |", "|---|---|"]
    L += [f"| {t} | {n} |" for t, n in s["indicator_counts"].items()] or ["| - | 0 |"]
    if s["indicators_unparsed"]:
        L.append(f"\n{s['indicators_unparsed']} indicator(s) had non-STIX or unparseable patterns; inspect them by hand.")
    for kind, rows in s["indicators"].items():
        L += ["", f"### {kind} ({s['indicator_counts'].get(kind, len(rows))})"]
        for r in rows:
            meta = []
            if r.get("indicator_types"):
                meta.append("/".join(r["indicator_types"]))
            if r.get("valid_until"):
                meta.append(f"until {r['valid_until'][:10]}")
            if r.get("confidence") is not None:
                meta.append(f"conf {r['confidence']}")
            L.append(f"- `{r['value']}`" + (f" ({'; '.join(meta)})" if meta else "") + (f" {r['name']}" if r.get("name") and r["name"] != r["value"] else ""))
        if s["indicator_counts"].get(kind, 0) > len(rows):
            L.append(f"- ... {s['indicator_counts'][kind] - len(rows)} more (raise --max-list)")
    if not indicators_only:
        L += ["", "## Relationships", "| Relationship | Count |", "|---|---|"]
        L += [f"| {e} | {n} |" for e, n in s["relationship_edges"].items()] or ["| (none) | 0 |"]
        if s["relationship_examples"]:
            L += ["", "Resolved examples:"] + [f"- {e}" for e in s["relationship_examples"]]
        if s["sightings"]:
            L.append(f"\nSightings: {s['sightings']}")
        if s["reports"]:
            L += ["", "## Reports"] + _md_list(s["reports"], ("report_types", "published", "object_refs"))
        if s["courses_of_action"]:
            L += ["", "## Courses of action"] + _md_list(s["courses_of_action"], ())
        if s["identities"]:
            L += ["", "## Identities"] + _md_list(s["identities"], ("identity_class", "sectors"))
    return "\n".join(L)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="STIX 2.1 bundle JSON file, or - for stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--refang", action="store_true", help="show live indicator values (default: defanged)")
    ap.add_argument("--max-list", type=int, default=25, help="max entries per list in the output (default 25)")
    ap.add_argument("--indicators-only", action="store_true", help="Markdown output: only the indicator section")
    args = ap.parse_args(argv)

    try:
        if args.input == "-":
            raw = sys.stdin.read()
            if len(raw) > MAX_INPUT_BYTES:
                raise ValueError("stdin input exceeds size limit")
        else:
            p = Path(args.input)
            if not p.is_file():
                raise ValueError(f"{p} is not a file")
            if p.stat().st_size > MAX_INPUT_BYTES:
                raise ValueError(f"{p} exceeds size limit ({MAX_INPUT_BYTES} bytes)")
            raw = p.read_text(encoding="utf-8", errors="replace")
        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON: {exc}")
        if isinstance(bundle, list):  # tolerate a bare object array
            bundle = {"type": "bundle", "objects": bundle}
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise ValueError("input is not a STIX bundle (expected {\"type\": \"bundle\", \"objects\": [...]})")
        summary = summarize(bundle, do_defang=not args.refang, max_list=max(1, args.max_list))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render_md(summary, indicators_only=args.indicators_only))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
