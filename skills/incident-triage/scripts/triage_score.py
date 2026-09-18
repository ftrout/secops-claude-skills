#!/usr/bin/env python3
"""Score an alert into a severity tier from five triage factors.

Model (see references/severity-matrix.md for the reasoning):

    exposure   = weighted mean of impact, asset_criticality, spread, data_sensitivity (each 1..5)
    score      = 100 * (exposure / 5) * (confidence / 5) ** confidence_exponent
    tier       = first tier whose min_score <= score, then floor/ceiling rules are applied

"How bad is it if true" times "how sure are we" is how an experienced analyst
thinks: a confirmed compromise of a lab box and a vague alert on a domain
controller should both land in the middle, not at the top. Weights, tiers,
labels, and the floor/ceiling rules live in a JSON config the team can edit
(default: references/severity-weights.json).

Standard library only. No network calls. Reads a JSON blob or flags, writes to stdout.

Usage:
    python triage_score.py --confidence 4 --impact 3 --asset-criticality 5 --spread 2 --data-sensitivity 3
    python triage_score.py --json alert.json --format md
    cat alert.json | python triage_score.py --json - --format json
    python triage_score.py --json alert.json --config my-weights.json
    python triage_score.py --show-config     # print the effective config and factor labels

Factor values may be integers 1..5 or the labels defined in the config (e.g. "high").
Optional JSON keys alert_id, title, and notes are echoed into the output.
Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

EXPOSURE_FACTORS = ["impact", "asset_criticality", "spread", "data_sensitivity"]
FACTORS = ["confidence", *EXPOSURE_FACTORS]
MAX_INPUT_BYTES = 1_000_000

DEFAULT_CONFIG: dict = {
    "scale_max": 5,
    "confidence_exponent": 1.0,
    "weights": {
        "impact": 1.2,
        "asset_criticality": 1.0,
        "spread": 0.8,
        "data_sensitivity": 0.8,
    },
    "tiers": [
        {"name": "P1", "min_score": 75, "label": "Critical: page on-call, incident commander now"},
        {"name": "P2", "min_score": 50, "label": "High: work immediately, escalate to tier 2 / IR"},
        {"name": "P3", "min_score": 25, "label": "Medium: work this shift, tier 1 owns"},
        {"name": "P4", "min_score": 0, "label": "Low: queue, tune, or close with note"},
    ],
    "floors": [
        {"when": {"confidence": 5, "impact": 5}, "min_tier": "P1",
         "reason": "confirmed business-critical impact is always P1"},
        {"when": {"confidence": 5, "asset_criticality": 5}, "min_tier": "P2",
         "reason": "confirmed activity on a crown-jewel asset is never below P2"},
        {"when": {"confidence": 4, "data_sensitivity": 5}, "min_tier": "P2",
         "reason": "likely-true activity touching regulated data has notification clocks attached"},
        {"when": {"confidence": 3, "spread": 5}, "min_tier": "P2",
         "reason": "plausible org-wide spread needs coordination regardless of per-host impact"},
    ],
    "ceilings": [
        {"when": {"confidence": 1}, "max_tier": "P4",
         "reason": "a probable false positive should be tuned, not escalated"},
        {"when": {"impact": 1, "confidence": 3}, "max_tier": "P3",
         "reason": "blocked before execution with no confirmation is a tuning task, not an incident"},
    ],
    "labels": {
        "confidence": {
            "1": "probably benign / matches a known false-positive pattern",
            "2": "unclear, benign explanation more likely than not",
            "3": "plausible either way, needs more data",
            "4": "likely true positive, one or two corroborating artifacts",
            "5": "confirmed: hands-on-keyboard, payload, or exfil observed",
        },
        "impact": {
            "1": "no effect: blocked/quarantined before execution",
            "2": "single low-privilege user or workstation affected",
            "3": "service degradation or a privileged user session",
            "4": "server/domain-level compromise or data access",
            "5": "business-critical outage, ransomware, or confirmed exfiltration",
        },
        "asset_criticality": {
            "1": "lab, test, or disposable asset",
            "2": "standard workstation",
            "3": "internal server or shared service",
            "4": "production, customer-facing, or admin workstation",
            "5": "crown jewel: domain controller, IdP, PKI, backups, payment, PHI/PII store",
        },
        "spread": {
            "1": "one host or one account",
            "2": "two to five hosts/accounts, one team",
            "3": "one site, VLAN, or business unit",
            "4": "multiple sites or business units",
            "5": "organization-wide or supply-chain / third-party involvement",
        },
        "data_sensitivity": {
            "1": "public or no data involved",
            "2": "internal, low sensitivity",
            "3": "confidential business data",
            "4": "customer PII, credentials, source code",
            "5": "regulated: PHI, PCI, financial, classified, or legal hold",
        },
    },
    "aliases": {
        "low": 1, "minimal": 1, "none": 1,
        "medium": 3, "moderate": 3, "unknown": 3,
        "high": 4, "likely": 4,
        "critical": 5, "confirmed": 5, "severe": 5,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: Path | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy without pickle
    if path is None:
        return cfg
    if not path.is_file():
        raise ValueError(f"config {path} is not a file")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("config file too large")
    try:
        user = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"config is not valid JSON: {exc}") from exc
    if not isinstance(user, dict):
        raise ValueError("config must be a JSON object")
    cfg = _deep_merge(cfg, user)
    if not cfg.get("tiers"):
        raise ValueError("config must define at least one tier")
    return cfg


def coerce_factor(name: str, raw, cfg: dict) -> int:
    """Accept 1..5 ints, numeric strings, or config-defined labels."""
    scale_max = int(cfg.get("scale_max", 5))
    if isinstance(raw, bool):
        raise ValueError(f"{name}: booleans are not valid factor values")
    if isinstance(raw, (int, float)):
        val = int(round(raw))
    elif isinstance(raw, str):
        s = raw.strip().lower()
        if s.lstrip("-").isdigit():
            val = int(s)
        elif s in cfg.get("aliases", {}):
            val = int(cfg["aliases"][s])
        else:
            raise ValueError(f"{name}: unknown value {raw!r}; use 1..{scale_max} or one of "
                             f"{sorted(cfg.get('aliases', {}))}")
    else:
        raise ValueError(f"{name}: unsupported type {type(raw).__name__}")
    if not 1 <= val <= scale_max:
        raise ValueError(f"{name}: {val} is outside 1..{scale_max}")
    return val


def tier_rank(cfg: dict, name: str) -> int:
    """0 = most severe tier (tiers are listed most severe first)."""
    names = [t["name"] for t in cfg["tiers"]]
    if name not in names:
        raise ValueError(f"tier {name!r} not defined in config tiers {names}")
    return names.index(name)


def _floor_matches(when: dict, factors: dict[str, int]) -> bool:
    """Floors fire when every listed factor is AT LEAST the listed value."""
    return all(factors.get(k, 0) >= int(v) for k, v in when.items())


def _ceiling_matches(when: dict, factors: dict[str, int]) -> bool:
    """Ceilings fire when every listed factor is AT MOST the listed value."""
    return all(factors.get(k, 99) <= int(v) for k, v in when.items())


def compute(factors: dict[str, int], cfg: dict) -> tuple[float, float, str, str, list[str]]:
    """Return (exposure_0_100, score_0_100, base_tier, final_tier, adjustments)."""
    scale_max = int(cfg.get("scale_max", 5))
    weights = {f: float(cfg["weights"].get(f, 1.0)) for f in EXPOSURE_FACTORS}
    total_w = sum(weights.values())
    if total_w <= 0:
        raise ValueError("weights must sum to a positive number")
    exposure = sum(weights[f] * factors[f] for f in EXPOSURE_FACTORS) / total_w / scale_max
    conf = (factors["confidence"] / scale_max) ** float(cfg.get("confidence_exponent", 1.0))
    score_val = round(100 * exposure * conf, 1)

    tiers = sorted(cfg["tiers"], key=lambda t: -float(t["min_score"]))
    base_tier = tiers[-1]["name"]
    for t in tiers:
        if score_val >= float(t["min_score"]):
            base_tier = t["name"]
            break

    final_tier = base_tier
    adjustments: list[str] = []
    for rule in cfg.get("floors", []):
        if _floor_matches(rule.get("when", {}), factors):
            if tier_rank(cfg, rule["min_tier"]) < tier_rank(cfg, final_tier):
                adjustments.append(f"raised to {rule['min_tier']}: {rule.get('reason', 'floor rule')}")
                final_tier = rule["min_tier"]
    for rule in cfg.get("ceilings", []):
        if _ceiling_matches(rule.get("when", {}), factors):
            if tier_rank(cfg, rule["max_tier"]) > tier_rank(cfg, final_tier):
                adjustments.append(f"capped at {rule['max_tier']}: {rule.get('reason', 'ceiling rule')}")
                final_tier = rule["max_tier"]
    return round(exposure * 100, 1), score_val, base_tier, final_tier, adjustments


def score(factors: dict[str, int], cfg: dict) -> dict:
    scale_max = int(cfg.get("scale_max", 5))
    weights = {f: float(cfg["weights"].get(f, 1.0)) for f in EXPOSURE_FACTORS}
    exposure, score_val, base_tier, final_tier, adjustments = compute(factors, cfg)

    # Which exposure factor pushes hardest each way (weighted distance from the midpoint).
    mid = (scale_max + 1) / 2
    push = {f: weights[f] * (factors[f] - mid) for f in EXPOSURE_FACTORS}
    dominant_high = max(push, key=lambda f: push[f])
    dominant_low = min(push, key=lambda f: push[f])

    # Sensitivity: what single one-step change would move the tier?
    movers: list[str] = []
    for f in FACTORS:
        for delta in (+1, -1):
            v = factors[f] + delta
            if not 1 <= v <= scale_max:
                continue
            alt_tier = compute(dict(factors, **{f: v}), cfg)[3]
            if alt_tier != final_tier:
                direction = "up" if tier_rank(cfg, alt_tier) < tier_rank(cfg, final_tier) else "down"
                movers.append(f"{f} {factors[f]}->{v} moves it {direction} to {alt_tier}")

    tier_label = next((t.get("label", "") for t in cfg["tiers"] if t["name"] == final_tier), "")
    labels = cfg.get("labels", {})
    return {
        "tier": final_tier,
        "tier_label": tier_label,
        "score": score_val,
        "exposure": exposure,
        "confidence_multiplier": round((factors["confidence"] / scale_max)
                                       ** float(cfg.get("confidence_exponent", 1.0)), 2),
        "base_tier": base_tier,
        "adjustments": adjustments,
        "factors": {f: {"value": factors[f],
                        "weight": weights.get(f, None),
                        "meaning": labels.get(f, {}).get(str(factors[f]), "")} for f in FACTORS},
        "dominant_high": dominant_high,
        "dominant_low": dominant_low,
        "what_would_change_it": movers,
    }


def render_md(result: dict, context: dict) -> str:
    lines: list[str] = []
    if context.get("alert_id") or context.get("title"):
        lines.append(f"**Alert:** {context.get('alert_id', '')} {context.get('title', '')}".rstrip() + "  ")
    lines += [f"**Severity: {result['tier']}** ({result['tier_label']})  ",
              f"**Score:** {result['score']} / 100 = exposure {result['exposure']} x confidence "
              f"{result['confidence_multiplier']} (base tier {result['base_tier']})",
              "", "| Factor | Value | Weight | Meaning |", "|---|---|---|---|"]
    for f, d in result["factors"].items():
        w = "multiplier" if d["weight"] is None else f"{d['weight']:g}"
        lines.append(f"| {f} | {d['value']} | {w} | {d['meaning']} |")
    lines += ["", "**Rationale**", ""]
    lines.append(f"- Exposure is pushed up most by `{result['dominant_high']}` and held down most by "
                 f"`{result['dominant_low']}`.")
    for adj in result["adjustments"]:
        lines.append(f"- Rule applied: {adj}.")
    if result["what_would_change_it"]:
        lines.append("- What would change the tier: " + "; ".join(result["what_would_change_it"]) + ".")
    else:
        lines.append("- No single one-step factor change moves the tier; this verdict is stable.")
    if context.get("notes"):
        lines.append(f"- Analyst notes: {context['notes']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", dest="json_in", help="JSON file with factor fields, or - for stdin")
    for f in FACTORS:
        ap.add_argument("--" + f.replace("_", "-"), dest=f, help=f"{f}: 1..5 or a config label")
    ap.add_argument("--config", type=Path,
                    default=Path(__file__).resolve().parent.parent / "references" / "severity-weights.json",
                    help="weights/tiers/labels JSON (default: references/severity-weights.json)")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--show-config", action="store_true", help="print the effective config and exit")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(args.config if args.config and args.config.is_file() else None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.show_config:
        print(json.dumps(cfg, indent=2))
        return 0

    blob: dict = {}
    if args.json_in:
        try:
            if args.json_in == "-":
                raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
            else:
                p = Path(args.json_in)
                if not p.is_file():
                    print(f"error: {p} is not a file", file=sys.stderr)
                    return 2
                raw = p.read_text(encoding="utf-8", errors="replace")
            if len(raw) > MAX_INPUT_BYTES:
                print("error: input too large", file=sys.stderr)
                return 2
            blob = json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"error: input is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(blob, dict):
            print("error: JSON input must be an object", file=sys.stderr)
            return 2

    # Flags override JSON values. Accept both snake_case and kebab-case keys in JSON.
    factors: dict[str, int] = {}
    missing: list[str] = []
    for f in FACTORS:
        raw = getattr(args, f)
        if raw is None:
            raw = blob.get(f, blob.get(f.replace("_", "-")))
        if raw is None:
            missing.append(f)
            continue
        try:
            factors[f] = coerce_factor(f, raw, cfg)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if missing:
        print(f"error: missing factors {missing}; supply via flags or JSON", file=sys.stderr)
        return 2

    try:
        result = score(factors, cfg)
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    context = {k: str(blob.get(k))[:500] for k in ("alert_id", "title", "notes") if blob.get(k)}
    if args.format == "json":
        out = dict(result)
        if context:
            out["context"] = context
        print(json.dumps(out, indent=2))
    else:
        print(render_md(result, context))
    return 0


if __name__ == "__main__":
    sys.exit(main())
