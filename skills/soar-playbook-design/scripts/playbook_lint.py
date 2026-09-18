#!/usr/bin/env python3
"""Lint a vendor-agnostic SOAR playbook definition (JSON) for safety and completeness.

The schema is documented in references/playbook-schema.md. The linter checks the
things that hurt when an automation misbehaves at 03:00:

  errors (exit 1)
    * required top-level fields: schema_version, id, name, version, owner, description,
      trigger, start, steps
    * step ids unique; start, next, branches[].next, default, on_failure, and approval
      on_timeout/on_reject targets all resolve to real steps
    * every non-end step has an on_failure path (step id, or abort / escalate / continue)
    * every containment or remediation step is gated: approval.required is true with a
      non-empty approvers list, or the immediate predecessor is an approval step, or
      auto.enabled is true with a justification of at least 30 characters
    * auto-approved containment has a rollback and a scope_limit
    * decision steps have branches and a default
    * no unreachable steps; no dangling references
  warnings (exit 0, or 1 with --strict)
    * trigger has no dedupe_key, rate_limit, or kill_switch
    * containment step lacks idempotency_key, rollback, timeout_seconds, or dry_run_supported
    * containment step uses on_failure: continue, or retries without idempotency_key
    * integration step lacks timeout_seconds
    * loops without max_iterations on any step in the cycle
    * no explicit end step; no metrics; no test cases; approval without timeout handling

Standard library only. No network access. Reads a JSON file or - for stdin.

Usage:
    python playbook_lint.py playbook.json
    python playbook_lint.py playbook.json --format json
    python playbook_lint.py playbook.json --strict
    cat playbook.json | python playbook_lint.py - --format md

Exit code 0 when clean (or warnings only), 1 when errors are found, 2 on bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REQUIRED_TOP = ["schema_version", "id", "name", "version", "owner", "description", "trigger", "start", "steps"]
STEP_TYPES = {"enrichment", "decision", "containment", "remediation", "notification", "ticketing",
              "approval", "transform", "wait", "end"}
DESTRUCTIVE = {"containment", "remediation"}
INTEGRATION_TYPES = {"enrichment", "containment", "remediation", "notification", "ticketing", "transform"}
FAILURE_KEYWORDS = {"abort", "escalate", "continue"}
TRIGGER_TYPES = {"alert", "incident", "indicator", "schedule", "webhook", "manual"}
MAX_BYTES = 5_000_000
MAX_STEPS = 500
MIN_JUSTIFICATION = 30


class Report:
    def __init__(self) -> None:
        self.errors: list[dict] = []
        self.warnings: list[dict] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append({"level": "error", "where": where, "message": msg})

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append({"level": "warning", "where": where, "message": msg})


def _is_nonempty_str(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _targets(step: dict) -> list[tuple[str, str]]:
    """All (field, target_step_id) references from a step, excluding keywords."""
    out: list[tuple[str, str]] = []
    if _is_nonempty_str(step.get("next")):
        out.append(("next", step["next"]))
    for i, br in enumerate(step.get("branches") or []):
        if isinstance(br, dict) and _is_nonempty_str(br.get("next")):
            out.append((f"branches[{i}].next", br["next"]))
    if _is_nonempty_str(step.get("default")):
        out.append(("default", step["default"]))
    of = step.get("on_failure")
    if _is_nonempty_str(of) and of not in FAILURE_KEYWORDS:
        out.append(("on_failure", of))
    # Inline gate on a containment step: approval.on_timeout / approval.on_reject.
    appr = step.get("approval")
    if isinstance(appr, dict):
        for key in ("on_timeout", "on_reject"):
            v = appr.get(key)
            if _is_nonempty_str(v) and v not in FAILURE_KEYWORDS:
                out.append((f"approval.{key}", v))
    # Stand-alone approval step: the same fields live at step level.
    if step.get("type") == "approval":
        for key in ("on_timeout", "on_reject"):
            v = step.get(key)
            if _is_nonempty_str(v) and v not in FAILURE_KEYWORDS:
                out.append((key, v))
    return out


def lint(pb: dict) -> Report:
    rep = Report()

    for key in REQUIRED_TOP:
        if key not in pb or pb[key] in ("", None, [], {}):
            rep.error("playbook", f"missing required field '{key}'")

    trig = pb.get("trigger")
    if isinstance(trig, dict):
        ttype = trig.get("type")
        if ttype not in TRIGGER_TYPES:
            rep.error("trigger", f"type {ttype!r} must be one of {sorted(TRIGGER_TYPES)}")
        if not _is_nonempty_str(trig.get("dedupe_key")):
            rep.warn("trigger", "no dedupe_key: the same alert can start the playbook repeatedly")
        rl = trig.get("rate_limit")
        if not (isinstance(rl, dict) and isinstance(rl.get("max_runs"), int) and rl.get("max_runs", 0) > 0
                and isinstance(rl.get("window_minutes"), (int, float)) and rl.get("window_minutes", 0) > 0):
            rep.warn("trigger", "no rate_limit {max_runs, window_minutes}: a detection storm becomes an action storm")
        if not _is_nonempty_str(trig.get("kill_switch")):
            rep.warn("trigger", "no kill_switch named: responders need a documented way to stop all runs")
    elif "trigger" in pb:
        rep.error("trigger", "trigger must be an object")

    steps = pb.get("steps")
    if not isinstance(steps, list):
        if "steps" in pb:
            rep.error("steps", "steps must be an array")
        return rep
    if len(steps) > MAX_STEPS:
        rep.error("steps", f"too many steps ({len(steps)} > {MAX_STEPS})")
        return rep

    by_id: dict[str, dict] = {}
    for i, st in enumerate(steps):
        where = f"steps[{i}]"
        if not isinstance(st, dict):
            rep.error(where, "step must be an object")
            continue
        sid = st.get("id")
        if not _is_nonempty_str(sid):
            rep.error(where, "step has no id")
            continue
        if sid in by_id:
            rep.error(where, f"duplicate step id {sid!r}")
            continue
        by_id[sid] = st

    start = pb.get("start")
    if _is_nonempty_str(start) and start not in by_id:
        rep.error("start", f"start step {start!r} does not exist")

    # Predecessor map for the "approval step immediately before" rule.
    preds: dict[str, set[str]] = {sid: set() for sid in by_id}
    for sid, st in by_id.items():
        for _, tgt in _targets(st):
            if tgt in preds:
                preds[tgt].add(sid)

    for sid, st in by_id.items():
        where = f"step {sid}"
        stype = st.get("type")
        if not _is_nonempty_str(st.get("name")):
            rep.error(where, "missing name")
        if stype not in STEP_TYPES:
            rep.error(where, f"type {stype!r} must be one of {sorted(STEP_TYPES)}")
            continue

        for field, tgt in _targets(st):
            if tgt not in by_id:
                rep.error(where, f"{field} points to unknown step {tgt!r}")

        if stype == "end":
            if st.get("next") or st.get("branches"):
                rep.warn(where, "end step should not have next/branches")
            continue

        of = st.get("on_failure")
        if not _is_nonempty_str(of):
            rep.error(where, "missing on_failure (step id, or abort / escalate / continue)")
        elif of == "continue" and stype in DESTRUCTIVE:
            rep.warn(where, "on_failure: continue on a containment step hides a failed action from the analyst")

        if stype == "decision":
            branches = st.get("branches")
            if not (isinstance(branches, list) and branches):
                rep.error(where, "decision step needs a non-empty branches array")
            else:
                for j, br in enumerate(branches):
                    if not isinstance(br, dict) or not _is_nonempty_str(br.get("when")) or not _is_nonempty_str(br.get("next")):
                        rep.error(where, f"branches[{j}] needs 'when' and 'next'")
            if not _is_nonempty_str(st.get("default")):
                rep.error(where, "decision step needs a default branch for the unexpected case")
        elif stype not in ("wait", "approval") and not _is_nonempty_str(st.get("next")) and not st.get("branches"):
            rep.error(where, "non-terminal step has no next; point it at an end step explicitly")

        if stype in INTEGRATION_TYPES:
            if not _is_nonempty_str(st.get("action")):
                rep.error(where, f"{stype} step needs an action")
            if not isinstance(st.get("timeout_seconds"), (int, float)) or st.get("timeout_seconds", 0) <= 0:
                rep.warn(where, "no timeout_seconds: a hung integration call stalls the whole run")

        if stype == "approval":
            appr = st.get("approval") if isinstance(st.get("approval"), dict) else st
            if not (isinstance(appr.get("approvers"), list) and appr.get("approvers")):
                rep.error(where, "approval step needs a non-empty approvers list")
            if not isinstance(appr.get("timeout_minutes"), (int, float)):
                rep.warn(where, "approval has no timeout_minutes; a request nobody answers should expire")
            if not _is_nonempty_str(appr.get("on_timeout")):
                rep.warn(where, "approval has no on_timeout; default should be abort, never auto-approve")
            if not _is_nonempty_str(appr.get("on_reject")) and not _is_nonempty_str(st.get("next")):
                rep.warn(where, "approval has no on_reject path")

        if stype in DESTRUCTIVE:
            _lint_destructive(rep, where, sid, st, by_id, preds)

    # Reachability from start.
    if _is_nonempty_str(start) and start in by_id:
        seen: set[str] = set()
        stack = [start]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for _, tgt in _targets(by_id[cur]):
                if tgt in by_id and tgt not in seen:
                    stack.append(tgt)
        for sid in by_id:
            if sid not in seen:
                rep.error(f"step {sid}", "unreachable from start")

        # Cycles: any back edge in DFS. Loops are allowed only with max_iterations somewhere on the loop.
        colour: dict[str, int] = {}
        path: list[str] = []

        def dfs(node: str) -> None:
            colour[node] = 1
            path.append(node)
            for _, tgt in _targets(by_id[node]):
                if tgt not in by_id:
                    continue
                if colour.get(tgt) == 1:
                    loop = path[path.index(tgt):]
                    if not any(isinstance(by_id[n].get("max_iterations"), int) for n in loop):
                        rep.warn(f"step {tgt}", f"loop {' -> '.join(loop + [tgt])} has no max_iterations on any step")
                elif colour.get(tgt) is None:
                    dfs(tgt)
            path.pop()
            colour[node] = 2

        dfs(start)

    if not any(st.get("type") == "end" for st in by_id.values()):
        rep.warn("steps", "no explicit end step; terminal state is implicit")
    if not pb.get("metrics"):
        rep.warn("playbook", "no metrics listed; you will not know if the playbook helps or hurts")
    testing = pb.get("testing")
    if not (isinstance(testing, dict) and isinstance(testing.get("test_cases"), list) and testing["test_cases"]):
        rep.warn("playbook", "no testing.test_cases; add at least a true-positive and a benign case")
    elif not testing.get("dry_run_supported"):
        rep.warn("playbook", "testing.dry_run_supported is not true; run new versions in dry-run first")
    return rep


def _lint_destructive(rep: Report, where: str, sid: str, st: dict, by_id: dict, preds: dict) -> None:
    appr = st.get("approval") if isinstance(st.get("approval"), dict) else {}
    auto = st.get("auto") if isinstance(st.get("auto"), dict) else {}
    inline_gate = appr.get("required") is True
    pred_gate = any(by_id[p].get("type") == "approval" for p in preds.get(sid, ()))
    is_auto = auto.get("enabled") is True

    if inline_gate and is_auto:
        rep.error(where, "both approval.required and auto.enabled are true; pick one")
    if inline_gate:
        if not (isinstance(appr.get("approvers"), list) and appr.get("approvers")):
            rep.error(where, "approval.required is true but approvers is empty")
        if not isinstance(appr.get("timeout_minutes"), (int, float)):
            rep.warn(where, "approval has no timeout_minutes")
        if not _is_nonempty_str(appr.get("on_timeout")):
            rep.warn(where, "approval has no on_timeout; default should be abort, never auto-approve")
        if not _is_nonempty_str(appr.get("on_reject")):
            rep.warn(where, "approval has no on_reject path")
    elif is_auto:
        just = auto.get("justification")
        if not _is_nonempty_str(just) or len(just.strip()) < MIN_JUSTIFICATION:
            rep.error(where, f"auto.enabled needs a justification of at least {MIN_JUSTIFICATION} characters "
                             "explaining why no human gate is needed")
        if not st.get("rollback"):
            rep.error(where, "auto-approved containment must define rollback")
        if not isinstance(auto.get("scope_limit"), dict) or not auto["scope_limit"]:
            rep.error(where, "auto-approved containment must define auto.scope_limit (e.g. max_targets, exclude tags)")
    elif pred_gate:
        pass  # gated by a preceding approval step
    else:
        rep.error(where, f"{st.get('type')} step has no approval gate: set approval.required with approvers, "
                         "precede it with an approval step, or mark auto.enabled with justification")

    if not _is_nonempty_str(st.get("idempotency_key")):
        rep.warn(where, "no idempotency_key: a retried or duplicated run will apply the action twice")
    if not st.get("rollback"):
        rep.warn(where, "no rollback defined: every containment needs a documented undo")
    if st.get("dry_run_supported") is not True:
        rep.warn(where, "dry_run_supported is not true: this step cannot be exercised safely in tests")
    if isinstance(st.get("retries"), int) and st["retries"] > 0 and not _is_nonempty_str(st.get("idempotency_key")):
        rep.warn(where, "retries > 0 without idempotency_key can duplicate the action")
    if not _is_nonempty_str(st.get("integration")):
        rep.warn(where, "no integration named; the platform mapping in references/platforms.md needs it")


# --------------------------------------------------------------------------- output

def render_text(pb: dict, rep: Report) -> str:
    head = f"{pb.get('id', '?')} v{pb.get('version', '?')}: {len(rep.errors)} error(s), {len(rep.warnings)} warning(s)"
    lines = [head]
    for item in rep.errors + rep.warnings:
        lines.append(f"  [{item['level'][0].upper()}] {item['where']}: {item['message']}")
    return "\n".join(lines)


def render_md(pb: dict, rep: Report) -> str:
    lines = [f"## Lint: {pb.get('name', pb.get('id', '?'))} (v{pb.get('version', '?')})", "",
             f"**Result:** {'FAIL' if rep.errors else 'PASS'} with {len(rep.errors)} error(s) and {len(rep.warnings)} warning(s)", ""]
    if rep.errors or rep.warnings:
        lines += ["| Level | Where | Message |", "|---|---|---|"]
        for item in rep.errors + rep.warnings:
            msg = item["message"].replace("|", "\\|")
            lines.append(f"| {item['level']} | {item['where']} | {msg} |")
    return "\n".join(lines)


def render_json(pb: dict, rep: Report) -> str:
    return json.dumps({"playbook": pb.get("id"), "version": pb.get("version"),
                       "ok": not rep.errors, "errors": rep.errors, "warnings": rep.warnings}, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="playbook JSON file, or - for stdin")
    ap.add_argument("--format", choices=["text", "json", "md"], default="text")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors for the exit code")
    args = ap.parse_args(argv)

    try:
        if args.input == "-":
            raw = sys.stdin.read(MAX_BYTES + 1)
        else:
            p = Path(args.input)
            if not p.is_file():
                print(f"error: {p} is not a file", file=sys.stderr)
                return 2
            raw = p.read_text(encoding="utf-8", errors="replace")
        if len(raw) > MAX_BYTES:
            print("error: input too large", file=sys.stderr)
            return 2
        pb = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(pb, dict):
        print("error: playbook must be a JSON object", file=sys.stderr)
        return 2

    rep = lint(pb)
    out = {"text": render_text, "md": render_md, "json": render_json}[args.format](pb, rep)
    print(out)
    if rep.errors or (args.strict and rep.warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
