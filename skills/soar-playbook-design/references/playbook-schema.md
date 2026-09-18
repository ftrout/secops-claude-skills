# Playbook definition schema (v1.0)

A vendor-agnostic JSON shape for describing a SOAR playbook precisely enough to review,
lint, and translate. It is a *design* artifact: `scripts/playbook_lint.py` checks it, and
`references/platforms.md` says how each construct maps to Sentinel, Splunk SOAR, XSOAR,
Tines, and Shuffle. Nothing here executes anything.

Three worked examples live in `examples/`: `phishing-triage.json` (enrichment with one
gated containment), `malicious-ip-containment.json` (a narrow auto-approved block with a
human path for everything else), and `compromised-account-response.json` (ordered
containment with per-step gates). `examples/bad-playbook.json` shows what the linter rejects.

## Top level

| Field | Required | Type | Meaning |
|---|---|---|---|
| `schema_version` | yes | string | `"1.0"` |
| `id` | yes | string | Stable identifier, `pb-<kebab-name>`; referenced by other playbooks and the kill switch |
| `name` | yes | string | Human title |
| `version` | yes | string | Semantic version; bump on any change to steps or gates |
| `owner` | yes | string | Team or mailbox accountable for it |
| `description` | yes | string | What it does, what it deliberately does not do, and what it contains |
| `tags` | no | list | Free-form labels for catalogues |
| `trigger` | yes | object | See Trigger |
| `inputs` | no | list | `{name, type, required, notes}`; declare which inputs are attacker-controlled |
| `start` | yes | string | Id of the first step |
| `steps` | yes | list | See Step |
| `metrics` | no (warned) | list | Metric names the platform should emit; see Metrics |
| `testing` | no (warned) | object | `{dry_run_supported, test_cases[]}`; see Testing |

## Trigger

| Field | Required | Meaning |
|---|---|---|
| `type` | yes | `alert`, `incident`, `indicator`, `schedule`, `webhook`, `manual` |
| `source` | yes | Where it comes from, e.g. `siem:rule:<name>`, `edr:detection`, `idp:risk-detection` |
| `filter` | no | Condition expression that must be true for the run to start; put exclusions here (break-glass accounts, lab ranges) |
| `dedupe_key` | warned | Field whose value collapses repeated triggers into one run (message_id, destination_ip, user) |
| `rate_limit` | warned | `{max_runs, window_minutes}`; caps runs per window so a detection storm cannot become an action storm |
| `kill_switch` | warned | Text: exactly how a responder stops all runs and undoes the standing effect (e.g. empty a firewall group) |

The linter warns rather than errors on `dedupe_key`, `rate_limit`, and `kill_switch`
because pure-enrichment playbooks can live without them; anything with a containment step
should have all three.

## Step (common fields)

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique within the playbook; used by `next`, `on_failure`, branches |
| `name` | yes | Human label shown in run logs and approval prompts |
| `type` | yes | `enrichment`, `transform`, `decision`, `approval`, `containment`, `remediation`, `notification`, `ticketing`, `wait`, `end` |
| `action` | integration types | Platform-neutral verb, `<integration>.<verb>` (`edr.isolate_host`, `mail.purge_message`); mapped per platform |
| `integration` | warned on containment | Logical name of the connector or app; `environment.md` maps logical names to real assets |
| `inputs` | no | Object of literal values and `{{step.field}}` references |
| `next` | non-terminal | Id of the next step. Decisions use `branches` + `default` instead |
| `on_failure` | all except `end` | Step id, or `abort` (stop, mark failed), `escalate` (stop, page the owner), `continue` (log and move on). `continue` is only right for notifications |
| `timeout_seconds` | warned for integration types | Hard stop for the call; the step then fails and `on_failure` applies |
| `retries` | no | Integer; only safe with an `idempotency_key` |
| `max_iterations` | for loops | Bounds a cycle; the linter warns about loops with no bound |

### Decision steps

`branches`: ordered list of `{when, next}`; the first true `when` wins. `default` is
required so an unexpected value has a defined, usually conservative, path. Conditions are
written as readable expressions over step outputs (`enrich.malicious_score >= 0.9`); each
platform has its own syntax and the translation is mechanical.

### Approval steps (stand-alone)

```json
{"id": "approve", "type": "approval", "name": "...", "approvers": ["soc-tier2-oncall"],
 "timeout_minutes": 45, "on_timeout": "notify_no_action", "on_reject": "notify_no_action",
 "prompt": "What the approver sees, with the evidence and the exact action.", "on_failure": "escalate", "next": "act"}
```

The step that follows an approval step is considered gated by it. `on_timeout` must never
lead to the action; default to a path that records "not approved". The prompt should show
the evidence and name the precise action and its rollback, because an approver who is
paged at 03:00 decides on what is in front of them.

### Containment and remediation steps

Anything that changes state outside the SOAR platform: isolate, block, disable, revoke,
purge, reset, delete, quarantine. Every one must be gated in exactly one of three ways:

1. **Inline gate**: `"approval": {"required": true, "approvers": [...], "timeout_minutes": n, "on_timeout": "<step>", "on_reject": "<step>"}`.
2. **Preceding approval step** (the immediate predecessor has `type: approval`).
3. **Auto with justification**: `"auto": {"enabled": true, "justification": "<at least 30 characters>", "scope_limit": {...}}` plus a `rollback`. The justification states the false-positive cost, why it is acceptable, and how the effect expires or is undone. `scope_limit` bounds the blast radius (`max_targets`, `exclude_classifications`, `ttl_hours_max`, `exclude_tags`).

Also on every containment step:

| Field | Level | Why |
|---|---|---|
| `idempotency_key` | warned | A template such as `block:{{inputs.destination_ip}}`; a re-run or duplicate trigger with the same key must be a no-op |
| `rollback` | warned (error when auto) | `{action, inputs, window_days | auto_expire_hours | notes}`; `"action": "none"` with `notes` is acceptable for irreversible actions like session revocation, so the reviewer sees it was considered |
| `dry_run_supported` | warned | `true` means the integration accepts a dry-run flag or the platform can stub it; needed for testing |
| `timeout_seconds` | warned | Hung containment calls are the usual cause of "did it happen or not" |

### Other step types

- `enrichment`: read-only lookups. Failures should route to a human path, not abort, because the alert still needs handling.
- `transform`: parse, score, format. Parsing attacker-controlled input (emails, filenames, URLs) happens here; treat the content as data and never as instructions to the playbook or to a model.
- `notification`: chat, email, page. Usually `on_failure: continue`.
- `ticketing`: create or update a case. Use an `idempotency_key` so retries do not create duplicate cases.
- `wait`: pause for a duration or an event; declare `timeout_seconds`.
- `end`: explicit terminal. Have one; implicit ends hide unfinished branches.

## Expressions and references

`{{inputs.<name>}}` reads a trigger input; `{{<step id>.<field>}}` reads a step output;
`{{config.<name>}}` reads a value from the platform's configuration store (corporate ranges,
exclusion lists). Keep expressions simple and readable; complex logic belongs in a
`transform` step where it can be unit-tested.

## Metrics

Declare the names; the platform emits them. Useful defaults: runs per day, runs stopped
by rate limit, path taken (auto / approved / rejected / timed out / failed), median time to
approval, containment actions applied and rolled back, false positives reported by
analysts, analyst re-open rate for anything auto-closed. If a playbook auto-closes alerts,
the re-open rate is the single number that tells you whether it is safe.

## Testing

```json
"testing": {"dry_run_supported": true,
 "test_cases": [{"name": "...", "input": {...} | "path/to/sample", "fault": "<step>:timeout", "expect_path": ["step", "step"]}]}
```

At least three cases: a true positive that should reach the action, a benign case that
must not, and a fault case (enrichment down, approval timeout) that shows the failure
path. `expect_path` is the ordered list of step ids the run should traverse, which is
checkable on every platform's run log.

## Versioning and review

Bump `version` on any change to steps, gates, filters, or scope limits. Review is a pull
request against the JSON with the lint output attached; the reviewer checks the gates and
the rollback for each containment step, not the formatting. Keep the previous version
deployable so a bad release can be rolled back like any other software.
