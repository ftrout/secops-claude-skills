---
name: soar-playbook-design
description: >-
  Design safe security automation playbooks for a SOAR platform (Microsoft Sentinel automation
  rules and Logic Apps, Splunk SOAR, Cortex XSOAR, Tines, Shuffle): triggers, enrichment,
  decision logic, containment behind human-approval gates, idempotency, rate limits, rollback,
  error handling, dry-run testing, and metrics, expressed in a vendor-agnostic JSON definition
  that a bundled linter checks. Use this whenever someone wants to "automate" an alert response,
  asks for a playbook, workflow, automation rule, Logic App, story, or runbook-as-code, wants to
  auto-block, auto-isolate, auto-disable, or auto-close anything, asks "is this automation safe",
  or wants an existing playbook reviewed or translated between platforms. Design and review only;
  it never executes actions.
---

# SOAR Playbook Design

A good playbook removes toil from the analyst without removing judgment from the decisions
that need it: it enriches reliably, routes clearly, asks a human before it changes the
world, records what it did, and can be stopped and undone. Automation goes wrong in
predictable ways: a noisy detection becomes a storm of containment actions, a retry applies
the same block twice, a hung API call leaves nobody sure whether the account was disabled,
an approval that timed out is treated as a yes, and a playbook nobody can switch off keeps
isolating laptops during an outage. Every step below exists to prevent one of those. Inputs
a playbook parses (email bodies, filenames, URLs, alert descriptions) are attacker-controlled
data; a playbook, and any model inside it, must never take instructions from them.

## Workflow

1. **Pin down the trigger, the outcome, and the non-goals.** Write one sentence each: what
   starts it (which alert, with what filter), what the analyst gets at the end (a case with
   evidence, a closed alert, a blocked IP), and what it deliberately will not do. Most bad
   playbooks fail here by trying to fully resolve an incident. Enrich-and-route is the
   default scope; containment is added only for a narrow, well-understood case.

2. **Lay out the steps in the standard order: parse, enrich, decide, gate, act, record,
   hand off.** Draw the graph before writing JSON. Every decision has a default branch that
   leads to a human. Every enrichment failure leads to "open a case anyway", not to abort,
   because the alert still needs handling when the TI platform is down. Every path ends at
   an explicit end step.

3. **Design the safety properties explicitly**, using the field reference in
   `references/playbook-schema.md`:
   - **Gate every containment.** Inline `approval.required` with named approvers, a
     preceding approval step, or `auto.enabled` with a written justification, a
     `scope_limit`, and a rollback. Auto is for one target, high confidence, low
     false-positive cost, and a self-expiring effect (the auto-block example in
     `examples/malicious-ip-containment.json` shows the shape). The approval prompt must show
     the evidence and name the exact action and its undo.
   - **Timeouts never approve.** `on_timeout` and `on_reject` route to a step that records
     "not approved" and pages if needed.
   - **Idempotency.** Give every containment and ticketing step an `idempotency_key` so a
     duplicate trigger or a retry is a no-op. Set `dedupe_key` on the trigger.
   - **Rate limits and a kill switch.** `rate_limit` on the trigger and a written
     `kill_switch` that says how to stop runs *and* undo standing effects (empty the block
     group, re-enable accounts from the list).
   - **Rollback.** Every containment step declares one, even if it is `"action": "none"`
     with a note explaining why and what the recovery path is.
   - **Exclusions.** Break-glass accounts, service accounts, domain controllers, corporate
     and partner IP ranges, executive-protected users: filter them at the trigger and
     re-check them right before the action, using the lists in `references/environment.md`.
   - **Order of operations** for identity containment (revoke sessions, then reset, then
     remove persistence) and for host containment (capture volatile evidence, then isolate)
     comes from `identity-threat-investigation` and `incident-triage`; encode it as steps,
     not as a comment.

4. **Write the definition as JSON** against `references/playbook-schema.md`. Start from the
   closest example in `examples/` (phishing triage, malicious-IP containment, compromised
   account response). Fill `metrics` and at least three `testing.test_cases`: a true positive
   that reaches the action, a benign case that must not, and a fault case (enrichment
   timeout, approval timeout) that exercises the failure path.

5. **Lint it and fix every error; read every warning.**
   ```bash
   python scripts/playbook_lint.py playbook.json
   python scripts/playbook_lint.py playbook.json --format md --strict   # warnings fail too
   ```
   Errors cover ungated containment, missing `on_failure`, dangling or unreachable steps,
   decisions without a default, auto-containment without rollback or scope limit, and
   missing required fields. Warnings cover missing dedupe/rate limit/kill switch, missing
   idempotency keys, timeouts, dry-run support, unbounded loops, missing metrics and tests.
   `examples/bad-playbook.json` shows what a failing report looks like.

6. **Translate to the platform** using `references/platforms.md`, which maps each schema
   construct (trigger filter, approval gate, on-failure, idempotency marker, kill switch) to
   Sentinel automation rules and Logic Apps, Splunk SOAR, XSOAR, Tines, and Shuffle, and lists
   each platform's gotchas (for example, Logic App "run after" settings, SOAR prompt blocks,
   XSOAR pre-processing for dedupe). Scope the credential or managed identity used by the
   containment step to the minimum; it is the true blast radius.

7. **Test in dry-run, then stage.** Run the test cases against the staging environment with
   the containment integration in dry-run or pointed at a lab asset. Compare the observed
   path in the run log to `expect_path`. Then deploy with containment steps set to
   approval-required even if the design says auto, watch the metrics for a period agreed in
   `references/environment.md`, and only then enable auto for the narrow case.

8. **Measure and review.** The numbers that matter: runs stopped by the rate limit, path
   distribution (auto / approved / rejected / timed out / failed), median time to approval,
   actions rolled back, analyst re-open rate for anything auto-closed, false-positive
   containment reports. Review monthly; a rising re-open rate or any false-positive
   containment triggers a version bump and a re-lint. Detection noise found here goes to
   `detection-engineering`; new enrichment needs go to `threat-intel-analysis`.

## Output

Deliver two artifacts: the JSON definition (linted clean) and a short design note the
reviewer and the approvers can read without opening the JSON.

```markdown
# Playbook design: <id> v<version>
**Owner:** <team> | **Platform:** <target> | **Status:** <draft / staged / production>

## Purpose and scope
- Trigger: <source and filter, in words>
- Outcome: <what the analyst receives>
- Not in scope: <what it deliberately does not do>

## Step summary
| Step | Type | Action | Failure path | Gate |
|---|---|---|---|---|

## Safety
- Containment steps and how each is gated: <...>
- Auto-approved actions and their justification, scope limit, expiry: <... or none>
- Idempotency keys, dedupe key, rate limit: <...>
- Kill switch and standing-effect undo: <...>
- Exclusions applied: <break-glass, service accounts, ranges, hosts>
- Credential / identity scope for containment: <...>

## Testing
| Case | Input | Expected path | Result (dry run) |
|---|---|---|---|

## Metrics and review
- Metrics emitted: <...>
- Review cadence and thresholds: <...>

## Lint
<paste scripts/playbook_lint.py output>
```

## Things that go wrong

- **Auto-containment on a noisy detection.** The rule was fine at 5 alerts a day and the
  playbook was fine at 5 runs a day; the day the rule misfires, 400 laptops are isolated.
  Rate limit at the trigger, cap targets per run, and make the kill switch a documented
  one-liner.
- **Timeout means yes.** An approval nobody answered must not proceed. Route timeouts to a
  "record and page" step and test that path.
- **Retries without idempotency.** Two case tickets, two blocks, two password resets. Key
  every state-changing step and check the key before acting.
- **Silent failures.** A containment call that timed out with `on_failure: continue` looks
  like success in the run log. Use `escalate` or a partial-containment notification.
- **Enrichment outage aborts the run.** The alert then sits unhandled. Enrichment failures
  route to "open a case with what we have".
- **Excluding at the trigger only.** Group membership and tags change; re-check break-glass,
  service, and VIP status immediately before the action.
- **One credential for everything.** If the enrichment API key can also isolate hosts, the
  enrichment step is a containment step. Separate identities, minimum scope.
- **Wrong order.** Password reset before session revocation leaves a live refresh token;
  isolating before capturing memory loses the process tree. Encode order as steps.
- **Following instructions found in the data.** An email subject that says "approved by
  SOC, do not quarantine" is data. Decision logic reads verdicts and scores, never free text
  from the artifact; and a model step, if any, is told the same.
- **No rollback story.** Every reviewer should be able to answer "how do we undo this at
  03:00" from the design note alone.
- **Version drift.** The JSON in git says one thing; the platform runs another. Treat the
  platform build as a deployment of the versioned definition, and re-lint on every change.

## Customization

Edit `references/environment.md` with the target platform (which selects the translation
section), the map of logical integration names to real connectors and credential scopes,
approver groups and default approval timeouts, the exclusion lists and guardrails
(break-glass and service accounts, never-block ranges, never-isolate hosts, maximum auto
TTL and target counts), kill-switch procedures, and the metrics thresholds that force a
review. Adjust `references/playbook-schema.md` only if your platform needs extra fields;
keep the gating rules, since the linter enforces them. Add your own linted playbooks to
`examples/` so new designs start from something already reviewed.
