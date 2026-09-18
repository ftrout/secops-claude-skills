# soar-playbook-design

Turn "can we automate this alert" into a reviewable, vendor-agnostic JSON playbook with
gated containment, rollback, idempotency, and a kill switch, checked by a linter that fails
the unsafe shapes. Design and review only; it never executes anything.

Part of [secops-claude-skills](../../README.md).

## Overview

Automation removes toil. It also removes the pause in which a human would have noticed
something was wrong, and the failures that follow are boringly predictable.

**A noisy detection becomes an action storm.** The rule was fine at five alerts a day and the
playbook was fine at five runs a day. The morning the rule misfires, four hundred laptops are
isolated and nobody can find the off switch. Rate limit at the trigger, cap targets per run,
and make the kill switch a documented one-liner that also says how to undo standing effects.

**Timeout is treated as approval.** An approval nobody answered must never proceed. Every
gate needs an `on_timeout` and an `on_reject` routing to a step that records "not approved"
and pages if needed, and that path must be in the test cases.

**Retries apply the action twice, and failures look like successes.** Two case tickets, two
firewall blocks, two password resets, so every state-changing step carries an
`idempotency_key` and the trigger a `dedupe_key`. Meanwhile a containment call that timed out
under `on_failure: continue` reads as a clean run while the account is still live, and the
reverse trap is an enrichment outage that aborts the run and leaves the alert unhandled when
the right answer is "open a case with what we have".

**Order gets encoded as a comment instead of as steps.** Password reset before session
revocation leaves a live refresh token; isolating before capturing memory loses the process
tree. The bundled account-response example encodes revoke, then reset, then remove
persistence as actual steps, the only form the platform will honour.

## What it does

1. Pins down the trigger, the outcome, and the explicit non-goals, defaulting to
   enrich-and-route rather than full resolution.
2. Lays out the graph in the standard order (parse, enrich, decide, gate, act, record, hand
   off), with every decision having a default branch that leads to a human.
3. Designs the safety properties explicitly: approval gates, timeouts, idempotency, rate
   limits, rollback, exclusions, and the kill switch.
4. Writes the definition as JSON against the schema, from the closest worked example.
5. Lints it, fixes every error, and reads every warning.
6. Translates to the target platform, then tests in dry-run and stages with containment set
   to approval-required before any auto path is enabled.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, the design-note output shape, and the pitfalls |
| `scripts/playbook_lint.py` | Safety and completeness linter for a playbook definition |
| `references/playbook-schema.md` | The v1.0 JSON shape: top level, trigger, step types, decisions, approvals, containment, expressions, metrics, testing |
| `references/platforms.md` | Concept map and per-platform translation for Sentinel automation rules and Logic Apps, Splunk SOAR, Cortex XSOAR, Tines, and Shuffle, with each platform's gotchas |
| `references/environment.md` | Your customization file: platform, integration and credential map, approver groups, exclusions, kill switches, metric thresholds |
| `examples/` | Three linted playbooks, one deliberately unsafe one, and the CI smoke manifest |

The three worked examples are the fastest way to understand the schema:

- `phishing-triage.json` (v1.3.0) enriches a user-reported email, auto-closes obvious clean
  mail, opens a case for the rest, and offers a mailbox purge as its one human-approved
  containment.
- `malicious-ip-containment.json` (v2.1.0) is the narrow auto-approval case: a single,
  high-confidence, non-allow-listed destination IP with a 24 h expiry auto-blocks; a CDN
  address, a corporate egress address, or a TI timeout all route to a human instead.
- `compromised-account-response.json` (v1.0.2) gathers sign-ins, MFA changes, inbox rules and
  consent grants, then after tier-2 approval revokes sessions, resets the password, and
  removes persistence in that order, with a partial-containment path that pages.

Each ships metrics and at least three test cases: a true positive that reaches the action, a
benign case that must not, and a fault case that exercises the failure path.

## Using it

### In Claude Code

You do not invoke it by name. Describe the automation:

> *can we auto-block the IPs from this C2 rule, or is that a terrible idea*

> *review this Logic App before I ship it, I think the approval path is wrong*

> *translate this XSOAR playbook to Sentinel automation rules*

### As a standalone tool

`playbook_lint.py` is standard library only, so it runs in CI as easily as in Claude.

```bash
# Lint a definition
python scripts/playbook_lint.py examples/phishing-triage.json

# Machine-readable, for a pipeline gate
python scripts/playbook_lint.py examples/phishing-triage.json --format json

# Warnings fail the build too
python scripts/playbook_lint.py examples/compromised-account-response.json --strict

# Markdown block to paste into the design note
cat examples/compromised-account-response.json | python scripts/playbook_lint.py - --format md
```

A clean playbook says so in one line:

```
pb-phishing-triage v1.3.0: 0 error(s), 0 warning(s)
```

The deliberately unsafe example shows what it catches (exit code 1, trimmed):

```
pb-bad-example v0.1.0: 7 error(s), 13 warning(s)
  [E] step isolate: missing on_failure (step id, or abort / escalate / continue)
  [E] step isolate: auto.enabled needs a justification of at least 30 characters explaining why no human gate is needed
  [E] step isolate: auto-approved containment must define rollback
  [E] step isolate: auto-approved containment must define auto.scope_limit (e.g. max_targets, exclude tags)
  [E] step decide: decision step needs a default branch for the unexpected case
  [E] step notify: next points to unknown step 'does_not_exist'
  [E] step orphan: unreachable from start
  [W] trigger: no rate_limit {max_runs, window_minutes}: a detection storm becomes an action storm
  [W] trigger: no kill_switch named: responders need a documented way to stop all runs
  [W] step isolate: no idempotency_key: a retried or duplicated run will apply the action twice
  [W] playbook: no testing.test_cases; add at least a true-positive and a benign case
```

Errors are the shapes that hurt at 03:00; warnings are the things you should have a reason
for omitting.

The script takes `--help`, reads `-` for stdin, writes to stdout, and uses three exit codes:
0 clean or warnings only, 1 when errors are found, 2 on bad input.

## Install

This skill ships with the plugin. Inside Claude Code:

```
/plugin marketplace add ftrout/secops-claude-skills
/plugin install secops-skills@secops-claude-skills
```

To install just this skill, copy the folder:

```bash
git clone https://github.com/ftrout/secops-claude-skills
cd secops-claude-skills
./scripts/install.sh soar-playbook-design            # POSIX, to ~/.claude/skills
.\scripts\install.ps1 soar-playbook-design           # Windows
./scripts/install.sh --project soar-playbook-design  # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the exclusions and guardrails block in `references/environment.md`: break-glass
accounts, service accounts, VIP groups, corporate and partner ranges that must never be
blocked, hosts that must never be auto-isolated, maximum auto-block TTL, maximum targets per
run. Those values are referenced from trigger filters and `scope_limit` fields, and they are
the difference between a playbook that contains an attacker and one that disables the account
you need to fix it with. Set the platform field in the same file too, since it selects the
section of `references/platforms.md` used for translation, and fill in the integration table
so a logical name like `edr` maps to a real connector with an isolate-only credential.

Change `references/playbook-schema.md` only if your platform needs extra fields, and keep the
gating rules as they are, because the linter enforces them. Adding your own reviewed
playbooks to `examples/` is the best long-term edit: new designs start from something that
already passed.

## Related skills

- Identity containment order comes from
  [identity-threat-investigation](../identity-threat-investigation/); host containment order
  and the triage that precedes automation come from [incident-triage](../incident-triage/)
- Detection noise found in the run metrics goes to
  [detection-engineering](../detection-engineering/)
- New enrichment needs go to [threat-intel-analysis](../threat-intel-analysis/)
