# detection-engineering

Turn a threat report, hunt finding, or purple-team gap into a Sigma rule that has tests, a
measured false-positive rate, an honest ATT&CK tag, and a review date.

Part of [secops-claude-skills](../../README.md).

## Overview

Writing the query is the easy part. A detection is only finished when someone can answer
four questions about it: does it fire on real attacker telemetry, does it stay quiet during
normal business, what is an analyst supposed to *do* when it fires, and who re-checks it
when the log source changes. Most rules in most SIEMs cannot answer any of them.

The failure modes are specific and they compound. **Rules written straight in SPL or KQL**
are locked to one backend and skip the question of whether the data source even exists, so
half of them match nothing forever. **Silent exclusions** get added at 03:00 during an
incident with no comment, and because nobody knows what they hide, nobody ever removes
them. **Over-tagging** — tagging the whole kill chain of the report that inspired the rule
rather than the one behaviour the logic observes — quietly lies to the coverage dashboard
leadership reads. And **fabricated test data**, a hand-written log line that happens to
match, proves only that the author can type.

The skill is built around those four. Sigma is the source of truth and conversion happens
through a pipeline, so the rule is portable and the generated query is never hand-patched.
Filters are named and commented. The ATT&CK tag describes the logic, not the campaign. Two
unit tests — a true positive from real telemetry or a named public emulation test, and the
closest benign twin — are part of the deliverable, not a follow-up.

It also knows when to say no. An indicator list is a watchlist, not a rule. A query that
needs three more queries before an analyst can decide is a hunt, not an alert.

## What it does

1. Writes the requirement as one sentence and checks that an analyst action exists.
2. Confirms the logsource, fields, host coverage, and retention exist before any logic gets written.
3. Describes the behaviour at field level, then the benign twins that become `falsepositives:` and filters.
4. Authors the rule in Sigma, anchoring on constraints an attacker cannot cheaply change.
5. Lints it, tags ATT&CK for what the logic sees, and writes the true-positive and benign-twin tests.
6. Backtests, tunes with the safest lever, peer-reviews, and deploys with a record and a review date.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The eleven-step lifecycle Claude follows, the detection-package template, and the pitfalls |
| `scripts/sigma_lint.py` | Dependency-free Sigma linter: metadata, logsource, condition consistency, modifiers, tags, dates |
| `references/sigma-cheatsheet.md` | Rule skeleton, level guidance, tag namespaces, logsource taxonomy, modifiers, condition syntax, per-backend field names |
| `references/rule-review-checklist.md` | Six-section peer-review checklist (scope, data source, logic, tests, operational, safety) and the review outcome template |
| `references/false-positive-tuning.md` | How to measure noise, classify each FP population, and pick the safest tuning lever; stop-thresholds by level |
| `references/environment.md` | Your customization file: backend and pipeline, telemetry inventory, noise thresholds, reviewers, test-data locations |
| `examples/` | A passing rule, a deliberately broken rule, and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *this report describes schtasks persistence from temp, how would we catch that*

> *review this sigma rule, I think the filter is doing too much*

> *this rule fires 200 times a day on the backup agent, what do I tune*

> *the purple team got away with a service install last week, write me a detection*

### As a standalone tool

`sigma_lint.py` is plain Python with no dependencies — notably no `yaml`, since it parses
the subset of YAML that Sigma rules actually use. That makes it easy to drop into CI.

```bash
# One rule
python scripts/sigma_lint.py examples/good-rule.yml

# A whole rule directory, as a Markdown table for a PR comment
python scripts/sigma_lint.py examples/ --format md --no-info

# Warnings fail the run too
python scripts/sigma_lint.py rules/ --strict

# From stdin, machine-readable
cat rule.yml | python scripts/sigma_lint.py - --format json
```

A clean rule:

```
PASS   examples\good-rule.yml  (Scheduled Task Created From User-Writable Temp Directory): 0 error(s), 0 warning(s)

1 rule(s) checked, 0 error(s), 0 warning(s), 0 unreadable
```

The bundled `examples/bad-rule.yml` exists to be broken. It is the fastest way to see what
the linter is actually looking for:

```
FAIL   examples\bad-rule.yml  (Suspicious Thing): 11 error(s), 6 warning(s)
       ERROR   [id] id 'rule-0001' is not a UUID
       ERROR   [detection] condition references `selection3` which is not defined
       WARNING [detection] selection `selection2` is defined but not used in the condition
       ERROR   [detection] selection `selection` is wildcard-only ('*'); it matches every event
       WARNING [modifier] unknown modifier `contians` on `CommandLine|contians` in `selection2`
       ERROR   [tags] tag `attack.T1053` must be lower-case (e.g. attack.t1059.001)
       ERROR   [date] date '17/09/2026' is not YYYY-MM-DD
       ERROR   [falsepositives] missing falsepositives; list the benign activity that will trip this rule (or `Unlikely`)
```

That run exits 1, which is the point: the same command in CI blocks the merge. The typo'd
`contians` modifier and the condition pointing at a `selection3` that was never written are
exactly the mistakes a human reviewer skims past while thinking about logic.

The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 when the
input cannot be read or parsed (as opposed to 1, which means the rules parsed fine and
failed). If `sigma-cli` is installed, run `sigma check` alongside it for full-spec
validation.

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
./scripts/install.sh detection-engineering          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 detection-engineering         # Windows
./scripts/install.sh --project detection-engineering   # to ./.claude/skills
```

Requires Python 3.10+ for the linter. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the telemetry inventory in `references/environment.md`. It is a table of Sigma
logsources with a tick box, coverage, and the table or index each lives in. Filling it in
honestly is the single highest-value edit, because step 2 of the workflow reads it to
decide whether a rule is even possible — and a rule written for telemetry you do not
collect is worse than no rule, since it looks like coverage. The same file sets your
conversion target and pipeline, the noise thresholds that decide when tuning is done, the
status lifecycle and review cadence, and who reviews `high` and `critical` rules.

If your team uses custom logsource categories or extra top-level metadata keys, extend the
vocabulary sets at the top of `scripts/sigma_lint.py` (`STATUSES`, `LEVELS`, `MODIFIERS`,
`KNOWN_CATEGORIES`, `KNOWN_PRODUCTS`, `KNOWN_TOP_KEYS`) so the linter stops warning about
things that are correct here.

## Related skills

- Requirements arrive from [threat-intel-analysis](../threat-intel-analysis/),
  [threat-hunting](../threat-hunting/), [purple-team-exercise](../purple-team-exercise/),
  and [incident-report-writing](../incident-report-writing/)
- Indicator lists are watchlists, not rules: [ioc-extraction](../ioc-extraction/) and
  [siem-query-authoring](../siem-query-authoring/)
- Conversion targets, backtest queries, and platform specifics come from
  [siem-query-authoring](../siem-query-authoring/)
- Ambiguous technique mappings go to [mitre-attack-mapping](../mitre-attack-mapping/)
- The analyst triage note is consumed by [incident-triage](../incident-triage/)
- Automated response behind the alert is designed with
  [soar-playbook-design](../soar-playbook-design/)
- A rule that always needs manual context is a hunt: [threat-hunting](../threat-hunting/)
