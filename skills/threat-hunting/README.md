# threat-hunting

Turn a threat report, an ATT&CK gap, or "something feels off" into a testable hypothesis,
count-first queries, a stacked long tail with every rare value explained, and a hunt report
that says how much of the estate you could actually see.

Part of [secops-claude-skills](../../README.md).

## Overview

"We hunted for X and found nothing" is the most common hunt output and the least useful
one, because on its own it is unfalsifiable. Nothing found on how many hosts? Over what
window? Was the data source even collecting? A null result is a legitimate and valuable
outcome — but only with a denominator attached.

The failures upstream of that are mechanical. A **keyword search dressed as a hunt**
("search for mimikatz") tests one procedure of one technique and misses every renamed
binary. **Stacking un-normalised values** puts every command line containing a GUID or a
username in the long tail, so the tail becomes the whole dataset and tells you nothing.
**Trusting count over prevalence** hides the actual signal: a beacon is frequent by design,
and what makes it interesting is that exactly one host does it. **Filtering exclusions away
instead of labelling them** destroys the arithmetic — once the backup agent's 1,190 hits
are dropped at query time, the report can never show that 1,204 hits became 14 worth
reviewing. And **explaining benign by assumption** ("probably the updater") is how a real
intrusion gets closed as noise.

So the workflow is built around a hypothesis that names a behaviour, a population, and a
data source; an expected benign volume written down *before* the query runs; exclusions
kept countable rather than filtered; prevalence as the primary rarity signal; and three
bins at the end — escalate, explained benign with evidence, accepted residual with a
reason. The explained-benign table is the part that compounds: next quarter's hunter starts
from your allow-list instead of rebuilding it.

Four outcomes count as success, and the plan says which one it is aiming at: an incident, a
hypothesis rejected with coverage evidence, a detection candidate or documented telemetry
gap, or a recorded baseline.

## What it does

1. Captures the trigger and picks the hunt type (hypothesis-driven, baseline, or model-assisted).
2. Writes the hypothesis and its null result, drawing on the hypothesis library when the trigger is a technique or report.
3. Maps to ATT&CK and checks data-source coverage, so a missing source produces a telemetry request rather than a false all-clear.
4. Estimates benign volume and chooses the analysis technique before writing a query.
5. Runs count-first queries, stacks the results, and reads the long tail by prevalence.
6. Pivots on and explains every rare value, then sorts into escalate / explained benign / accepted residual and writes the report.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The nine-step workflow, the minimal inline summary format, and the pitfalls |
| `scripts/stack.py` | Stack counting and long-tail analysis over CSV or JSONL, with prevalence and rarity flags |
| `references/hypothesis-library.md` | 64 concrete hypotheses across twelve ATT&CK tactics, each with technique ID, data source, analysis technique, and expected benign population |
| `references/methodology.md` | PEAK/TaHiTI framing, trigger-to-hypothesis, the six analysis techniques, benign-volume estimation, success criteria |
| `references/environment.md` | Your customization file: data sources and coverage, fleet size and rarity thresholds, known-benign populations, hand-offs |
| `assets/hunt-plan.md` | Pre-execution template: hypothesis and null result, ATT&CK mapping, scope, data sources, queries, expected benign volume, success criteria, effort |
| `assets/hunt-report.md` | Post-execution template: outcome, coverage table, results arithmetic, escalated findings, explained-benign table, hand-offs, lessons |
| `examples/` | A synthetic process-event CSV, a DNS JSONL export, and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *what stands out in this process export*

> *build me a hunt from this report, we have sysmon and dns*

> *is anyone in the estate running a remote access tool we didn't approve*

> *we've got a free afternoon, what's worth hunting this week*

### As a standalone tool

`stack.py` is plain Python with no dependencies. It reads a CSV (delimiter sniffed, header
required) or JSON Lines / JSON array, with nested keys addressed by dots.

```bash
# Stack a single field, prevalence by host, flag anything under 5% of rows
python scripts/stack.py examples/process_events.csv --by process --group host --rare-below 5%

# Parent/child combinations, long tail first, rare rows only
python scripts/stack.py examples/process_events.csv --by parent,process --group host --rare-only --order asc

# Nested JSONL field, flag anything seen on one host or fewer
python scripts/stack.py examples/dns.jsonl --by dns.query --group host --rare-groups 1

# Filter rows, drop the group samples
python scripts/stack.py examples/process_events.csv --by user --where host=WS-003 --sample-groups 0
```

Real output from the bundled sample:

```
note: csv input, 40 rows, 12 distinct value(s), 6 rare
**Rows:** 40  **Distinct:** 12  **Rare (< 5% or on <= 1 host(s)):** 6  **Shown:** 12

| process | count | percent | groups (host) | sample groups | rare |
|---|---|---|---|---|---|
| `outlook.exe` | 8 | 20.00% | 8 | WS-001, WS-002, WS-003 |  |
| `svchost.exe` | 8 | 20.00% | 8 | WS-001, WS-002, WS-003 |  |
| `backupagent.exe` | 6 | 15.00% | 6 | WS-001, WS-002, WS-003 |  |
| `powershell.exe` | 2 | 5.00% | 2 | WS-003, WS-005 |  |
| `anydesk.exe` | 1 | 2.50% | 1 | WS-007 | RARE |
| `schtasks.exe` | 1 | 2.50% | 1 | WS-003 | RARE |
```

The `groups` column is the one to read. `backupagent.exe` has a high count but spreads over
six hosts, which is an agent. `anydesk.exe` has a count of one on one host, which is a lead.
Stacking combinations sharpens it further — the parent/child run surfaces
`winword.exe -> cmd.exe` and `powershell.exe -> schtasks.exe`, both on WS-003, which is the
same intrusion seen twice.

The DNS export shows why count alone misleads:

```
| dns.query | count | percent | groups (host) | sample groups | rare |
|---|---|---|---|---|---|
| `outlook.office365.com` | 5 | 22.73% | 5 | WS-001, WS-002, WS-003 |  |
| `updates.evil-domain.example` | 5 | 22.73% | 1 | WS-003 | RARE |
| `a1b2c3d4e5f6a7b8.dyn-tunnel.example` | 1 | 4.54% | 1 | WS-002 | RARE |
```

Identical counts, opposite verdicts, and the difference is entirely in the `groups` column.

Other flags: `--lower` case-folds before counting, `--where COL!=VALUE` excludes rows and
is repeatable, `--top N` caps the rows shown, and `--format md|csv|json` changes the output
shape. The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad
input such as a missing file or an unknown column.

The two templates under `assets/` are filled in by hand or by Claude: `hunt-plan.md` before
execution (it is the plan that pins down the null result and the expected benign volume, so
you cannot rationalise afterwards), and `hunt-report.md` after (its results table forces the
arithmetic — total hits, labelled benign, reviewed, escalated, unexplained — and its
coverage table forces the denominator).

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
./scripts/install.sh threat-hunting          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 threat-hunting         # Windows
./scripts/install.sh --project threat-hunting   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the two coverage tables in `references/environment.md`: which data sources exist
with what host and account coverage, and which populations have no telemetry at all. Those
are what turn "nothing found" into "nothing found on 1,198 of 1,240 workstations over 14
days", and they are what lets the skill refuse a hunt it cannot actually answer. Nothing
else in the file matters as much.

Then set the fleet size and rarity defaults, which become the `--rare-below` and
`--rare-groups` values passed to `stack.py` (1% and a single group are sensible under a
couple of thousand endpoints and too noisy above), and fill in the known-benign populations
table — machine accounts, service accounts, scanners, the deployment system, the approved
remote-access tool. Those get labelled up front and kept countable, not filtered away.

`references/hypothesis-library.md` is meant to grow. Add hypotheses specific to your
environment using the same columns, and when one becomes a deployed detection, note the
rule ID next to it rather than deleting the row.

## Related skills

- Triggers arrive from [threat-intel-analysis](../threat-intel-analysis/),
  [mitre-attack-mapping](../mitre-attack-mapping/), and
  [purple-team-exercise](../purple-team-exercise/)
- Query syntax and the indicator-to-query script come from
  [siem-query-authoring](../siem-query-authoring/)
- Indicator lists are normalised by [ioc-extraction](../ioc-extraction/) on the way in and
  on the way out
- Confirmed activity goes straight to [incident-triage](../incident-triage/), before the
  write-up is finished
- A repeatable query with acceptable noise becomes a rule in
  [detection-engineering](../detection-engineering/), with the backtest numbers attached
- Coverage results go back to [mitre-attack-mapping](../mitre-attack-mapping/)
