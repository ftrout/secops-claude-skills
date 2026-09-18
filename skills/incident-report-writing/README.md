# incident-report-writing

Turn triage notes, bridge chat, and a pile of timestamps in four time zones into the document
the reader in front of you actually needs: a status update, an exec summary, a post-incident
report, a customer notice, or a blameless retro, with a normalized UTC timeline underneath.

Part of [secops-claude-skills](../../README.md).

## Overview

Incident writing fails in ways that are obvious in hindsight and invisible at 02:00.

**One document is written for everyone.** The board receives twenty pages of technical
narrative and reads none of it; the responders receive an exec summary and cannot act on it.
The audience decides the shape before a word is written, which is why this skill starts with
an audience matrix rather than a template.

**The timeline is assembled from memory in mixed time zones.** A two-hour offset error on one
entry turns "detected in fifteen minutes" into "the attacker was inside for two hours before
the alert fired", and those intervals are what the exec summary, the regulator, and the retro
all quote. The bundled script exists so that never happens.

**Confidence gets overstated early and retracted later.** A retraction in front of a
regulator costs far more than a cautious first statement. "We have confirmed X. We suspect Y
and are checking Z by 16:00Z" is the house style, and every number says whether it rests on
full logs, partial logs, or an estimate. Relatedly, "no data was accessed" is not a finding:
absence of evidence in logs you do not have is not evidence of absence.

**Clocks start before anyone asks about them.** Several regimes run from a *determination*
rather than from discovery, and interim reports are normal. The skill never decides whether
an obligation applies; it makes sure the question reaches counsel in the first hours with the
facts attached.

## What it does

1. Identifies the audience and the moment, then picks the document and cadence from the
   audience matrix.
2. Gathers facts with a source and a "when did we know this" for each, refusing to invent
   counts to make a section look finished.
3. Builds the timeline with the script: everything converted to UTC, sorted, T+ computed, and
   gaps, out-of-order rows, duplicates, assumed time zones, and unparseable rows flagged.
4. Runs the regulatory trigger questions early, logging each regime with its clock-start
   event, deadline, owner, and status.
5. Drafts from that audience's template, keeping confirmed and suspected apart in words.
6. Reviews for placeholders, live indicators, and UTC consistency, then routes through the
   reviewers and approvers table before anything leaves the organisation.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, the which-document-when table, and the pitfalls |
| `scripts/timeline_format.py` | Normalizes mixed-format event lists into a sorted UTC timeline with flags |
| `assets/status-update.md` | Numbered live-incident update: bottom line, since-last-update, impact, next steps, decisions needed, notifications, confidence |
| `assets/exec-summary.md` | One page for executives and the board: what happened, what it means for the business, what we did, what we need from you |
| `assets/post-incident-report.md` | Ten-section technical record: impact, timeline, root cause, detection assessment, containment, indicators, notifications, action items, limitations |
| `assets/lessons-learned.md` | Blameless retro agenda: decision walk-through, what went well and poorly, where we got lucky, owned actions |
| `references/audiences.md` | Per-audience matrix (question, length, template, cadence) plus drafting rules and timeline conventions |
| `references/regulatory-notification.md` | Trigger questions and a clocks table for ~18 regimes, with "verify with counsel" framing and an as-of date |
| `references/environment.md` | Your customization file: org profile, reviewers and approvers, cadence, conventions |
| `examples/` | A deliberately messy CSV timeline, a clean JSON one, and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the document you owe someone:

> *write the 09:00 update for INC-2026-0093, nothing has changed since 05:00*

> *the CEO wants a page on this by lunch and doesn't care about the malware*

> *do we have to notify anyone? EU customer emails, maybe 400 of them*

> *clean up this timeline, half of it is in local time*

### As a standalone tool

`timeline_format.py` is standard library only, so it runs outside Claude too.

```bash
# Markdown timeline table from a CSV, filling the year for syslog-style rows
python scripts/timeline_format.py examples/timeline.csv --assume-year 2026

# JSON array input, flag gaps over 12 hours, emit CSV
python scripts/timeline_format.py examples/timeline.json --format csv --gap-hours 12

# Non-standard column names, a fixed T+ reference, and an offset for naive timestamps
python scripts/timeline_format.py events.csv --map "timestamp=Time,action=Description" \
  --t0 2026-09-14T07:42:13Z --assume-tz +02:00

# JSON Lines from stdin
cat events.jsonl | python scripts/timeline_format.py - --input-format jsonl --format json
```

Real output from the bundled messy CSV, trimmed:

```
## Timeline (UTC, ISO 8601)

Events: 11 | Span: 2026-09-14T07:42:13Z to 2026-09-15T11:00:00Z (1d 03:17:47) | T+ relative to 2026-09-14T07:42:13Z
Flags: 2 gap(s) over 4 h, 1 out-of-order in source, 3 with assumed time zone, 1 duplicate(s), 1 unparsed

| # | Time (UTC) | T+ | Source | Actor | Action | Flags |
|---|---|---|---|---|---|---|
| 3 | 2026-09-14T09:06:55Z | +01:24:42 | Entra ID sign-in | j.doe | Successful sign-in from 198.51.100.23 (new ASN) |  |
| 6 | 2026-09-14T10:15:00Z | +02:32:47 | EDR | WS-4471 | Outbound connection to 203.0.113.56:443 every 60 s | out-of-order in source, tz assumed |
| 7 | 2026-09-14T15:30:00Z | +07:47:47 | SOC | analyst.k | Alert triaged as P2; host isolation approved | gap 05:15:00 |
| 10 | 2026-09-15T08:10:00Z | +1d 00:27:47 | IAM | iam.oncall | j.doe sessions revoked and password reset | duplicate |

### Unparsed timestamps (fix the source and re-run)

| Input row | Raw timestamp | Source | Action |
|---|---|---|---|
| 12 | yesterday afternoon | Helpdesk | User reported the email looked suspicious after the fact |
```

(An evidence column is present in the real output; dropped here for width.) The input held an
ISO timestamp with a `+02:00` offset, an epoch value, a US-style `09/14/2026 10:15:00 AM`, a
syslog `Sep 15 11:00:00` with no year, a duplicated row, and one entry typed as "yesterday
afternoon". Every one is converted or listed separately; nothing is silently dropped. The
05:15 gap is the question the report has to answer, and the sort of thing a hand-built table
hides.

The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input
(for example a `--map` that names a column the file does not have).

### The templates

The four files in `assets/` are skeletons to fill, not prose to paraphrase: each placeholder
is either filled or the line is deleted, and the review step searches for a stray `<` before
anything is sent. What fills them is the triage note and severity from
[incident-triage](../incident-triage/), the timeline from the script, indicator lists, ATT&CK
technique IDs with the version noted, notification tracker rows, and owned action items.

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
./scripts/install.sh incident-report-writing            # POSIX, to ~/.claude/skills
.\scripts\install.ps1 incident-report-writing           # Windows
./scripts/install.sh --project incident-report-writing  # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the organisation profile at the top of `references/environment.md`: legal entities
and countries, whether you are publicly listed, regulated sectors, the data categories you
hold, and whether you are controller or processor. That block decides which regimes the
regulatory checklist raises, so filling it turns a generic eighteen-row table into a short
list that applies to you. The same file holds the reviewers and approvers table that gates
every external document, and the `--gap-hours` and `--assume-tz` defaults the script uses.

Then adapt the four `assets/` templates to your house style and classification labels, and
add jurisdictions your counsel cares about to `references/regulatory-notification.md`,
keeping the "verify with counsel" framing and refreshing the as-of date.

## Related skills

- Triage notes and severity come from [incident-triage](../incident-triage/)
- Technique IDs come from [mitre-attack-mapping](../mitre-attack-mapping/); indicators go to
  [ioc-extraction](../ioc-extraction/) for a clean list
- Detection gaps go to [detection-engineering](../detection-engineering/); techniques with
  poor visibility go to [purple-team-exercise](../purple-team-exercise/)
- Attribution reasoning belongs in [threat-intel-analysis](../threat-intel-analysis/), not in
  the summary
