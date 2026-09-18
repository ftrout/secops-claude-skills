# log-forensics

Turn a pile of exports in four different formats and three different time zones into one
UTC super-timeline, with each claim tied to a log line and every gap stated plainly.

Part of [secops-claude-skills](../../README.md).

## Overview

The hard part of a log investigation is almost never finding the bad event. It is being able to
defend the order of events afterwards, and four things break that.

**Mixed time zones.** The single most common error. Windows Event Viewer exports local time with
no zone attached; IIS logs are already UTC; Apache carries an explicit offset; auditd is epoch;
the SIEM may re-stamp on ingest. Compare the raw strings and you get a "logon before the
phishing email" that is really an hour after it. Everything gets converted once, and the script
counts how many rows relied on an assumed zone so the report can say so.

**One source mistaken for the whole picture.** No Sysmon means no process-to-network events.
4688 without command-line auditing means you see `powershell.exe` and nothing else. auditd not
configured means no EXECVE. Absence of evidence in a source that could never have shown it is
not evidence of absence, and the note template has a Gaps section so that distinction survives.

**Evidence handled carelessly.** Screenshots instead of exports, CSVs opened and re-saved in
Excel (which silently rewrites timestamps and long numbers), no hash at collection.

**Stopping at "found it".** The first malicious event is rarely the first event. The workflow
pivots user → host → process → network → back to user, and only stops when a full pass adds
nothing new. And command lines, usernames, and messages inside logs were written by whoever ran
the command, the attacker included: quote them as evidence, never act on them.

## What it does

1. Writes the question down first, with the time window in UTC and a generous margin.
2. Preserves before analyzing: native exports, hashes at collection, a one-line custody note.
3. Chooses sources from the event references, and records which ones were not available.
4. Normalizes every timestamp to UTC, declaring the zone of any naive ones.
5. Merges everything into one sorted super-timeline, flags silences, and reads it end to end.
6. Pivots outward until the scope stops growing, corroborates each claim across independent
   sources, and hands off what belongs to other skills.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The eight-step workflow, the forensic note template, and the failure modes |
| `scripts/timeline_builder.py` | Multi-format merge, timestamp normalization to UTC, filtering, gap flagging |
| `references/windows-events.md` | Security/System/PowerShell/Task Scheduler/WMI/Defender event IDs, logon types, status codes |
| `references/sysmon.md` | Sysmon event IDs, key fields, and what each one answers |
| `references/linux-artifacts.md` | auth/secure, journal, auditd, wtmp/btmp, cron, systemd, shell history, SSH keys |
| `references/web-logs.md` | Apache/nginx/IIS/proxy formats, their time zones, and what attacks look like |
| `references/environment.md` | Your customization file: SIEM tables, audit policy, zones, custody, escalation |
| `examples/` | A Windows Security CSV, a Linux auth JSONL, an Apache access log, and the smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *build me a timeline from these three exports, they're in different time zones*

> *what happened on WS-FIN-07 between 5 and 7pm*

> *someone cleared the security log, what else can tell me what happened in that hour*

### As a standalone tool

The builder is plain Python with no dependencies. It accepts CSV/TSV, JSON arrays, JSON Lines,
and plain text logs (syslog, Apache/nginx, auditd, ISO-prefixed lines). Each input takes a
`--map` in the same position, `label=timestamp[,actor,action,detail[,host]]`; leave it empty
(`web=`) or omit it to let the script guess from common column names.

```bash
# Merge three formats; the Windows CSV has naive local timestamps (US Eastern, DST)
python scripts/timeline_builder.py examples/windows-security.csv examples/linux-auth.jsonl examples/web-access.log \
  --map "winsec=TimeCreated,SubjectUserName,EventID,Message,Computer" \
  --map "auth=@timestamp,user,program,message,host" --map "web=" \
  --assume-tz=-04:00 --format md --detail-max 60

# Narrow to a window and a pattern, emit CSV for a spreadsheet or the SIEM
python scripts/timeline_builder.py examples/windows-security.csv examples/linux-auth.jsonl \
  --assume-tz=-04:00 --grep "powershell|useradd|1102" --format csv \
  --from 2026-09-15T18:00:00Z --to 2026-09-15T19:00:00Z

# Surface silences: insert a row wherever nothing was logged for 30 minutes
python scripts/timeline_builder.py examples/windows-security.csv --assume-tz=-04:00 --flag-gaps 30 --format csv
```

Trimmed real output from the three-source merge (`--detail-max 60` to keep it narrow here):

```
timeline: 28 events emitted of 28 parsed (0 unparsed); range 2026-09-15T17:58:02.000Z .. 2026-09-15T21:30:00.000Z; naive timestamps assumed -04:00
  winsec           windows-security.csv kind=csv rows=10 parsed=10 unparsed=0 tz_assumed=10 fields={...}
  auth             linux-auth.jsonl kind=jsonl rows=10 parsed=10 unparsed=0 tz_assumed=0 fields={...}
  web              web-access.log kind=text rows=8 parsed=8 unparsed=0 tz_assumed=0

| timestamp_utc | source | host | actor | action | detail |
|---|---|---|---|---|---|
| 2026-09-15T18:01:15.000Z | winsec | WS-FIN-07.corp.yourcompany.example | j.doe | 4688 | A new process has been created. New Process Name: C:\Windows... |
| 2026-09-15T18:04:31.000Z | web | 203.0.113.77 |  | POST 200 | POST /uploads/img_2026.php HTTP/1.1 ua=python-requests/2.31 ... |
| 2026-09-15T18:05:11.000Z | auth | web-01 | deploy | sshd | Accepted password for deploy from 203.0.113.77 port 51422 ss... |
| 2026-09-15T18:47:10.000Z | winsec | WS-FIN-07.corp.yourcompany.example | j.doe | 1102 | The audit log was cleared. |
```

The summary goes to stderr and the timeline to stdout. `tz_assumed=10` is the number that
belongs in the report: ten Windows rows had no zone and were read as `-04:00`. The same source
IP appearing in the Windows RDP logons, the web POSTs, and the SSH session is the pivot the
timeline exists to make visible. The `--flag-gaps 30` run adds rows like the second one below,
and a silence right after an `1102 audit log cleared` is a finding, not a formatting quirk:

```
2026-09-15T18:47:10.000Z,windows-security,WS-FIN-07.corp.yourcompany.example,j.doe,1102,The audit log was cleared.
2026-09-15T18:47:10.000Z,[gap],,,gap,no events for 2.7 h (until 2026-09-15T21:30:00.000Z)
```

Other flags worth knowing: `--source` to keep only some labels, `--year` for syslog lines that
carry no year, `--keep-original` to retain the raw timestamp string, `--keep-unparsed` to append
rows whose timestamp could not be read, and `--limit`. The script takes `--help`, reads `-` for
stdin, writes to stdout, and exits 2 on bad input or when nothing could be parsed.

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
./scripts/install.sh log-forensics          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 log-forensics         # Windows
./scripts/install.sh --project log-forensics   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

`references/environment.md` is the only config file, and the section to fill in first is
**audit policy actually in force**: whether 4688 carries command lines, whether PowerShell
script block logging is on, whether Sysmon is deployed and with which config, whether auditd
rules are loaded. That table is what lets the analysis say "the source could not have shown
this" instead of "nothing happened", which is the difference between an honest report and a
wrong one.

Close behind it is the time-zone column per source, which decides the `--assume-tz` you pass to
each input, and the naming conventions (machine and service accounts, scanner IPs, backup
accounts, patch windows) that let known-benign volume be ruled out quickly rather than
re-investigated each time.

## Related skills

- Indicators go to [ioc-extraction](../ioc-extraction/); unknown binaries to
  [malware-triage](../malware-triage/)
- Account compromise signs go to
  [identity-threat-investigation](../identity-threat-investigation/); cloud control-plane
  events to [cloud-incident-investigation](../cloud-incident-investigation/)
- Observed behaviors map through [mitre-attack-mapping](../mitre-attack-mapping/); detection
  gaps go to [detection-engineering](../detection-engineering/); searches you need written go
  to [siem-query-authoring](../siem-query-authoring/)
- The finished timeline CSV feeds [incident-report-writing](../incident-report-writing/);
  severity and containment decisions go through [incident-triage](../incident-triage/)
