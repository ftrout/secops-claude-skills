# Hunt plan: <short title>

| Field | Value |
|---|---|
| Hunt ID | HUNT-<YYYY>-<NNN> |
| Owner | <name> |
| Date planned | <YYYY-MM-DD> |
| Trigger | <threat report / ATT&CK gap / anomaly / incident lesson / new data source> |
| Source link | <report URL, ticket, purple-team result> |
| Hunt type | hypothesis-driven / baseline / model-assisted |
| Priority | <high / medium / low> and why (threat relevance x feasibility x asset criticality) |

## Hypothesis

<One sentence: behaviour + population + data source.>
Example: "On workstations, an adversary has established persistence with a scheduled task
whose action lives in a user-writable directory; Sysmon 1 and Security 4698 would show it."

**Null result (what "false" looks like):** <e.g. only known updaters (Teams, OneDrive,
Chrome) and installer-created tasks; every remaining hit explained by an owner>

## ATT&CK mapping

| Tactic | Technique | Procedure(s) we expect | ATT&CK version |
|---|---|---|---|
| <Persistence TA0003> | <T1053.005 Scheduled Task> | schtasks /create with Temp/AppData action; task XML dropped directly | v17 |

## Scope

- Population: <workstations / servers / cloud account X / all users>
- Time window: <start> to <end> (UTC); baseline window: <start> to <end>
- Exclusions applied up front (labelled, not deleted): <machine accounts, SCCM, ...>
- Out of scope: <segments without telemetry, systems requiring approval>

## Data sources

| Source | Table / index | Fields needed | Coverage | Retention OK? |
|---|---|---|---|---|
| Sysmon 1 | <DeviceProcessEvents> | Image, CommandLine, ParentImage, User | <N of M hosts> | yes / no |
| Security 4698 | <SecurityEvent> | TaskName, TaskContent, SubjectUserName | | |

Gaps that limit the conclusion: <list or "none">

## Queries

Count-first, then rows. Built with `siem-query-authoring`.

```<lang>
<query 1: count by value / prevalence>
```

```<lang>
<query 2: rows for the rare subset>
```

Offline stacking (if exporting): `python scripts/stack.py export.csv --by <col> --group host --rare-below 1%`

## Expected benign volume

<What normal will look like and roughly how many hits: e.g. "~2,000 task creations/week,
95% from four updaters; expect 20 to 50 to review".>

## Analysis technique

<stacking / prevalence / baselining / clustering / sequence / outlier / enrichment>,
and the pivot plan: value -> hosts -> users -> parent process -> network.

## Success criteria

- [ ] Hypothesis confirmed (hand to `incident-triage`), or
- [ ] Rejected with coverage evidence (population and window fully queried), and
- [ ] Detection candidate or telemetry gap filed with `detection-engineering`
- [ ] Baseline / allow-list recorded

## Effort and timing

Estimated effort: <hours>. Runs during: <off-peak if the queries are heavy>.
Approvals needed: <none / data owner for mailbox content / ...>
