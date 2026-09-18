# Hunt report: <short title>

| Field | Value |
|---|---|
| Hunt ID | HUNT-<YYYY>-<NNN> (plan: <link>) |
| Owner | <name> |
| Dates | planned <YYYY-MM-DD>, executed <YYYY-MM-DD> to <YYYY-MM-DD> |
| Hypothesis | <one sentence, copied from the plan> |
| ATT&CK | <tactic / technique IDs, version> |
| Outcome | **confirmed** / **rejected with evidence** / **inconclusive (coverage gap)** |
| Effort | <hours> |

## Summary (three sentences)

<What was hunted, what was found, what changes as a result.>

## Coverage

| Source | Population queried | Window | Hosts/accounts with data | Gaps |
|---|---|---|---|---|
| <Sysmon 1> | <1,240 workstations> | <2026-09-01 to 2026-09-15 UTC> | <1,198 (96.6%)> | <42 hosts without Sysmon; list attached> |

Queries run (final versions): <link to saved queries or inline below>

## Results

| Metric | Value |
|---|---|
| Total hits | <N> |
| Attributed to known-benign populations (labelled) | <N> (<breakdown>) |
| Reviewed individually | <N> |
| Suspicious, escalated | <N> |
| Unexplained after review | <N> |

### Findings escalated

| # | Entity (host / user) | Evidence (defanged) | Verdict | Ticket |
|---|---|---|---|---|
| 1 | <WS-003 / carol> | `schtasks /create /tn Updater /tr C:\Users\carol\AppData\Local\Temp\upd[.]exe` | true positive | INC-<n> |

### Explained benign (the allow-list for next time)

| Value / pattern | Population | Reason | Evidence | Added to environment.md? |
|---|---|---|---|---|
| `\AppData\Local\Microsoft\Teams\Update.exe` | all users | Teams updater | signer Microsoft, 1,100 hosts | yes |

### Unexplained (accepted residual)

<Items reviewed but not fully explained, with why they were accepted and any follow-up owner.>

## Analysis notes

<What technique worked (stacking, prevalence, baseline), what did not, normalisation
applied, pivots taken, enrichment sources actually queried (mark others "not checked").>

## Outputs and hand-offs

| Output | Destination | Link / status |
|---|---|---|
| Incident(s) | `incident-triage` | INC-<n> |
| Indicators | `ioc-extraction` | <list or n/a> |
| Detection candidate | `detection-engineering` | requirement DET-<n>: <one line>; backtest numbers above |
| Telemetry gap | <logging team> | <ticket>: 42 hosts without Sysmon |
| Baseline / allow-list | `references/environment.md` | updated <date> |
| ATT&CK coverage update | `mitre-attack-mapping` | <technique>: hunted <date>, detection pending |

## Follow-up hypotheses added to the backlog

- <HUNT-<n+1>: ...>
- <...>

## Lessons

<One or two lines on what would make this hunt faster next time: a saved query, a new
field, an export, a normalisation rule.>
