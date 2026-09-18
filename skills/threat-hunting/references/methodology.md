# Hunting methodology and analysis techniques

## Frameworks

Two frameworks shape the workflow in this skill; both are public and worth reading once.

**PEAK** (Splunk SURGe, 2023): *Prepare, Execute, Act, Knowledge*. Its useful ideas are the
three hunt types and the insistence that every hunt ends in an artifact:

| Hunt type | Starts from | Ends with |
|---|---|---|
| Hypothesis-driven | A specific claim about attacker behaviour ("an attacker is using scheduled tasks from Temp") | Confirm/deny plus a detection or a documented gap |
| Baseline (exploratory) | A data source you want to understand ("what does normal PowerShell look like here?") | A baseline document and a list of anomalies to follow up |
| Model-assisted (M-ATH) | A statistical or ML model surfacing outliers | Reviewed outliers and a tuned model |

**TaHiTI** (Dutch financial sector ISAC, 2018): *Targeted Hunting integrating Threat
Intelligence*. Three phases, *Initiate* (trigger, abstract, hunt backlog), *Hunt*
(define hypothesis, determine data, execute, refine), *Finalize* (document, hand off).
Its contribution is the **hunt backlog**: hypotheses are written down, prioritised by
threat relevance and feasibility, and picked off in order, rather than hunted on whim.

**Hunting Maturity Model** (Sqrrl, 2015): HMM0 (alert-driven only) to HMM4 (automated,
data-driven with hunts becoming detections). The point: a hunt that does not produce a
detection, a baseline, or a telemetry request leaves the team at the same maturity.

## From trigger to hypothesis

| Trigger | Questions that turn it into a hypothesis |
|---|---|
| Threat report / TTPs (from `threat-intel-analysis`) | Which techniques in the report would we *not* already alert on? Which data source would show them here? What does the actor's tooling look like at the field level? |
| ATT&CK technique or coverage gap (from `mitre-attack-mapping`, `purple-team-exercise`) | What are the two or three procedures for this technique we are most likely to face? Which one is cheapest to hunt with our telemetry? |
| Anomaly or "something feels off" | What is the population (hosts, users, time window)? What would normal look like, and how would I measure it? |
| Incident lesson (from `incident-triage` / `incident-report-writing`) | Did this happen elsewhere? What preceded it that we could have caught earlier? |
| New data source | What are the top 20 values of each interesting field? Where is the long tail? |

Write the hypothesis in one sentence with a behaviour, a population, and a data source:
"On workstations, an adversary has established persistence with a scheduled task whose
action lives in a user-writable directory; Sysmon 1 and 4698 would show it."

Then write the **null result**: what you expect to see if the hypothesis is false
(only known updaters, N hits, all explained). Deciding that up front keeps the hunt from
expanding forever.

## Analysis techniques

### Stacking (frequency analysis)

Count occurrences of a value and read from the bottom. `scripts/stack.py` does this over
a CSV or JSONL export; in the SIEM it is `summarize count() by X | order by count_ asc`,
`stats count by X | sort count`, `STATS c = COUNT(*) BY X | SORT c`.

- Stack *combinations* (parent + child, user + host, process + signer) when single fields
  are too common.
- Normalise before stacking: lower-case, strip GUIDs/PIDs/timestamps from command lines
  (replace with a token), collapse user-specific paths (`C:\Users\<user>\` -> `C:\Users\*\`).
- Read the top too: a common value that *should* be rare (a remote-access tool on 60% of
  hosts) is a finding.

### Prevalence (rarity across a population)

For each value, how many distinct hosts/users/accounts show it? A value with count 500
on 1 host is different from count 500 across 500 hosts. `stack.py --group host` reports
this as `groups`; the `--rare-groups` flag marks values seen on few groups. In the SIEM:
`summarize hosts=dcount(DeviceName) by X`, `stats dc(host) by X`. Prevalence is the single
most productive hunting signal for process, DLL, scheduled task, and domain stacks.

### Baselining

Compare the hunt window to a prior window: values that appear in the last 7 days but not
in the previous 30 are *new*. Implement with two aggregations joined on the value
(`join kind=leftanti`, `stats` with a window flag, `NOT IN (subquery)`). New is not bad,
but new plus rare plus a weak reason is the shortlist. Keep baselines per entity where
behaviour differs by role (an admin's "normal" is not a finance user's).

### Clustering and grouping

Group events by a shared attribute and look for clusters that stand apart: hosts that
resolve the same never-before-seen domain, accounts that all failed a logon from the same
ASN, processes with the same import hash. Small clusters (2-5 members) that share an
unusual attribute are often the same intrusion seen from different vantage points.

### Sequence and timing

Order events by entity and look for chains within a window: Office spawns shell spawns
network connection; discovery commands within minutes; failed logons then success from a
new IP. Express as EQL `sequence`, YARA-L `match over`, KQL self-join or `prev()`, SPL
`transaction` (carefully) or `streamstats`. Timing outliers: activity at hours the account
never works, intervals too regular to be human (beaconing), durations too long for the
protocol.

### Outlier detection (numeric)

Bytes out, distinct destinations, files touched, tickets requested, API calls per hour.
Compute per-entity distribution and flag values beyond a multiple of the median or above
the 99th percentile. Prefer robust statistics (median, MAD) over mean and standard
deviation; log data is heavy-tailed.

### Enrichment-driven filtering

Join to an attribute the log does not carry: domain registration age, ASN type
(hosting vs residential vs corporate), file signer, prevalence in public sandboxes, asset
criticality. Enrichment turns "rare" into "rare and suspicious" or "rare and boring".
Use the enrichment sources listed in `ioc-extraction`'s reference material; record which
ones were actually queried.

## Estimating benign volume before you run

For each hypothesis write the expected benign hits and where they come from (the
hypothesis library's last column). If the expected benign volume is thousands of rows,
plan the exclusion or aggregation first; a hunt that returns 50,000 rows is a query, not
an analysis. If the expected benign volume is zero and you get 300 hits, the hypothesis
or the data source is wrong, not the environment.

## Success criteria

A hunt succeeds when one of these is true, and the plan says which one was the target:

1. The hypothesis is **confirmed**: malicious activity found, handed to `incident-triage`.
2. The hypothesis is **rejected with evidence**: the query covered the population, the
   data source was complete, and the results were explained.
3. A **detection** was written or a **telemetry gap** was documented (`detection-engineering`).
4. A **baseline** was recorded that future hunts and triage can use.

"We looked and did not find anything" without coverage numbers is not a result.

## Documenting

Every hunt gets a plan (`assets/hunt-plan.md`) before it starts and a report
(`assets/hunt-report.md`) when it ends, even if the report is ten lines. The report's
value is mostly in the *explained benign* section: the next hunter starts from your
allow-list instead of rebuilding it.
