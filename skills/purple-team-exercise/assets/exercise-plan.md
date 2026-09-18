# Purple Team Exercise Plan: <exercise name>

> Fill every angle-bracket placeholder. This plan is written and approved **before** anything
> runs. Pair it with the rules of engagement (`rules-of-engagement.md`). Reference emulation
> tests by ID/name only; the operator pulls the actual test from the source project.

## 1. Objective and scope of the question

- **Objective:** <what this exercise answers, e.g. "How well do we detect the credential-access
  and impact stages of a ransomware precursor on Windows endpoints?">
- **Driver:** <threat profile / actor / recent incident / new detection to validate> (source:
  `threat-intel-analysis` output, ticket, etc.)
- **ATT&CK version used for mapping:** v<version> (<year>)
- **Success criteria:** <e.g. "coverage and TTD measured for every planned technique; gaps
  assigned with owners; regressions vs. last quarter identified">

## 2. Scenarios

Each scenario is a realistic chain, not a random list.

### Scenario A: <name>
Narrative: <one or two sentences describing the intrusion story this reproduces>.
Techniques: <T1078.004 -> T1059.001 -> T1547.001 -> T1003.001 -> T1021.002 -> T1490>.

### Scenario B: <name>
Narrative: <...>
Techniques: <...>

## 3. Technique plan (write expected source BEFORE the run)

| # | Scenario | Technique ID | Technique | Tactic | Emulation test (ID/name only) | Platform | Target host/account | Operator | Planned time (UTC) | Expected data source | Priority |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | A | T1078.004 | Cloud Accounts | Initial Access | Stratus aws.initial-access.console-login-without-mfa | AWS | pt-aws-user | <op> | <t> | CloudTrail ConsoleLogin | 1 |
| 2 | A | T1059.001 | PowerShell | Execution | ART T1059.001 Test #9 (Invoke-DownloadCradle) | Windows | pt-lab-01 | <op> | <t> | Sysmon 1 + PowerShell 4104 | 2 |
| 3 | A | T1003.001 | LSASS Memory | Credential Access | ART T1003.001 Test #1 (ProcDump) | Windows | pt-lab-01 | <op> | <t> | Sysmon 10 + EDR | 1 |
| 4 | A | T1490 | Inhibit System Recovery | Impact | ART T1490 Test #1 (delete shadow copies) | Windows (throwaway) | pt-lab-throwaway | <op> | <t> | Sysmon 1 + EDR | 1 |
| ... | | | | | | | | | | | |

Sequencing notes: <run noisy/destructive steps last; leave >= N minutes between steps so
time-to-detect is measurable per technique; note any prerequisite state each test needs>.

## 4. Roles

| Role | Person | Responsibility |
|---|---|---|
| Exercise lead | <name> | owns plan, ROE, readout |
| Operator(s) | <name> | runs the tests from the source projects under ROE |
| Blue observer(s) | <name> | scores expected-vs-observed, captures timestamps |
| Control group | <names> | know in advance; hold the deconfliction signal |
| Approver(s) | <name> | signed the ROE |

## 5. Data collection

- Execution timestamps captured from: <operator log / CALDERA operation / cloud trail>.
- Alert timestamps captured from: <SIEM / EDR console / ticket system>.
- Scorecard input CSV columns: `technique_id, technique, tactic, test_name, expected_source,
  observed, ttd_minutes, notes` (+ optional `priority, platform, test_id`).
- Time-to-detect SLA for this exercise: <N> minutes (`scorecard.py --ttd-sla N`).

## 6. Schedule

- Run window (UTC): <start> to <end>.
- Readout: <date>.
- Retest of gaps: <date / next exercise>.

## 7. Deliverables

- This plan (approved), the ROE (approved), the scorecard (`scorecard.py` output), and the
  readout (see the skill's Output section).
- Detection backlog handed to `detection-engineering`; telemetry-onboarding items handed to
  <log platform owner>.

## 8. Sign-off

| Name | Role | Approved (date) |
|---|---|---|
| <name> | <role> | <date> |
