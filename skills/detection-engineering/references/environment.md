# Environment customization (edit me)

Replace the placeholders with your team's values. This file is loaded whenever the skill
needs to decide which backend to target, what "acceptable noise" means, or who reviews.

## Backend and conversion

| Setting | Value | What it changes |
|---|---|---|
| Primary SIEM / query language | `<Splunk SPL | Microsoft Sentinel KQL | Defender XDR KQL | Elastic ES|QL | Chronicle YARA-L>` | Which conversion target and pipeline the workflow uses |
| sigma-cli target and pipeline | `sigma convert -t <target> -p <pipeline>` | Exact command in step 8 |
| Custom pipeline file | `<repo>/pipelines/yourcompany.yml` | Field-name mappings for local schemas |
| Rule repository | `<git-url>/detections` | Where rules, tests, and deployment records live |
| CI checks on pull requests | `sigma_lint.py`, `sigma check`, unit tests | What must pass before merge |

## Telemetry we actually have

Tick what exists and where. The workflow's data-source check reads this before writing a
rule, so an honest list saves a lot of wasted rules.

| Sigma logsource | Present? | Coverage | Table / index | Notes |
|---|---|---|---|---|
| `process_creation` / windows | [ ] | servers + workstations | `<DeviceProcessEvents / index=sysmon>` | Command line included? |
| `network_connection` / windows | [ ] | | | |
| `dns_query` / windows | [ ] | | | |
| `ps_script` (4104) | [ ] | | | Script block logging enabled? |
| `security` service (4624/4688/4698/4720...) | [ ] | | | Audit policy applied? |
| `process_creation` / linux (auditd/EDR) | [ ] | | | |
| `aws` cloudtrail | [ ] | all accounts? | | |
| `azure` signinlogs / auditlogs | [ ] | | | |
| `m365` exchange / audit | [ ] | | | |
| `okta` | [ ] | | | |
| `proxy` / `dns` / `firewall` | [ ] | | | |

Retention: hot `<N>` days, searchable `<N>` days. Rules needing longer correlation windows
must say so.

## Noise thresholds

| Level | Max FP rate | Max alerts/day | Who is paged |
|---|---|---|---|
| critical | 5% | 3 | on-call IR |
| high | 20% | 10 | SOC shift lead |
| medium | 50% | 50 | SOC queue |
| low / informational | n/a | n/a | dashboards, hunts |

Backtest window before deployment: `30` days (`90` for rare behaviours).

## Naming and metadata

- `author`: `<Team name> (yourcompany.example)`
- Title prefix for internal-only rules: `[INT]` (or none)
- Tags we add beyond ATT&CK: `<yourcompany.tier1>`, `<yourcompany.crownjewel>`
- Ticket reference format in `references`: `https://<ticketing>/browse/DET-1234`
- Status lifecycle: `experimental` (2 weeks) -> `test` (30 days) -> `stable`; review every
  `6` months or on data-source change.

## Review and escalation

- Rule reviewers: `<name/team>`; two approvals for `high`/`critical`.
- Emergency deployment (active incident): `<who can approve>`; rule still gets a review
  within `<N>` days.
- Who owns tuning after deployment: `<SOC / detection team>`
- Where alert triage notes live: `<wiki-url>` (consumed by `incident-triage`).

## Test data

- Location of true-positive samples: `<repo>/tests/<rule-id>/tp.jsonl`
- Location of benign samples: `<repo>/tests/<rule-id>/benign.jsonl`
- Purple-team results feed: `<link>` (from `purple-team-exercise`)
- Public emulation catalog we reference by ID: Atomic Red Team, MITRE CALDERA, Stratus Red
  Team (cloud). Reference by test name/ID only; never store attack commands in this repo.
