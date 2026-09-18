# Environment customization (edit me)

Replace the placeholders with your team's real values. This file is loaded whenever the
skill needs it, so keep it short and current. Fields marked **(changes behaviour)** alter
what the workflow does, not just what it prints.

## Tooling
- SIEM: `<Sentinel | Splunk | Elastic | Chronicle | other>`; console: `<siem-url>`
- EDR: `<CrowdStrike | Defender for Endpoint | SentinelOne | other>`; console: `<edr-url>`
- IdP: `<Entra ID | Okta | Google Workspace | other>`
- Email gateway: `<Defender for Office | Proofpoint | Mimecast | other>`
- Ticketing / case management: `<Jira | ServiceNow | TheHive | other>`; project key: `<KEY>`
- Asset inventory / CMDB: `<tool>`; criticality field: `<field name>` **(changes behaviour:
  the asset_criticality factor is read from here when available, otherwise scored 3 "unknown")**
- Enrichment available in the session (MCP tools, APIs): `<list them, or "none">`

## Severity model
- Weights file: `references/severity-weights.json` **(changes behaviour: weights, thresholds,
  floors, ceilings, and label aliases are all read from it)**
- Tier names used in tickets: `<P1..P4 | Sev1..Sev4 | Critical/High/Medium/Low>` (rename in the
  weights file so the script output matches the ticketing system)
- SLA per tier (acknowledge / update / resolve): P1 `<15m / 1h / ->`, P2 `<30m / 4h / ->`,
  P3 `<shift>`, P4 `<weekly review>`

## Escalation paths
- Tier 2 / IR queue: `<channel, queue, or on-call rota>`
- Page on-call (P1): `<pager service, schedule name>`
- Incident commander for P1: `<role>`
- Legal / privacy contact for regulated data (data_sensitivity 5): `<role, contact>`
- HR / insider-risk contact for DLP cases: `<role, contact>` **(changes behaviour: DLP true positives
  are not user-contacted until this role is looped in)**
- Executive notification threshold: `<P1 only | P1 and P2>`

## Containment approvals **(changes behaviour)**
| Action | Who can approve | How to request | Rollback |
|---|---|---|---|
| Isolate endpoint | `<tier 2 lead>` | `<ticket field / chat command>` | EDR un-isolate |
| Disable user account | `<IAM on-call>` | `<...>` | re-enable, restore group membership |
| Revoke sessions / reset password | `<IAM on-call>` | `<...>` | user re-authenticates |
| Block domain / IP at perimeter | `<network on-call>` | `<change ticket type>` | remove rule |
| Purge email from mailboxes | `<messaging admin>` | `<...>` | restore from quarantine |
| Rotate cloud credentials | `<cloud platform team>` | `<...>` | see `cloud-incident-investigation` |

Pre-approved (no ticket needed) actions, if any: `<e.g. block external domain with VT >= 10 detections>`

## Known-benign context (reduces false positives)
- Vulnerability scanners / pen-test sources: `<hostnames, IP ranges>`
- Software deployment accounts and tools: `<svc-sccm, ansible-runner, ...>`
- Corporate egress IPs / VPN / SASE ranges: `203.0.113.0/24`, `<...>`
- Phishing simulation sender domains and schedule owner: `<domain>`, `<role>`
- Approved remote-access tools: `<list>`
- Where tuning notes / known-FP records live: `<wiki page or ticket label>`

## Naming and note conventions
- Incident ID format: `<INC-YYYY-NNNN>`
- Triage note goes in: `<ticket comment | case timeline | chat thread>`
- Timestamps: UTC, ISO 8601 (`2026-09-17T14:03:00Z`); local time in parentheses if your team needs it
- Verdict vocabulary: `true-positive | false-positive | benign-true-positive | undetermined`
