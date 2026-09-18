# Environment customization (edit me)

Replace the placeholders. The skill reads this to decide what data it can hunt in, what
"rare" means here, which populations to exclude up front, and where results go.

## Hunting platform and data

| Setting | Value | What it changes |
|---|---|---|
| Primary query platform | `<Sentinel KQL / Splunk SPL / Elastic / Chronicle / Athena>` | Which `siem-query-authoring` reference is used for hunt queries |
| Export path for offline stacking | `<how to export CSV/JSONL from the SIEM>` | Whether `scripts/stack.py` is used on exports or the SIEM aggregates directly |
| Hunt backlog location | `<ticketing project or wiki page>` | Where new hypotheses and results are filed |
| Hunt report location | `<wiki / repo path>` | Where `assets/hunt-report.md` output is saved |

Data sources available for hunting (tick and note coverage):

| Data source | Present | Coverage (hosts / accounts) | Retention | Table / index | Known gaps |
|---|---|---|---|---|---|
| Endpoint process creation (Sysmon 1 / 4688 / EDR) | [ ] | | `<N>` d | | command line captured? |
| Endpoint network (Sysmon 3 / EDR) | [ ] | | | | |
| DNS (server / EDR / resolver logs) | [ ] | | | | |
| Proxy / web gateway | [ ] | | | | user and process attribution? |
| Firewall / NetFlow | [ ] | | | | |
| Windows Security (4624/4625/4688/4698/4720/4728/4769/7045) | [ ] | | | | audit policy verified on `<date>` |
| PowerShell 4104 | [ ] | | | | |
| Linux auditd / EDR | [ ] | | | | |
| IdP sign-ins (Entra / Okta) | [ ] | | | | non-interactive included? |
| M365 unified audit log | [ ] | | | | MailItemsAccessed enabled? |
| Cloud control plane (CloudTrail / Azure Activity / GCP audit) | [ ] | all accounts? | | | |
| Email gateway / URL clicks | [ ] | | | | |

Populations with **no** telemetry (results there mean "not visible"): `<OT segment, BYOD, ...>`.

## Rarity and baseline defaults

| Setting | Default | Notes |
|---|---|---|
| Fleet size (endpoints / users) | `<N>` / `<N>` | Turns "3 hosts" into a percentage |
| Rare threshold for `stack.py --rare-below` | `1%` | Lower for fleets over 5,000 hosts |
| Rare prevalence (`--rare-groups`) | `1` (`2` for fleets over 2,000) | Values on this many hosts or fewer are flagged |
| Hunt window | `7` days | Baseline window `30` days before it |
| Aggregate-instead-of-rows threshold | `5000` rows | Above this, stack first |

## Known-benign populations to exclude or label up front

| Population | Identifier pattern | Why it is noisy |
|---|---|---|
| Machine accounts | `*$` | Every Windows host |
| Service accounts | `svc_*`, `<list>` | Scheduled jobs, backups |
| Vulnerability scanners | `<hostnames / IPs>` | Discovery, LDAP, service enumeration |
| Software deployment | `<SCCM/Intune/PDQ hosts and accounts>` | Remote service creation, encoded PowerShell |
| Backup / monitoring agents | `<binaries and signers>` | LSASS access, VSS, high file counts |
| Approved remote access tool | `<product>` | Every other remote-access product is a finding |
| Admin jump hosts | `<hostnames>` | Discovery and lateral movement look normal here |
| CI/CD and IaC identities | `<roles / service principals>` | Cloud create/delete bursts |

Exclusions are labels, not deletions: keep excluded rows countable so the report can say
"1,204 hits, 1,190 from populations above, 14 reviewed".

## Threat profile inputs

- PIRs / threat profile document: `<link>` (from `threat-intel-analysis`)
- Crown-jewel systems and their hosts/accounts: `<list>` (prioritise hunts touching them)
- Current ATT&CK coverage layer: `<link>` (from `mitre-attack-mapping`); prefer hunts in
  uncovered techniques

## Hand-offs

| Outcome | Goes to | Format |
|---|---|---|
| Confirmed malicious activity | `incident-triage` | triage note with evidence, scope, and the hunt query |
| Indicators discovered | `ioc-extraction` | raw text or list; it normalises and defangs |
| Repeatable query with acceptable noise | `detection-engineering` | requirement + query + backtest numbers |
| Telemetry gap | `<logging / platform team ticket queue>` | data source, hosts affected, hunt that needed it |
| Baseline / allow-list | `<wiki>` and this file's benign table | value, population, reason, date |
| Coverage update | `mitre-attack-mapping` | technique IDs hunted, result |

Hunt cadence: `<N>` hunts per `<sprint/month>`; review the backlog every `<N>` weeks.
Who approves hunts that touch mailbox content, DLP, or HR data: `<name/role>`.
