# Environment customization (edit me)

Replace the placeholders. The skill reads this to choose the platform, the tables, the
default time window, and the limits it should respect when generating queries.

## Platforms we have

| Platform | In use? | URL / workspace | Query language | Notes |
|---|---|---|---|---|
| Microsoft Sentinel | [ ] | `<siem-url>` / workspace `<name>` | KQL | retention `<N>` days analytics, `<N>` archive |
| Defender XDR advanced hunting | [ ] | security.microsoft.com | KQL | 30-day lookback |
| Splunk | [ ] | `<splunk-url>` | SPL | CIM accelerated models: `<list>` |
| Elastic Security | [ ] | `<kibana-url>` | KQL / EQL / ES\|QL | version `<8.x/9.x>`; `LOOKUP JOIN` available? |
| Google SecOps (Chronicle) | [ ] | `<instance>.chronicle.security` | UDM / YARA-L | reference lists: `<names>` |
| Athena / BigQuery | [ ] | database `<name>` | SQL | partition scheme: `<year/month/day or projection>` |

Default platform when the user does not say: `<platform>`.

## Where each data source lives

| Question type | Platform | Table / index / datamodel | Time column | Gotchas |
|---|---|---|---|---|
| Endpoint process | `<kql>` | `DeviceProcessEvents` | `Timestamp` | command line truncated at `<N>` chars? |
| Endpoint network | | | | |
| DNS | | | | |
| Proxy / web | | | | |
| Identity sign-ins | | `SigninLogs` | `TimeGenerated` | non-interactive in a separate table |
| Email | | | | |
| Cloud control plane (AWS) | | `cloudtrail_logs` | `eventtime` | partitions `year/month/day` |
| Cloud control plane (Azure) | | `AzureActivity` | | |
| Cloud control plane (GCP) | | | | |
| Firewall / IDS | | | | |
| Custom / application | | | | |

Hosts or segments with **no** telemetry (so "no results" means "not visible"): `<list>`.

## Defaults and limits

- Default time window for retro-hunts: `30` days network, `90` days hashes (matches
  `ioc-extraction` shelf life).
- Maximum values per `in`-list per platform (edit `chunk_size` in
  `references/field-map.json` to match): KQL `500`, SPL `500`, Elastic `300`, SQL `500`,
  Chronicle `50` (use reference lists above that).
- Row cap before the query must aggregate instead: `10000`.
- Queries that scan more than `<N>` GB / `<N>` days need `<approval or off-peak schedule>`.
- Preferred saved-query location: `<repo or SIEM folder>`; naming: `hunt-<date>-<topic>`.

## Field-name overrides

Our schemas differ from the defaults in these places (the skill uses these names instead):

| Platform | Default field | Our field | Why |
|---|---|---|---|
| `<spl>` | `Processes.process_hash` | `Processes.process_hash_sha256` | custom TA |
| | | | |

Add or change table/field pairs in `references/field-map.json`; `ioc_to_query.py` reads
that file, so a team-specific copy passed with `--map` is the cleanest override.

## Naming conventions

- Corporate domains and ranges to exclude from "external" logic: `yourcompany.example`,
  `203.0.113.0/24`
- Service account pattern: `svc_*`, `*$` (machine accounts)
- Admin jump hosts: `<names>`; vulnerability scanners: `<names / IPs>`

## Hand-offs

- Indicator lists come from `ioc-extraction` (CSV `indicator,type,role,confidence,...`).
- Hits on indicators go to `incident-triage`; behaviour hunts go to `threat-hunting`;
  queries worth keeping become rules through `detection-engineering`.
- Who can approve a query that touches HR/legal-sensitive sources (mailbox content, DLP):
  `<name/role>`.
