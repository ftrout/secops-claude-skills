# Elastic: KQL, EQL, ES|QL over ECS

Elastic Security ingests into data streams named `logs-<integration>.<dataset>-<namespace>`
and normalizes field names to the Elastic Common Schema (ECS, 8.x, 2025). Three query
languages coexist: Kibana Query Language (KQL) for filtering in Discover and rule queries,
EQL for sequence/process-tree logic in detection rules and Timelines, and ES|QL for
piped analytics (Elastic 8.11+). Field names are shared across all three.

## ECS fields you will use most

| Area | Fields |
|---|---|
| Host / user | `host.name`, `host.id`, `user.name`, `user.domain`, `user.id` |
| Process | `process.name`, `process.executable`, `process.command_line`, `process.args`, `process.pid`, `process.entity_id`, `process.parent.name`, `process.parent.executable`, `process.parent.command_line`, `process.hash.sha256`, `process.hash.md5`, `process.code_signature.subject_name`, `process.pe.original_file_name` |
| File | `file.name`, `file.path`, `file.extension`, `file.hash.sha256`, `file.size`, `file.directory` |
| Network | `source.ip`, `source.port`, `destination.ip`, `destination.port`, `destination.domain`, `network.direction`, `network.protocol`, `network.bytes`, `network.community_id` |
| DNS | `dns.question.name`, `dns.question.type`, `dns.answers.data`, `dns.response_code` |
| URL / HTTP | `url.full`, `url.original`, `url.domain`, `url.path`, `http.request.method`, `http.response.status_code`, `user_agent.original` |
| Registry | `registry.path`, `registry.key`, `registry.value`, `registry.data.strings` |
| DLL | `dll.name`, `dll.path`, `dll.hash.sha256` |
| Email | `email.from.address`, `email.sender.address`, `email.to.address`, `email.subject`, `email.attachments.file.hash.sha256` |
| Auth | `event.category:authentication`, `event.outcome` (success/failure), `source.ip`, `user.name`, `winlog.event_id`, `winlog.event_data.LogonType` |
| Cloud | `cloud.provider`, `cloud.account.id`, `cloud.region`, `user.name`, `aws.cloudtrail.*`, `azure.activitylogs.*`, `gcp.audit.*` |
| Event taxonomy | `event.category` (process, file, network, authentication, registry...), `event.type` (start, end, creation, access...), `event.action`, `event.outcome`, `event.dataset`, `event.module` |
| Time | `@timestamp` (ingest-normalized UTC), `event.created`, `event.ingested` |

`event.category` + `event.type` is the fastest way to pick the right subset:
`event.category:process and event.type:start` is process creation regardless of source
(Elastic Agent, Sysmon via winlogbeat, auditd).

## KQL (Kibana Query Language)

```
event.category:process and event.type:start and process.name:schtasks.exe and process.args:/create
process.command_line:*AppData\\Local\\Temp*                 // wildcard on a text/keyword field
destination.ip:("203.0.113.56" or "198.51.100.23")           // value list
not user.name:(SYSTEM or "NETWORK SERVICE")
source.ip:10.0.0.0/8                                          // CIDR on ip fields
@timestamp >= "2026-09-01" and @timestamp < "2026-09-03"      // explicit window
host.name:web-* and not process.parent.name:services.exe
```

- Keyword fields (`.keyword`, most ECS identifiers) are exact and case-sensitive; text
  fields are analyzed (tokenized, lower-cased) so `process.command_line:temp` matches a
  token but `process.command_line.keyword:temp` does not. Check the mapping when a query
  returns nothing.
- Escape spaces and reserved characters (`\ : ( ) " *`) with a backslash, or quote the
  whole value.
- The time range comes from the picker in Discover; in saved queries and rules add the
  `@timestamp` clause so the query means the same thing everywhere.
- KQL has no aggregation: use Lens/Discover field stats, or ES|QL, for counts.

## EQL (Event Query Language)

```
process where event.type == "start" and process.name : "schtasks.exe" and process.args : "/create"

sequence by host.id with maxspan=5m
  [process where process.name : "powershell.exe" and process.args : "-enc*"]
  [network where destination.port == 443 and not cidrmatch(destination.ip, "10.0.0.0/8")]

sequence by process.entity_id
  [file where file.name : "*.exe" and file.path : "*\\Temp\\*"]
  [process where process.executable : "*\\Temp\\*"]
```

- `:` is case-insensitive with wildcards; `==` is case-sensitive exact. Use `:` for names
  and paths, `==` for hashes and IDs.
- `sequence by <field>` correlates events sharing a value within `maxspan`; `until` ends
  the sequence early. `with runs=3` repeats a step.
- Functions: `cidrmatch()`, `startsWith()`, `endsWith()`, `stringContains()`, `length()`,
  `wildcard()`, `concat()`.
- EQL is the native language of Elastic's prebuilt detection rules and the Timeline
  "correlation" tab; it is not available in Discover.

## ES|QL

```
FROM logs-*
| WHERE @timestamp > NOW() - 30 days
  AND event.category == "process" AND event.type == "start"
  AND process.name == "schtasks.exe" AND process.command_line LIKE "*/create*"
| STATS hits = COUNT(*), hosts = COUNT_DISTINCT(host.name), first = MIN(@timestamp), last = MAX(@timestamp)
    BY process.command_line
| SORT hits ASC
| LIMIT 100
```

- `LIKE` uses `*`/`?` wildcards; `RLIKE` is regex. Both case-sensitive; wrap with
  `TO_LOWER()` when in doubt.
- `IN` works on keyword fields: `process.hash.sha256 IN ("a", "b")`. For `ip` typed fields
  compare with `==` and `TO_IP("...")` or use `CIDR_MATCH(destination.ip, "203.0.113.56/32")`.
- Default `LIMIT` is 1000 rows in the UI; state it explicitly.
- `LOOKUP JOIN` (8.18+/9.x) joins against a lookup-mode index; check the version before
  relying on it. `ENRICH` policies are the older mechanism.
- Great for stacking: `| STATS c = COUNT(*) BY process.executable | SORT c ASC` is the
  long-tail view in one line.

## Count first, then rows

KQL in Discover shows the histogram and hit count immediately; look at that before
expanding documents. In ES|QL, write the `STATS` version first and only replace it with
`KEEP` + `LIMIT` when the count is sane.

## Lookups and joins

- Value lists in detection rules: Security > Rules > Value lists, referenced by the rule
  exception or `list` features. Big IOC lists belong there, not in the query string.
- Threat-intel matching: the "indicator match" rule type joins events to a threat index
  (`logs-ti_*`) on chosen fields; use it instead of hand-built `or` lists when TI
  integrations are on.
- Ad hoc joins: ES|QL `LOOKUP JOIN` / `ENRICH`; otherwise correlate by `STATS ... BY key`
  over a `FROM a,b` union.

## Performance pitfalls

- Leading wildcards (`*.evil.example`) on keyword fields expand to term scans; prefer
  `url.domain:evil.example or url.domain:*.evil.example` split, or the `domain` field
  that already holds the registered domain (`url.registered_domain`).
- `logs-*` across all datasets is fine for a first count but slow for regex; narrow to
  `logs-endpoint.events.process-*` or `logs-windows.sysmon_operational-*` once you know
  the dataset (`event.dataset` tells you).
- Detection rules have a `max_signals` cap (default 100 per run) and a lookback; a rule
  that finds 5,000 hits an hour is dropping alerts silently. Tune or aggregate.
- `boolean max_clause_count` (1024 historically, 4096 in newer versions) bounds the number
  of `or` terms; chunk indicator lists at a few hundred.
- Frozen/cold tiers answer slowly or not at all for wildcard-heavy queries; time-bound
  searches to the hot tier unless the hunt needs the archive.
