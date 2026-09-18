# Google SecOps (Chronicle): UDM search and YARA-L basics

Google Security Operations (formerly Chronicle) normalizes every log into the Unified Data
Model (UDM). Ad hoc questions use **UDM search** (a filter expression over UDM fields);
detections and multi-event logic use **YARA-L 2.0** rules. Based on Google SecOps
documentation, 2025-2026; field paths are stable but new ones are added regularly, so use
the UDM field browser in the UI when a field is missing here.

## UDM structure

Every event has these top-level nouns; each carries the same set of sub-fields
(`ip`, `hostname`, `user.userid`, `process.command_line`, `file.sha256`, `url`, ...):

| Noun | Role |
|---|---|
| `principal` | Who/what initiated the action (source host, user, process) |
| `target` | What was acted on (destination host, file, URL, account) |
| `src` | Source of data in a transfer, when different from principal |
| `intermediary` | Proxy, firewall, mail relay in the path |
| `observer` | The sensor that saw it |
| `about` | Additional entities referenced (a group, an email attachment) |
| `network` | Protocol details: `network.dns.questions.name`, `network.http.user_agent`, `network.email.from`, `network.direction`, `network.ip_protocol`, `network.application_protocol` |
| `security_result` | Detection outcome: `security_result.action` (ALLOW/BLOCK), `security_result.severity`, `security_result.rule_name`, `security_result.category` |
| `metadata` | `metadata.event_type` (PROCESS_LAUNCH, NETWORK_CONNECTION, NETWORK_DNS, USER_LOGIN, FILE_CREATION, EMAIL_TRANSACTION, ...), `metadata.event_timestamp`, `metadata.log_type`, `metadata.product_name`, `metadata.vendor_name` |
| `extensions` | Product-specific: `extensions.auth.type`, `extensions.auth.mechanism` |
| `additional.fields` | Key/value bag for what did not fit the model |

Commonly used paths:

```
principal.hostname, principal.ip, principal.user.userid, principal.user.email_addresses
principal.process.command_line, principal.process.file.full_path, principal.process.file.sha256
principal.process.parent_process.file.full_path
target.hostname, target.ip, target.port, target.url, target.user.userid
target.file.full_path, target.file.sha256, target.file.md5
target.process.command_line, target.registry.registry_key, target.registry.registry_value_data
network.dns.questions.name, network.dns.answers.data
network.email.from, network.email.to, network.email.subject
metadata.event_type, metadata.log_type, security_result.action
```

## UDM search syntax

```
metadata.event_type = "PROCESS_LAUNCH" AND principal.process.file.full_path = /schtasks\.exe$/ AND principal.process.command_line = /\/create/ nocase
target.ip = "203.0.113.56" OR target.ip = "198.51.100.23"
network.dns.questions.name = /evil-domain\.example$/
principal.user.userid = "jdoe" AND metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK"
metadata.log_type = "WINEVTLOG" AND metadata.product_event_type = "4688"
target.process.command_line != "" AND NOT principal.hostname = "build-01"
```

- Operators: `=`, `!=`, `>`, `<`, `>=`, `<=`, regex with `/.../`, `AND`, `OR`, `NOT`,
  parentheses. Add `nocase` after a string or regex comparison for case-insensitive
  matching; matches are case-sensitive by default.
- Time range comes from the UI picker (or the API's start/end); there is no in-query time
  bound. Say the window in your notes.
- Strings use double quotes; escape backslashes in regexes (`\\`) and in Windows paths.
- Enumerations (`metadata.event_type`, `security_result.action`) are UPPER_CASE strings.
- Reference lists: `principal.ip IN %bad_ips` where `bad_ips` is a list created under
  Detection > Lists (string, regex, or CIDR type). Use these for IOC sets instead of long
  `OR` chains; the search UI accepts long expressions but the rule engine has size limits.
- Results are grouped by event and can be pivoted (prevalence, entity graph); "Search
  statistics" (the stats tab, YARA-L `match`/`outcome` style aggregations) gives counts by
  field without leaving the search.

## Count first

Run the filter, read the event count and the "prevalence" column before opening rows. For
a stacked view use the statistics tab or a YARA-L rule with an `outcome` section in test
mode; UDM search itself does not have a `group by`.

## YARA-L 2.0 basics

```
rule scheduled_task_from_temp {
  meta:
    author = "SOC yourcompany.example"
    description = "schtasks /create pointing at a temp directory"
    severity = "MEDIUM"
    mitre_attack_tactic = "Persistence"
    mitre_attack_technique = "T1053.005"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.principal.process.file.full_path, `\\schtasks\.exe$`) nocase
    re.regex($e.principal.process.command_line, `/create`) nocase
    re.regex($e.principal.process.command_line, `\\(AppData\\Local\\Temp|Windows\\Temp|Users\\Public)\\`) nocase
    $host = $e.principal.hostname

  match:
    $host over 1h

  outcome:
    $risk_score = 50
    $cmd = array_distinct($e.principal.process.command_line)

  condition:
    $e
}
```

- `events:` binds one or more event variables (`$e`, `$login`, ...) with predicates;
  fields joined across variables (`$e1.principal.ip = $e2.target.ip`) express correlation.
- `match:` groups over a window (`over 10m`, max 48h) by the placeholder variables;
  omit it for single-event rules.
- `outcome:` computes values (`count_distinct`, `array_distinct`, `max`, risk scores)
  attached to the detection.
- `condition:` counts: `$e`, `#e > 5`, `$login and not $mfa` (with `not` needing a match
  window).
- Regexes are RE2, wrapped in backticks; `nocase` after the function call.
- Reference lists in rules: `$e.target.ip in %bad_ips`.
- Test a rule against historical data with "Test rule" before enabling; retrohunts run a
  rule over a past window and are the standard way to check an IOC list at scale.

## Pivots and enrichment

- Entity context (asset, user) is joined automatically: `principal.asset.*`,
  `principal.user.*` from the entity graph; `graph.entity.*` in YARA-L for asset/user
  context rules.
- Prevalence: how many assets touched a domain/hash in the org over the window; low
  prevalence is the built-in rarity signal for hunts.
- Curated detections and the Applied Threat Intelligence feed populate
  `security_result` and `ioc` context on matching events.

## Pitfalls

- Field paths are exact and nested: `principal.ip` is a repeated field, `principal.hostname`
  is a string; equality on a repeated field matches any element.
- `metadata.event_type` filtering first avoids scanning every log type; a hostname search
  without it is slow and noisy.
- Parsers differ per `metadata.log_type`; the same Windows event from two collectors can
  land in different fields. Check `metadata.log_type` on a few results before trusting a
  query across the estate.
- Regex is case-sensitive unless `nocase`; hostnames from AD often arrive upper-case.
- The 48-hour `match` window caps correlation in rules; longer baselines need outcome
  variables or a scheduled retrohunt.
