# Sigma cheat sheet

Based on the Sigma specification v2.0 (SigmaHQ, 2024) and the SigmaHQ rule repository
conventions. Sigma is the canonical form for rules in this skill because it is
vendor-neutral, reviewable as text, and converts to SPL/KQL/EQL/YARA-L with `sigma-cli`
and the pySigma backends. Verify field names against the current specification when in
doubt; the taxonomy grows every few months.

## Rule skeleton

```yaml
title: Short imperative statement of what is detected   # <= 256 chars, ideally < 120
id: 8f2d1e4c-1b2a-4c3d-9e8f-0a1b2c3d4e5f                   # UUID v4, never reused
related:                                                  # optional lineage
  - id: <uuid>
    type: derived | obsolete | merged | renamed | similar
status: experimental                                      # stable | test | experimental | deprecated | unsupported
description: |
  What behaviour is detected, why it matters, and what the attacker is doing. Two to four
  sentences. Someone reading only this must understand the alert.
references:
  - https://... (report, blog, vendor doc, internal ticket)
author: Name or team
date: 2026-09-17                                          # ISO 8601 (spec v2); YYYY/MM/DD is legacy
modified: 2026-09-17
tags:
  - attack.persistence                                    # tactic
  - attack.t1053.005                                      # technique / sub-technique
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
  filter_main_known_good:
    ParentImage|endswith: '\msiexec.exe'
  condition: selection and not filter_main_known_good
fields:                                                   # what to show the analyst
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Legitimate installers registering update tasks
level: medium                                             # informational | low | medium | high | critical
```

## Metadata field notes

| Field | Required (SigmaHQ) | Notes |
|---|---|---|
| `title` | yes | No trailing period. Say what, not how ("Scheduled Task From Temp Directory", not "Regex on CommandLine"). |
| `id` | yes | UUID v4. Generate a fresh one for every rule, including derived copies. |
| `status` | recommended | `experimental` for new rules in the first weeks; `test` once tuned; `stable` after a review cycle with acceptable FP rate; `deprecated` keeps the id resolvable. |
| `description` | yes | Explain the attacker behaviour and the reason the rule exists. |
| `references` | recommended | External write-ups, ATT&CK page, internal ticket. |
| `date` / `modified` | recommended | `YYYY-MM-DD`. Bump `modified` on any logic change. |
| `tags` | recommended | Lower-case. See tag namespaces below. |
| `logsource` | yes | At least one of `category`, `product`, `service`. |
| `detection` | yes | Named selections plus a `condition`. |
| `fields` | optional | Fields worth surfacing in the alert. |
| `falsepositives` | recommended | List of benign activity that trips the rule; `Unlikely` is acceptable when true. |
| `level` | recommended | See level guidance below. |

## Level guidance

| Level | Meaning | Typical handling |
|---|---|---|
| `informational` | Context, never alerts on its own | Enrichment, correlation input |
| `low` | Noisy or weak signal | Hunting dashboards, correlation |
| `medium` | Suspicious, needs a look | Ticket, triage within a shift |
| `high` | Likely malicious | Page on-call, triage within an hour |
| `critical` | Confirmed-malicious behaviour with high confidence | Immediate response, low FP tolerance |

## Tag namespaces (Sigma v2 spec)

| Namespace | Format | Example |
|---|---|---|
| ATT&CK tactic | `attack.<tactic_with_underscores>` | `attack.defense_evasion` |
| ATT&CK technique | `attack.tNNNN` or `attack.tNNNN.NNN` | `attack.t1218.011` |
| ATT&CK group / software | `attack.gNNNN`, `attack.sNNNN` | `attack.g0016` |
| CAR | `car.YYYY-MM-NNN` | `car.2016-04-005` |
| CVE | `cve.YYYY-NNNN` | `cve.2021-44228` |
| Detection type | `detection.dfir`, `detection.emerging_threats`, `detection.threat_hunting` | |
| TLP | `tlp.clear`, `tlp.green`, `tlp.amber`, `tlp.amber_strict`, `tlp.red` | |

Tactic names: `reconnaissance`, `resource_development`, `initial_access`, `execution`,
`persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`,
`lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`.

## Logsource taxonomy (common values)

Sigma's generic categories abstract the actual data source; the conversion pipeline maps
them to concrete tables/indices. Prefer a `category` over a vendor-specific `service`
whenever a category exists, so the rule converts on every backend.

| category | product | What it maps to (examples) |
|---|---|---|
| `process_creation` | windows / linux / macos | Sysmon 1, Security 4688, EDR process events, auditd EXECVE |
| `network_connection` | windows / linux / macos | Sysmon 3, EDR network events |
| `dns_query` | windows | Sysmon 22, EDR DNS events |
| `file_event` | windows / linux / macos | Sysmon 11, EDR file create |
| `file_delete`, `file_change`, `file_rename`, `file_access` | windows / linux | Sysmon 23/26, 2, EDR |
| `registry_event`, `registry_set`, `registry_add`, `registry_delete` | windows | Sysmon 12/13/14, EDR registry |
| `image_load` | windows | Sysmon 7, EDR image load |
| `driver_load` | windows | Sysmon 6 |
| `process_access` | windows | Sysmon 10 |
| `create_remote_thread` | windows | Sysmon 8 |
| `pipe_created` | windows | Sysmon 17/18 |
| `wmi_event` | windows | Sysmon 19/20/21 |
| `ps_script`, `ps_module`, `ps_classic_start` | windows | PowerShell 4104, 4103, 400 |
| `dns`, `proxy`, `firewall`, `webserver` | (any) | Network appliance logs, generic fields |
| `antivirus` | (any) | AV/EDR detections |

Service-based logsources (Windows event channels): `service: security`, `system`,
`sysmon`, `powershell`, `powershell-classic`, `taskscheduler`, `wmi`, `windefend`,
`msexchange-management`, `bits-client`, `dns-server`, `ntlm`, `printservice-admin`,
`terminalservices-localsessionmanager`, `codeintegrity-operational`, `applocker`.

Cloud and SaaS products: `aws` (`service: cloudtrail`), `azure` (`service: activitylogs`,
`signinlogs`, `auditlogs`, `riskdetection`), `gcp` (`service: gcp.audit`), `m365`
(`service: exchange`, `audit`, `threat_management`), `okta` (`service: okta`), `github`
(`service: audit`).

## Value syntax

- Strings are matched case-insensitively by default; `|cased` makes them case-sensitive.
- Wildcards: `*` any characters, `?` one character. Escape with backslash: `\*`, `\?`, `\\`.
  A single backslash before a normal character is literal, so `'\cmd.exe'` needs no doubling.
- `null` means "field absent". `''` means "field present and empty".
- A list under one field means OR (`Image|endswith: [a, b]`); add `|all` for AND.
- Multiple fields inside one selection are ANDed.
- A selection that is a *list of mappings* ORs the mappings.
- A selection that is a *list of strings* (no field names) is a keyword search across the
  whole event; expensive on most backends, use sparingly.
- Numbers are unquoted; quote anything with `*`, `\`, `:`, `#`, `{`, `[` or a leading `@`.

## Modifiers

| Modifier | Effect | Notes |
|---|---|---|
| `contains` | substring | Wraps value in `*...*` |
| `startswith` / `endswith` | prefix / suffix | `endswith: '\cmd.exe'` is the standard Image idiom |
| `all` | AND across a list | Combine: `CommandLine\|contains\|all` |
| `re` | regular expression | Sub-modifiers `\|i` (ignore case), `\|m`, `\|s`. Backend support varies; slower. |
| `cidr` | IP in range | `SourceIp\|cidr: '10.0.0.0/8'` |
| `exists` | field present | `Field\|exists: true` (preferred over `Field: '*'`) |
| `cased` | case-sensitive match | |
| `base64` / `base64offset` | match encoded value | `base64offset` covers all three alignments |
| `utf16le` / `utf16be` / `utf16` / `wide` | encode before base64 | Chain: `\|utf16le\|base64offset\|contains` |
| `windash` | match `-` and `/` and Unicode dashes | For Windows command-line switches |
| `gt` / `gte` / `lt` / `lte` | numeric comparison | |
| `fieldref` | compare to another field | `ParentImage\|fieldref: Image` |
| `expand` | placeholder expansion | `%Admins%`, resolved by the pipeline |

## Condition syntax

```
selection                                 one selection
selection and not filter                  exclusion
selection1 or selection2
1 of selection_*                          any selection matching the glob
all of selection_*                        every selection matching the glob
1 of them / all of them                   every selection in the rule
(sel_a or sel_b) and not 1 of filter_*    parentheses for grouping
```

Precedence: `not` > `and` > `or`. Write parentheses anyway; reviewers should not have to
remember precedence. Naming convention in SigmaHQ: `selection*` for positive matches,
`filter_main_*` for filters that apply always, `filter_optional_*` for environment-specific
ones. The old `| count() > N` aggregation is deprecated; use a **correlation rule**
(`correlation:` block with `type: event_count | value_count | temporal | temporal_ordered`)
in a separate document.

## Converting to a backend

```bash
# install once (pipx/uv keeps it isolated)
pipx install sigma-cli
sigma plugin install splunk            # also: microsoft365defender, azure (sentinel), elasticsearch, kusto, ...

sigma convert -t splunk -p sysmon rule.yml
sigma convert -t kusto  -p microsoft_xdr rule.yml
sigma convert -t esql   -p ecs_windows rule.yml
sigma check rules/                     # the official validator; run it in CI if available
```

Pipelines (`-p`) do the field-name mapping (Sigma `Image` -> Defender `FolderPath`,
Splunk `process_path`, ECS `process.executable`). If a field has no mapping the conversion
fails loudly; that is the moment to add a custom pipeline, not to hand-edit the output.
Hand-edited queries drift from the rule; keep the Sigma file as the source of truth and
regenerate. For query syntax details on each platform, use the `siem-query-authoring`
skill.

## Field names by common backend (process_creation)

| Sigma | Sysmon (Windows XML) | Defender XDR `DeviceProcessEvents` | Splunk CIM `Processes` | ECS |
|---|---|---|---|---|
| `Image` | `Image` | `FolderPath` | `process_path` | `process.executable` |
| `CommandLine` | `CommandLine` | `ProcessCommandLine` | `process` | `process.command_line` |
| `ParentImage` | `ParentImage` | `InitiatingProcessFolderPath` | `parent_process_path` | `process.parent.executable` |
| `ParentCommandLine` | `ParentCommandLine` | `InitiatingProcessCommandLine` | `parent_process` | `process.parent.command_line` |
| `User` | `User` | `AccountName` | `user` | `user.name` |
| `OriginalFileName` | `OriginalFileName` | `ProcessVersionInfoOriginalFileName` | `original_file_name` | `process.pe.original_file_name` |
| `Hashes` / `sha256` | `Hashes` | `SHA256` | `process_hash` | `process.hash.sha256` |
| `ComputerName` | `Computer` | `DeviceName` | `dest` | `host.name` |
