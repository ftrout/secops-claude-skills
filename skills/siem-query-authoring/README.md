# siem-query-authoring

Turn an investigative question, a hunt hypothesis, or an indicator list into a correct,
time-bounded, count-first query for Sentinel/Defender KQL, Splunk SPL, Elastic, Chronicle
UDM, or Athena/BigQuery SQL.

Part of [secops-claude-skills](../../README.md).

## Overview

The dangerous outcome of a badly written SIEM query is not an error message. It is zero
rows. An analyst runs a search, gets nothing back, and writes "no evidence of compromise"
in a ticket — when the real explanation was the wrong table, a field that is never
populated in this deployment, a case-sensitive operator against case-varying data, or a
30-day window against a source retained for seven.

The other failures cost money instead of truth. A query with no time bound scans a year and
times out, or scans a year and bills for it. A 4,000-value `in` list pasted straight into a
rule brings the search head down. A `contains` on a tool name is both slow and trivially
evaded by renaming the binary. Portal row caps and subsearch truncation quietly hand back
the first page of results and let it pass as the whole answer.

This skill is deliberately slow at the start. It refuses to write a query until the
question names a field, picks the table from the environment file rather than from memory,
puts the time bound first and the cheapest high-selectivity term second, and always runs an
aggregation before it asks for rows. The count tells you whether the answer is three rows
or three million, whether the field is populated at all, and often *is* the answer —
first seen, last seen, distinct hosts.

For indicator lists, hand-writing the `in` clauses is where mistakes live, so a script does
it: refang, de-duplicate, pick the right table and field per indicator type per platform,
quote for the dialect, chunk to the platform's comfortable list size, and emit count-first
skeletons. Types with no mapping are reported out loud, never silently dropped.

## What it does

1. Clarifies the question until it names an entity, an action, a time window, and what a hit would mean.
2. Picks the platform and data source from the environment file, then confirms the field exists and is populated.
3. Writes the query with the time bound first, matching the platform's case rules and preferring exact operators over substring.
4. Generates the `in`-list clauses from an indicator file with `ioc_to_query.py` rather than by hand.
5. Runs a count query before any row query, and debugs a zero count by testing the pieces instead of guessing.
6. Delivers the query with its caveats: retention, coverage gaps, unverified fields, and applied exclusions.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The six-step workflow, the output template, the cross-platform translation table, and the pitfalls |
| `scripts/ioc_to_query.py` | Indicator list to per-platform count-first queries: refang, de-duplicate, map, quote, chunk |
| `references/kql.md` | Sentinel and Defender XDR: tables, time bounding, case sensitivity, lists, joins, performance pitfalls |
| `references/spl.md` | Splunk: search anatomy, CIM data models, the `tstats` pattern, lookups and joins |
| `references/elastic.md` | Elastic: ECS fields, Kibana KQL vs EQL vs ES\|QL, lookups, performance pitfalls |
| `references/chronicle.md` | Google SecOps: UDM structure and search syntax, YARA-L 2.0 basics, pivots |
| `references/sql.md` | Athena/BigQuery: CloudTrail and flow-log columns, partition pruning, nested data |
| `references/field-map.json` | Indicator type to table/field mapping per platform, plus per-platform `chunk_size`; read by the script |
| `references/environment.md` | Your customization file: platforms, data-source locations, default windows, limits, exclusions |
| `examples/` | An `ioc-extraction`-style CSV, a plain indicator list, and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *did anything in the estate talk to 203.0.113.56 in the last month*

> *turn this IOC csv into retro-hunt queries for sentinel and splunk*

> *my query returns nothing and I don't believe it*

> *translate this SPL to KQL, it's for the defender console*

### As a standalone tool

`ioc_to_query.py` is plain Python with no dependencies. It reads the CSV or JSON from
[ioc-extraction](../ioc-extraction/), or any plain one-per-line list.

```bash
# Sentinel/Defender, 90-day look-back, every mapped type
python scripts/ioc_to_query.py examples/iocs.csv --platform kql --lookback 90d

# Just the IPv4 values, Splunk CIM via tstats
python scripts/ioc_to_query.py examples/iocs.csv --platform spl --types ipv4

# Plain list on stdin, Chronicle UDM
cat examples/iocs.txt | python scripts/ioc_to_query.py - --platform chronicle --types url,email

# KQL with dynamic() lists instead of inline values
python scripts/ioc_to_query.py examples/iocs.csv --platform kql --types ipv4 --kql-let
```

Real output from the bundled sample:

```
Indicators: ipv4=2, domain=2, url=1, sha256=1, md5=1, email=1, cve=1

============ kql ============
// ipv4: 2 values, chunk 1/1
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in~ ("203.0.113.56", "198.51.100.23")
| summarize count(), first_seen=min(Timestamp), last_seen=max(Timestamp) by RemoteIP

// domain: 2 values, chunk 1/1
DnsEvents
| where TimeGenerated > ago(90d)
| where Name in~ ("evil-domain.example", "updates.evil-domain.example")
| summarize count(), first_seen=min(TimeGenerated), last_seen=max(TimeGenerated) by Name

Not generated:
  - kql: no field mapping for type `cve` (1 values skipped)
```

Several things in that output are the whole point. The CSV contains `203[.]0[.]113[.]56`
as a separate row from `203.0.113.56`; they refang to the same value and appear once. The
time column differs per table (`Timestamp` for `DeviceNetworkEvents`, `TimeGenerated` for
`DnsEvents`) and comes from the field map rather than from habit. Every query is an
aggregation with first/last seen. And the `cve` row is announced as unmapped instead of
vanishing — a CVE is not something you search a network table for.

Splunk, for the same indicators, becomes a `tstats` search against the CIM model:

```
| tstats count min(_time) as first_seen max(_time) as last_seen from datamodel=Network_Traffic where earliest=-30d (All_Traffic.dest_ip IN ("203.0.113.56", "198.51.100.23") OR All_Traffic.src_ip IN ("203.0.113.56", "198.51.100.23")) by All_Traffic.dest_ip, All_Traffic.src_ip
```

And a defanged URL in a plain-text list arrives at Chronicle refanged and quoted:

```
note: 1 line(s) skipped (unrecognized type or malformed value)
Indicators: email=1, url=1

============ chronicle ============
// url: 1 values, chunk 1/1; UDM search, set the time range in the UI
(target.url = "http://evil-domain.example/payload.php")
```

Other flags: `--chunk N` overrides the per-platform list size, `--map my-fields.json`
points at a team-specific field map, and `--format md|json` changes the output shape. The
script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input or
when no usable indicators were found.

## Install

This skill ships with the plugin. Inside Claude Code:

```
/plugin marketplace add ftrout/secops-claude-skills
/plugin install secops-skills@secops-claude-skills
```

To install just this skill, copy the folder:

```bash
git clone https://github.com/ftrout/secops-claude-skills
cd secops-claude-skills
./scripts/install.sh siem-query-authoring          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 siem-query-authoring         # Windows
./scripts/install.sh --project siem-query-authoring   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Two files, and unusually for this repo both are required reading rather than optional
polish.

`references/field-map.json` is the table-and-field mapping the script uses, and the stock
version is a reasonable default for stock schemas — which almost nobody has. Point a custom
TA, a renamed index, or a non-default ECS mapping at the wrong field and every query in the
set silently returns zero. Fix it here once. The same file carries `chunk_size` per
platform; `ioc_to_query.py --map my-fields.json` takes a team copy without editing the
shipped one.

`references/environment.md` is the higher-value edit of the two. The "where each data
source lives" table tells the skill which table and time column to target, and the list of
hosts and segments with no telemetry is what lets it say "not visible" instead of "no
activity" — the distinction the overview opens with. Also set the default look-back
windows, the row cap before a query must aggregate, and the service-account and scanner
patterns to exclude.

## Related skills

- Indicator lists come from [ioc-extraction](../ioc-extraction/) as CSV or JSON
- A question that is really a hypothesis about behaviour belongs to
  [threat-hunting](../threat-hunting/), which comes back here for the query
- Hits on indicators go to [incident-triage](../incident-triage/) for scoping
- A query worth running every hour becomes a rule in
  [detection-engineering](../detection-engineering/), which also owns Sigma conversion
