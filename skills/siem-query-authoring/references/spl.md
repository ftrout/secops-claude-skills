# SPL: Splunk with the Common Information Model

Splunk Search Processing Language. The reliable way to write portable queries is against
CIM data models (`Endpoint`, `Network_Traffic`, `Web`, `Authentication`, `Email`, ...) via
`tstats`, because field names then stop depending on which add-on parsed the raw data. Fall
back to raw `index=... sourcetype=...` searches when you need fields the model does not
carry. Based on Splunk CIM 5.x documentation (2025) and Splunk Enterprise/Cloud 9.x.

## Anatomy of a search

```spl
index=wineventlog sourcetype=XmlWinEventLog EventCode=4688 earliest=-24h latest=now
    NOT user="*$"
| stats count min(_time) as first_seen max(_time) as last_seen by host, user, process_name
| sort -count
```

- Everything before the first `|` is the *base search*: index, sourcetype, time, and any
  term you can put there. Terms in the base search use the index (fast); filters after a
  `|` scan the events already retrieved (slow).
- `earliest`/`latest` inside the search string override the time picker and make the
  search self-contained; do that for anything you save or share.
- Field matching is case-insensitive for values by default (`user=Admin` matches `admin`);
  field *names* are case-sensitive. `CASE(...)` forces a case-sensitive value match.
- Wildcards: `process_name=*powershell*` works in the base search but only leading `*` is
  cheap-ish; leading wildcards defeat the index. `IN` accepts wildcards: `user IN ("svc_*")`.

## CIM data models and their fields

| Data model (object) | Typical sources | Fields you will filter on |
|---|---|---|
| `Endpoint.Processes` | Sysmon 1, 4688, EDR | `Processes.process_name`, `process`, `process_path`, `parent_process_name`, `parent_process`, `user`, `dest`, `process_hash`, `process_guid`, `original_file_name` |
| `Endpoint.Filesystem` | Sysmon 11, EDR | `Filesystem.file_name`, `file_path`, `file_hash`, `action`, `process_name`, `dest` |
| `Endpoint.Registry` | Sysmon 12/13 | `Registry.registry_path`, `registry_value_name`, `registry_value_data`, `action` |
| `Endpoint.Services` | 7045 | `Services.service_name`, `service_path` |
| `Network_Traffic.All_Traffic` | firewall, NetFlow, Sysmon 3 | `All_Traffic.src_ip`, `dest_ip`, `dest_port`, `action`, `bytes_out`, `app`, `user` |
| `Network_Resolution.DNS` | DNS server, Sysmon 22, Zeek | `DNS.query`, `answer`, `src`, `record_type`, `reply_code` |
| `Web` | proxy, ALB, IIS | `Web.url`, `url_domain`, `dest`, `src`, `user`, `http_method`, `status`, `http_user_agent`, `bytes_out` |
| `Authentication` | Windows, Okta, VPN, Linux | `Authentication.user`, `src`, `dest`, `action` (success/failure), `app`, `signature_id`, `authentication_method` |
| `Email.All_Email` | mail gateway, M365 | `All_Email.src_user`, `recipient`, `subject`, `file_hash`, `file_name`, `url`, `action` |
| `Change` | audit logs, cloud | `All_Changes.action`, `object`, `object_category`, `user`, `command` |
| `Malware.Malware_Attacks` | AV/EDR | `Malware_Attacks.signature`, `file_hash`, `file_path`, `dest`, `action` |
| `Intrusion_Detection.IDS_Attacks` | IDS/IPS | `IDS_Attacks.signature`, `src`, `dest`, `severity` |

`| datamodel Endpoint Processes search` shows what a model returns;
`| tstats count from datamodel=Endpoint.Processes by Processes.dest` tells you whether it is
accelerated and populated. If a model returns nothing, the add-on is not CIM-tagging the
data and you are back to raw searches.

## tstats pattern

```spl
| tstats summariesonly=true count min(_time) as first_seen max(_time) as last_seen
    from datamodel=Endpoint.Processes
    where earliest=-30d Processes.process_name="schtasks.exe" Processes.process="*/create*"
    by Processes.dest, Processes.user, Processes.process
| rename Processes.* as *
| sort -count
```

- `summariesonly=true` uses only accelerated summaries: fast, but misses the most recent
  minutes and anything not yet accelerated. Drop it (or set `false`) when completeness
  matters more than speed.
- `earliest=` goes inside `where`.
- Value lists: `where Processes.process_hash IN ("hash1","hash2")`.
- `tstats` can only group by fields in the model; add raw fields afterwards with a second
  search if needed.

## Count first, then rows

```spl
index=proxy earliest=-30d url_domain IN ("evil-domain.example","updates.evil-domain.example")
| stats count dc(src) as hosts min(_time) as first_seen max(_time) as last_seen by url_domain
| convert ctime(first_seen) ctime(last_seen)
```

Then `| table _time src user url` and `| head 100` once the numbers are sane.

## Lookups and joins

```spl
| inputlookup ioc_list.csv                              // view a lookup
index=proxy earliest=-30d [| inputlookup ioc_list.csv | fields url_domain | format]   // subsearch as OR-list
index=proxy earliest=-30d | lookup ioc_list.csv url_domain OUTPUT role confidence        // enrich rows
| where isnotnull(role)
```

- Subsearches (`[ ... ]`) are limited to 10,000 results and 60 seconds by default; a big
  IOC list should be a `lookup`, not a subsearch.
- `join` exists but is slow and truncates the subsearch at 50,000 rows; prefer
  `stats ... by common_field` over the union of both searches, or `lookup`.
- `| stats values(x) as x by key` after searching two sourcetypes together is the idiomatic
  SPL "join".

## Useful idioms

```spl
| stats count by _time span=1h                       // or: | timechart span=1h count by host
| eventstats count as total by host                  // add totals without collapsing
| rare process_name limit=50                         // long tail
| top limit=20 user                                  // head
| eval domain=lower(replace(url, "^https?://([^/]+).*", "\1"))
| rex field=process "-enc(?:odedcommand)?\s+(?<b64>[A-Za-z0-9+/=]{20,})"
| eval decoded=base64decode(b64)                     // Splunk 9+; UTF-16 needs extra handling
| transaction user maxspan=10m                       // group related events (expensive)
| dedup host process_name                            // first occurrence per combination
| fillnull value="-"
| where like(user, "svc_%")                          // SQL-ish match
| search NOT (user="*$" OR user="SYSTEM")
```

## Performance pitfalls

- `index=*` scans every index; name the index. `sourcetype=*` likewise.
- A search whose base is only `earliest=-30d` with all filters after the pipe reads every
  event in the window. Move terms to the base search.
- Leading wildcards (`*evil.example`) and `NOT` in the base search cannot use the index
  efficiently. `url_domain=evil.example OR url_domain=*.evil.example` is better than
  `url_domain=*evil.example`.
- `transaction` and `join` are memory-bound and silently truncate; `stats` scales.
- Regex extraction (`rex`) over millions of events is CPU-bound; filter first.
- Time picker vs search string: a saved search with no `earliest` runs over "all time" in
  some schedulers. Always specify.
- Splunk Cloud limits: scheduled searches quota, `max_searches_per_cpu`; a hunt that fires
  20 concurrent searches will queue behind alerting. Run big retro-hunts off-peak.
