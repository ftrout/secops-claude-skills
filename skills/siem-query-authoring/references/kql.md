# KQL: Microsoft Sentinel and Defender XDR advanced hunting

Kusto Query Language as used in Sentinel Log Analytics workspaces and the Defender XDR
advanced hunting portal. Both use the same language; the tables and the time column
differ. Sentinel-native tables use `TimeGenerated`; Defender XDR tables (`Device*`,
`Email*`, `UrlClickEvents`, `CloudAppEvents`, `IdentityLogonEvents`) use `Timestamp` and,
when streamed into Sentinel, also carry `TimeGenerated`. Verified against Microsoft Learn
schema pages, 2026; column names change occasionally, so `TableName | getschema` is the
authority in any session.

## Tables you will use most

| Table | Where | What it holds | Key columns |
|---|---|---|---|
| `SecurityEvent` | Sentinel (AMA/MMA) | Windows Security log | `EventID`, `Computer`, `Account`, `TargetUserName`, `IpAddress`, `LogonType`, `CommandLine` (4688), `SubjectUserName` |
| `SigninLogs` | Sentinel (Entra ID) | Interactive user sign-ins | `UserPrincipalName`, `IPAddress`, `Location`, `ResultType` (0 = success), `AppDisplayName`, `AuthenticationRequirement`, `ConditionalAccessStatus`, `DeviceDetail`, `RiskLevelDuringSignIn` |
| `AADNonInteractiveUserSignInLogs` | Sentinel | Token refreshes, non-interactive | Same shape; huge volume |
| `AuditLogs` | Sentinel (Entra ID) | Directory changes | `OperationName`, `Result`, `InitiatedBy`, `TargetResources` (dynamic) |
| `AzureActivity` | Sentinel | Azure control plane | `OperationNameValue`, `Caller`, `CallerIpAddress`, `ActivityStatusValue`, `ResourceGroup` |
| `OfficeActivity` | Sentinel (M365) | Exchange/SharePoint/Teams audit | `Operation`, `UserId`, `ClientIP`, `OfficeWorkload`, `Parameters` |
| `DeviceProcessEvents` | XDR | Process creation | `DeviceName`, `FileName`, `FolderPath`, `ProcessCommandLine`, `AccountName`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `SHA256` |
| `DeviceNetworkEvents` | XDR | Endpoint connections | `RemoteIP`, `RemotePort`, `RemoteUrl`, `LocalIP`, `ActionType`, `InitiatingProcessFileName` |
| `DeviceFileEvents` | XDR | File create/modify/delete | `FileName`, `FolderPath`, `SHA256`, `ActionType`, `InitiatingProcessFileName` |
| `DeviceRegistryEvents` | XDR | Registry changes | `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `ActionType` |
| `DeviceLogonEvents` | XDR | Endpoint logons | `AccountName`, `LogonType`, `RemoteIP`, `ActionType` |
| `DeviceImageLoadEvents` | XDR | DLL loads | `FileName`, `FolderPath`, `SHA256`, `InitiatingProcessFileName` |
| `DeviceEvents` | XDR | Everything else (AMSI, ASR, LDAP, named pipes...) | `ActionType`, `AdditionalFields` (dynamic) |
| `EmailEvents` | XDR | Mail flow | `SenderFromAddress`, `SenderMailFromAddress`, `SenderFromDomain`, `RecipientEmailAddress`, `Subject`, `DeliveryAction`, `ThreatTypes`, `NetworkMessageId` |
| `EmailUrlInfo` / `EmailAttachmentInfo` | XDR | URLs / attachments per message | `Url`, `UrlDomain` / `FileName`, `SHA256`; join on `NetworkMessageId` |
| `UrlClickEvents` | XDR (Safe Links) | User clicks | `Url`, `AccountUpn`, `ActionType`, `IsClickedThrough` |
| `CloudAppEvents` | XDR (Defender for Cloud Apps) | SaaS activity incl. M365 | `Application`, `ActionType`, `AccountObjectId`, `IPAddress`, `RawEventData` (dynamic) |
| `IdentityLogonEvents` / `IdentityDirectoryEvents` | XDR (Defender for Identity) | AD auth and directory changes | `LogonType`, `Protocol`, `AccountUpn`, `DeviceName`, `ActionType` |
| `CommonSecurityLog` | Sentinel (CEF) | Firewalls, proxies | `DeviceVendor`, `SourceIP`, `DestinationIP`, `DestinationPort`, `RequestURL`, `DeviceAction` |
| `Syslog` | Sentinel | Linux syslog | `Computer`, `Facility`, `SyslogMessage`, `ProcessName` |
| `DnsEvents` | Sentinel (DNS connector) | Windows DNS server queries | `Name`, `ClientIP`, `QueryType` |

## Time bounding

```kusto
// always first, always explicit; the UI time picker is not part of the saved query
DeviceProcessEvents
| where Timestamp > ago(7d)
// fixed window
| where TimeGenerated between (datetime(2026-09-01) .. datetime(2026-09-03))
```

Put the time filter before anything else. Kusto pushes predicates down but the habit
avoids scanning a year of `SecurityEvent` because the filter came after a `join`.

## Case sensitivity

| Operator | Case | Use for |
|---|---|---|
| `==`, `in`, `has`, `contains`, `startswith`, `endswith` | sensitive | rarely what you want on paths/users |
| `=~`, `in~`, `has_cs` (sensitive!), `contains_cs` | see name | `=~` and `in~` are the insensitive equals/in |
| `has` | sensitive, term-indexed | fast: matches whole terms (split on non-alphanumerics) |
| `has_any (list)`, `has_all (list)` | sensitive | many terms at once, still indexed |
| `contains` | sensitive, substring | slow on big tables; prefer `has` when the value is a whole term |
| `matches regex` | RE2 syntax | last resort |

Note the asymmetry: `has` is case-insensitive, `has_cs` is case-sensitive; `==` is
sensitive, `=~` is insensitive. Windows paths and usernames vary in case in the logs, so
default to `=~`, `in~`, `has`, and `endswith` (which is case-insensitive) for those.

## Count first, then rows

```kusto
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in~ ("203.0.113.56", "198.51.100.23")
| summarize hits=count(), first_seen=min(Timestamp), last_seen=max(Timestamp), hosts=dcount(DeviceName) by RemoteIP
```

Only after the count looks sane, `| project` the columns you need and `| take 100`.

## Lists and lookups

```kusto
let iocs = dynamic(["203.0.113.56", "198.51.100.23"]);       // inline list
let iocs2 = datatable(ip:string)["203.0.113.56", "198.51.100.23"];
let wl = _GetWatchlist('BadIPs') | project ip = SearchKey;    // Sentinel watchlist
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in~ (iocs)                                     // dynamic list
// or
| join kind=inner wl on $left.RemoteIP == $right.ip           // watchlist join
```

`in` accepts up to 1,000,000 values but queries with tens of thousands of literals get
slow to compile; chunk at a few hundred and use watchlists or `externaldata` for big
lists.

## Joins

```kusto
EmailEvents
| where Timestamp > ago(7d) and SenderFromDomain =~ "evil-domain.example"
| join kind=inner (EmailUrlInfo | where Timestamp > ago(7d)) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, Url
```

- Time-bound **both** sides; the right side of a join is not filtered by the left side's
  `where`.
- `kind=inner` (default is `innerunique`, which dedupes the left side on the key and
  surprises people), `leftouter`, `leftanti` (rows in left with no match; great for "hosts
  that did not check in").
- `join` materializes the right side; keep it small (`summarize` or `distinct` first).
- `lookup` is a cheaper left-outer join against a small dimension table.
- Correlate across time with `summarize make_set()` / `arg_min()` / `arg_max()` rather
  than self-joins when possible.

## Dynamic columns

```kusto
AuditLogs
| where TimeGenerated > ago(1d)
| extend target = tostring(TargetResources[0].userPrincipalName)
| extend initiator = tostring(InitiatedBy.user.userPrincipalName)
| mv-expand TargetResources           // one row per element when you need all of them
| extend props = parse_json(tostring(TargetResources.modifiedProperties))
```

Always `tostring()` / `toint()` before comparing; `dynamic == "x"` is false.

## Useful idioms

```kusto
| summarize count() by bin(Timestamp, 1h), DeviceName          // time series
| summarize arg_max(Timestamp, *) by DeviceName                 // latest row per host
| summarize make_set(ProcessCommandLine, 20) by DeviceName      // sample of values
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")  // fast multi-term
| extend b64 = extract(@"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| extend decoded = base64_decode_tostring(b64)                  // careful with UTF-16
| parse SyslogMessage with * "user=" user " " *                 // simple parsing
| top 20 by count_ desc
| distinct DeviceName
| project-away RawEventData
| count
```

## Performance pitfalls

- `contains` and `matches regex` on `ProcessCommandLine` over 30 days across the estate is
  a full scan. Use `has`/`has_any` for whole terms.
- `search "value"` across all tables is convenient and very expensive; time-bound it and
  use it once to find the table, then write a real query.
- `union *` similar. Name the tables.
- Advanced hunting in the portal has a 30-day lookback and result caps (10,000 rows in the
  UI, 100,000 via API); Sentinel retention is workspace-configured (default 90 days for
  analytics logs, longer for archive, which needs `search` jobs).
- Analytics rules run over their own lookback; a query that works ad hoc with `ago(30d)`
  will not see the same data inside a rule with a 1-hour period.
- `DeviceEvents` and `AADNonInteractiveUserSignInLogs` are the volume monsters; filter on
  `ActionType` / `ResultType` before anything else.
