# Environment customization (edit me)

Replace placeholders with your values. Each section says what it changes in the workflow.

## SIEM and log locations
- SIEM: `<Sentinel | Splunk | Elastic | Chronicle | other>`; console: `<siem-url>`; query help via `siem-query-authoring`
- Where each source lives (table/index and retention):
  | Source | Table / index | Retention | Time zone in export | Export procedure |
  |---|---|---|---|---|
  | Windows Security/System | `<SecurityEvent | index=wineventlog>` | `<90d>` | `<UTC in SIEM; local in Event Viewer CSV>` | `<saved search / wevtutil epl>` |
  | Sysmon | `<Event | index=sysmon>` | `<30d>` | UTC (`UtcTime`) | |
  | PowerShell 4104 | `<same as above>` | | | |
  | Linux auth/journal | `<Syslog | index=linux_auth>` | `<30d>` | `<host local; see timedatectl>` | `<journalctl --utc -o json>` |
  | auditd | `<index=auditd>` | | epoch | `<ausearch --raw>` |
  | Web access (Apache/nginx/IIS) | `<index=web>` | `<30d>` | `<offset in log | IIS UTC>` | |
  | Proxy / SWG | `<vendor export>` | `<90d>` | `<UTC>` | |
  | EDR timeline | `<DeviceProcessEvents | vendor console>` | `<30d>` | UTC | |
  | IdP sign-ins (hand to `identity-threat-investigation`) | `<SigninLogs | Okta System Log>` | | UTC | |
  | Cloud control plane (hand to `cloud-incident-investigation`) | `<CloudTrail | AzureActivity | GCP audit>` | | UTC | |
- Windows Event Forwarding / collector present: `<yes/no>`; collector host `<name>`

Effect: decides which `--assume-tz` to pass per input and which gaps to declare when a source is missing or expired.

## Audit policy actually in force (so absence of events is interpreted correctly)
- Process creation (4688) with command line: `<yes/no>`; on servers: `<yes/no>`
- PowerShell script block (4104) and module logging: `<yes/no>`; PowerShell 7 logging: `<yes/no>`
- Sysmon deployed: `<yes/no>`; config baseline and version: `<sysmon-modular vX | custom>`; events included: `<1,3,7,10,11,12,13,22,...>`
- File share auditing (5140/5145): `<yes/no>`; object access SACLs on: `<NTDS.dit, SAM, LSASS, Run keys>`
- DS Access auditing on DCs (4662 for DCSync): `<yes/no>`
- auditd rules loaded on Linux: `<none | baseline (execve, identity, privileged) | full>`; rule file: `<path>`
- Shell history timestamps (`HISTTIMEFORMAT`): `<set/not set>`; sudo I/O logging: `<yes/no>`
- Web servers log `X-Forwarded-For`: `<yes/no>`; TLS inspection on the proxy: `<yes/no>`

## Time conventions
- Report time zone: UTC (always); local zones noted per source
- Corporate Windows hosts default zone: `<e.g. America/New_York, -04:00 in DST / -05:00 otherwise>`
- Data center Linux hosts: `<UTC>`
- NTP source and expected skew: `<ntp.yourcompany.example, < 1 s>`; known hosts with drift: `<list>`

## Naming conventions (for filtering)
- Hostnames: workstations `<WS-*>`, servers `<SRV-*>`, DCs `<DC-*>`, domain `<corp.yourcompany.example>`
- Admin accounts: `<adm-*>`, service accounts `<svc-*>`, machine accounts end with `$`
- Known benign high-volume actors: vulnerability scanner IPs `<203.0.113.10-12>`, backup account `<svc-backup>`, monitoring UA `<...>`, patch window `<Sat 02:00-06:00 local>`

## Evidence handling
- Evidence store: `<\\evidence-share\<case-id>\ | S3 bucket | case tool>`; access restricted to `<group>`
- Hash on collection: `certutil -hashfile <file> SHA256` / `sha256sum <file>`; record in the case notes
- Custody one-liner (one per export): `<UTC time> | <collector> | <artifact> | <source host/system> | <method> | SHA-256 <hash> | stored at <path>`
- Native formats kept alongside derived CSV: `<yes, always>`
- Collection tooling for host triage: `<KAPE | Velociraptor | CyLR | vendor EDR live response>`
- Legal hold / privacy contact for exports containing personal data: `<role>`

## Escalation and hand-offs
- Findings that require immediate escalation to `incident-triage` / IR lead: `<credential dumping (Sysmon 10 on LSASS, NTDS access), log clearing on a server, DCSync, ransomware precursors (shadow copy deletion, mass renames), webshell confirmed>`
- Contact for domain controller evidence: `<AD team>`; for web servers: `<platform team>`; for cloud logs: `<cloud team>`
- Incident report owner (`incident-report-writing`): `<role>`; timeline CSV format they expect: the `timeline_builder.py --format csv` columns
