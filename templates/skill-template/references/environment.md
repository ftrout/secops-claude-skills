# Environment customization (edit me)

## Tooling
- SIEM: `<Sentinel | Splunk | Elastic | Chronicle | other>`; console: `<url>`
- EDR: `<CrowdStrike | Defender for Endpoint | SentinelOne | other>`
- Ticketing: `<Jira | ServiceNow | TheHive>`; project key: `<KEY>`

## Thresholds and conventions
- Severity scale: `<P1..P4 | Critical/High/Medium/Low>`
- Business hours / on-call rotation: `<timezone, hours>`
- Naming: incidents `<INC-YYYY-NNNN>`, detections `<TEAM-NNNN>`

## Escalation
- Escalate to: `<role>` when `<condition>`
- Legal / privacy contact for PII-bearing incidents: `<role>`
