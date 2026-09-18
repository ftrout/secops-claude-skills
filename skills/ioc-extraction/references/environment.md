# Environment customization (edit me)

Replace the placeholders with your team's real values. Keep it short; it is loaded into
context whenever the skill needs it.

## Our identifiers (never emit as indicators)
- Corporate domains: `yourcompany.example`, `mail.yourcompany.example`
- Public IP ranges: `203.0.113.0/24`
- SaaS we own: `yourcompany.okta.com`, `yourcompany.sharepoint.com`

Also add these as globs to `allowlist.txt` so the script drops them automatically.

## Where indicators go
| Destination | Format | Column order / notes |
|---|---|---|
| SIEM watchlist (e.g. Sentinel Watchlist, Splunk lookup) | CSV | `indicator,type,role,confidence,first_seen,source` |
| EDR custom IOC list | plain list per type | SHA-256 only for hashes; max 5,000 entries |
| DNS filter / proxy blocklist | plain list, domains + URLs | change ticket required |
| TIP (e.g. MISP, OpenCTI) | STIX 2.1 | tag `tlp:amber` unless the source says otherwise |

## Enrichment we have access to
- [ ] VirusTotal (API key location: ...)
- [ ] GreyNoise
- [ ] AbuseIPDB
- [ ] Internal passive DNS
- [ ] MCP tools available in this Claude session: (list them)

## Retro-hunt defaults
- Look-back window: 30 days for network indicators, 90 days for hashes
- Data sources: proxy, DNS, EDR process/file events, mail gateway
