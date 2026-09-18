# Enrichment sources and what each tells you

Only report enrichment results you actually obtained. If a source is unavailable in the
session, list it under "recommended enrichment" and leave the verdict blank.

| Indicator type | Source | What it answers |
|---|---|---|
| Any | VirusTotal | Multi-engine verdicts, first/last seen, relationships (contacted hosts, dropped files) |
| Hash | MalwareBazaar, Hybrid Analysis, Tria.ge | Family, sandbox behaviour, YARA matches |
| IP | GreyNoise | Is it mass-scanning background noise? (huge false-positive reducer) |
| IP | AbuseIPDB, Shodan, Censys | Abuse reports, open services, hosting provider, ASN |
| IP | Spur / IPinfo | Residential proxy / VPN / datacenter classification |
| Domain | passive DNS (SecurityTrails, Farsight, RiskIQ) | Resolution history, co-hosted domains, registration age |
| Domain | WHOIS/RDAP | Registrar, creation date (newly registered = suspicious), registrant privacy |
| Domain | urlscan.io | Screenshot, redirect chain, resources loaded |
| URL | urlscan.io, URLhaus | Payload hosting, phishing kit fingerprints |
| Email | DMARC/SPF records of the sending domain | Whether the sender domain is spoofable |
| CVE | NVD, CISA KEV, EPSS, vendor advisory | Severity, exploitation status, patch availability |
| Wallet | Blockchain explorers, Chainalysis/TRM (if licensed) | Payment activity, clustering with known ransomware groups |

## Internal enrichment (usually the most valuable)

- SIEM: has any host talked to this indicator in the look-back window? (proxy, DNS, firewall, EDR)
- EDR: has this hash executed anywhere? Where does this path exist?
- Mail gateway: did we receive mail from this sender/domain? Who received it? Was it delivered?
- Asset inventory: is the IP ours? Is it a partner's?
- Prior tickets: have we seen this indicator before? Was it a false positive?

## Reporting enrichment

One line per indicator so it fits in a ticket table:

```
1.2.3.4 | AS12345 (HostingCo), DE | GreyNoise: not seen | VT 6/94 | first seen 2026-09-01 | internal: 0 hits (30d proxy/DNS)
```
