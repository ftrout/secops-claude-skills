# Environment customization (edit me)

Replace placeholders with your values. Each field says what it changes in the workflow.

## Our domains and brands (pass to the script with --org-domain)
- Corporate mail domains: `yourcompany.example`, `mail.yourcompany.example`
- Brand / product domains users would trust: `yourproduct.example`
- Subsidiaries and partner domains that legitimately send as us (SPF includes / DKIM d=):
  `yourcompany.onmicrosoft.com`, `<marketing-esp>.example`, `<ticketing-saas>.example`
- Lookalike watchlist (registered or observed): `yourcompany-billing.example`, `yourc0mpany.example`
- Executives, finance, HR, and other VIP names to check for display-name impersonation: `<list or link to directory group>`

Effect: enables lookalike, internal-spoof, and VIP-impersonation findings; these raise severity.

## Mail platform and gateway
- Platform: `<Microsoft 365 | Google Workspace | Exchange on-prem | other>`
- Gateway / anti-phish layer: `<Defender for Office 365 | Proofpoint | Mimecast | Abnormal | other>`
- Where to get the original message with full headers: `<Threat Explorer | Message trace | Admin log search | Proofpoint TAP | quarantine>`
- Phishing report mailbox / button: `phish-reports@yourcompany.example`, `<Report Message add-in | vendor button>`
- Simulation vendor and the header it stamps (skip full analysis when present, still log it):
  `<X-PHISHTEST | X-KnowBe4-* | X-Gophish-* | vendor header>`
- Link rewriting in use: `<Safe Links | URL Defense | Mimecast Protect | none>`; click-log location: `<url>`

## Analysis tooling available
- [ ] URL sandbox / screenshot service: `<urlscan.io private | Browserling | internal>`; egress must be non-attributable: `<yes/no>`
- [ ] File sandbox: `<Tria.ge | ANY.RUN | VMRay | Joe | Defender detonation>`; policy on uploading customer data: `<never | TLP:AMBER only | allowed>`
- [ ] Reputation: `<VirusTotal (key location) | urlscan | passive DNS | WHOIS/RDAP>`
- [ ] QR decoder (offline): `<tool>`
- [ ] MCP tools available in this Claude session: `<list them>`
If a source is not listed here, mark it "not checked" in the note rather than guessing.

## Blast-radius searches
- Mail search tool and max look-back: `<Threat Explorer 30d | Advanced Hunting EmailEvents 30d | Gmail log search 30d | Splunk index=mail>`
- Standard search keys: sender address, sender domain, subject, URL host, attachment SHA-256, originating IP, Message-ID pattern
- Proxy / DNS logs for click confirmation: `<index or table>`
- Sign-in logs for credential-submitter checks: `<Entra SigninLogs | Okta System Log>` (hand to `identity-threat-investigation`)

## Response actions and who may take them
| Action | Tool | Self-service or change ticket |
|---|---|---|
| Soft-delete / purge from all mailboxes | `<Threat Explorer purge | Gmail investigation tool | search-mailbox>` | `<self-service if < N recipients>` |
| Block sender / domain / URL / hash | `<Tenant Allow/Block List | gateway policy | proxy blocklist>` | `<self-service>` |
| Submit sample to vendor | `<Submissions portal | vendor address>` | self-service |
| Reset password, revoke sessions and refresh tokens | `<Entra | Okta | AD>` | `<IAM team | self-service for tier 2>` |
| Remove inbox rules / OAuth consents | `<Exchange admin | Entra Enterprise apps>` | `<self-service>` |
| Block phone number (callback lures) | `<telephony admin>` | change ticket |
| Notify impersonated executive / vendor | `<comms owner>` | n/a |

## Thresholds and escalation
- Open an incident (hand to `incident-triage`) when: `<= N>` users clicked, `<= N>` submitted credentials, any VIP/finance targeted, any payment actioned, or malware confirmed on an endpoint
- Default blast-radius look-back: `<7 | 30>` days
- Severity mapping: credential submitted = `<High>`, click only = `<Medium>`, delivered unread = `<Low>`
- Escalate BEC with payment risk to: `<finance controller, legal>` within `<1 hour>`
- Time zone for the note: UTC (say so in the header)

## User communication
- Reporter thank-you template: `<link or short text>`
- Awareness team contact for campaign-wide notices: `<team>`
- Never include live links in user notices; defang or describe them
