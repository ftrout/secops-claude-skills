# Environment customization (edit me)

Fill in for your directory. The skill uses this to decide which platform reference to
follow, which sign-ins are expected, and who must approve containment.

## Identity platforms

| Plane | Product | Tenant / domain | Admin console | Who owns it |
|---|---|---|---|---|
| Primary IdP | Entra ID / Okta / Google Workspace | `yourcompany.onmicrosoft.com` / `yourcompany.okta.com` | `<url>` | `<team>` |
| On-prem directory | Active Directory forest `corp.yourcompany.example` | DCs: `dc01`, `dc02` (`<site>`) | | `<team>` |
| Hybrid sync | Entra Connect (PHS / PTA / federation via `<adfs-or-idp>`) | | | password writeback: `<yes/no>` |
| Federated relying parties | AWS IAM Identity Center, GCP Workforce Identity, GitHub, VPN, `<others>` | | | affects blast radius |

## Where the logs are

| Log | Location | Retention | Notes |
|---|---|---|---|
| Entra sign-ins (interactive, non-interactive, SP, MI) | Log Analytics `<workspace>` (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, ...) and `<siem-url>` | 90 d | portal export is 30 d |
| Entra audit | `AuditLogs` in same workspace | 90 d | |
| Identity Protection risk | `AADUserRiskEvents`, `AADRiskyUsers` | 90 d | requires P2 |
| Office / Exchange audit | `OfficeActivity` or Purview audit search | 180 d | inbox rules, forwarding |
| Graph activity | `MicrosoftGraphActivityLogs` | `<on/off>` | |
| Okta System Log | Okta admin > Reports > System Log; streamed to `<siem>` index `<okta>` | 90 d in Okta | |
| Workspace login / admin / OAuth audit | Admin console > Reporting; exported to `<bq-dataset>` | 6 months | |
| AD Security events | forwarded from DCs to `<siem>` (`SecurityEvent` / index `wineventlog`) | 365 d | confirm 4662 / 5136 SACL auditing is on |
| Sysmon on DCs and tier-0 | `<siem>` | 90 d | process creation for NTDS / ntdsutil detection |

## Expected geography and networks (judge travel flags against these)

| Name | Ranges / ASN | Countries |
|---|---|---|
| Corporate egress | `203.0.113.0/24` | US |
| VPN egress | `198.51.100.0/25` (AS64496) | US, NL |
| Privacy relay / carrier NAT that our users hit | Apple iCloud Private Relay, `<carrier ASNs>` | varies |
| Offices | `<city>: <range>` | |
| Travel-heavy teams | Sales, Exec | any |

## Analyzer thresholds (`scripts/signin_analyzer.py`)

| Flag | Default | Our value | Why |
|---|---|---|---|
| `--baseline-days` | 7 | | first N days of each user's history define "known" countries and UAs |
| `--max-kmh` | 900 | | commercial flight speed; lower catches more, flags more VPN |
| `--travel-hours` | 2 | | used only when a country has no centroid |
| `--mfa-burst` / `--mfa-window` | 5 in 10 min | | MFA fatigue threshold |
| `--fts-window` / `--fts-min-failures` | 60 min, 2 failures | | failed-then-success from new IP |

## Accounts that need owner approval before containment

| Account | Purpose | Owner | Safe action | Unsafe action |
|---|---|---|---|---|
| `svc-scanner@yourcompany.example` | vulnerability scanner Graph access | `<team>` | rotate secret | disable (breaks scans) |
| `breakglass01@yourcompany.example` | emergency admin | CISO | verify use, rotate | disable |
| `<shared mailbox>` | | | | |

## Containment authority

| Action | Who approves | Where recorded |
|---|---|---|
| Reset password + revoke sessions (standard user) | on-call analyst | `<ticket-system>` |
| Disable account | IR lead | ticket |
| Remove app consent / disable OAuth app tenant-wide | IR lead + identity team | ticket |
| Block ASN / country in CA or Okta network zone | identity team lead | change record |
| Admin account reset, PIM changes | identity team lead + IR lead | incident channel `#<channel>` |
| krbtgt double reset | AD owner + CISO delegate | change record; schedule the second reset |

## Escalation

- Identity platform on-call: `<contact>`
- AD / domain admins: `<contact>`
- Legal / privacy (mailbox access decisions): `<contact>`
- User communication template: `<link>`
