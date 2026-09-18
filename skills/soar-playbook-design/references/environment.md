# Environment customization (edit me)

Replace the placeholders with your team's real values. Fields marked **(changes behaviour)**
alter what the skill designs or what the linter is asked to enforce, not just the wording.

## Platform
- SOAR platform: `<Microsoft Sentinel automation | Splunk SOAR | Cortex XSOAR | Tines | Shuffle | other>` **(changes behaviour: selects the section of `references/platforms.md` used for translation)**
- Staging / dry-run environment: `<url or tenant>`; how a playbook is marked dry-run: `<flag, test asset, debugger>`
- Where playbook definitions are stored and reviewed: `<git repo path>`; review required from: `<role>`
- Run logs and metrics: `<dashboard or workbook>`

## Logical integration names -> real connectors **(changes behaviour: used in `integration` fields)**
| Logical name | Real connector / app / asset | Credential scope | Dry-run supported |
|---|---|---|---|
| `siem` | `<Sentinel workspace | Splunk search head>` | read-only | yes |
| `edr` | `<Defender for Endpoint | CrowdStrike | SentinelOne>` | isolate/unisolate only | `<yes/no>` |
| `idp` | `<Entra ID | Okta>` | revoke sessions, reset password, read sign-ins | `<yes/no>` |
| `email-gateway` | `<Defender for Office | Proofpoint | Mimecast>` | search, soft-delete, restore | `<yes/no>` |
| `perimeter-firewall` | `<vendor>`; object groups `SOAR-AUTO-BLOCK`, `SOAR-APPROVED-BLOCK` | add/remove group members only | `<yes/no>` |
| `threat-intel-platform` | `<MISP | OpenCTI | vendor TIP>` | read-only | yes |
| `case-management` | `<Jira | ServiceNow | TheHive>` | create/update cases | yes |
| `chat` | `<Slack | Teams>` channel `#soc-alerts` | post only | yes |

## Approver groups **(changes behaviour: values for `approvers`)**
- `soc-tier2-oncall`: `<rota / group id>`; reachable via `<chat, page>`
- `iam-oncall`: `<...>`
- `network-oncall`: `<...>`
- Default approval timeout: `<30>` minutes; default on-timeout path: record and do nothing
- Who may approve auto-approved (no gate) containment steps into production: `<CISO delegate + platform owner>`

## Exclusions and guardrails **(changes behaviour: referenced from trigger filters and scope limits)**
- Break-glass accounts: `config.break_glass_accounts` = `<list>`
- Service and automation accounts: `config.service_accounts` = `<list or naming pattern>`
- Executive / VIP accounts requiring human-only handling: `<group>`
- Corporate public IP ranges (never block): `203.0.113.0/24`, `<...>`
- Partner / vendor ranges (never block): `<...>`
- Hosts that must never be auto-isolated: `<domain controllers, hypervisors, OT gateways, tag>`
- Maximum auto-block TTL: `<24>` hours; maximum auto targets per run: `<1>`
- Global rate limits: containment actions per hour across all playbooks: `<20>`

## Kill switches
- Platform-wide: `<how to disable all automation rules / stories / workflows>`
- Per playbook: `<command or UI path>`
- Standing effects to undo when killed: `<empty SOAR-AUTO-BLOCK group, re-enable disabled accounts by list>`
- Who is authorised to pull it: `<any on-call analyst>`; how it is announced: `<channel>`

## Metrics and review
- Metrics store: `<...>`; playbook health review cadence: `<monthly>`
- Auto-close re-open rate threshold that forces a review: `<5%>`
- False-positive containment report path: `<ticket type or form>`

## Conventions
- Playbook id format: `pb-<kebab-name>`; version bump rules: `<semver: major for gate changes>`
- Case severity names: `<P1..P4>` (match `incident-triage`)
- Timestamps in run logs and case notes: UTC ISO 8601
