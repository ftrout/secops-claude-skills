# Environment customization (edit me)

Replace the placeholders with your organisation's real values. Fields marked
**(changes behaviour)** alter what the workflow does, not just what it prints.

## Organisation profile **(changes behaviour: drives the regulatory checklist)**
- Legal entities and countries of operation: `<Yourcompany Inc. (US), Yourcompany Ltd (UK), ...>`
- Publicly listed: `<yes: exchange, ticker | no>` (SEC 8-K Item 1.05 applies only if yes)
- Regulated sectors: `<healthcare (HIPAA) | financial (DORA, NYDFS, GLBA, banking rule) | critical infrastructure (NIS2, CIRCIA) | defense (DFARS) | payment cards (PCI DSS) | none>`
- Data categories we hold and where: `<customer PII (regions), PHI, PCI, employee data, source code>`
- Controller or processor for customer data: `<controller | processor | both, by product>`
- Cyber insurance: carrier `<name>`, policy notice window `<hours/days>`, panel counsel `<firm>`, notice contact `<...>`

## Reviewers and approvers **(changes behaviour: nothing external leaves without them)**
| Document | Drafted by | Reviewed by | Approved by |
|---|---|---|---|
| Status update | IC / scribe | - | IC |
| Executive summary | IC | CISO | CISO |
| Post-incident report | IR lead | system owners, security leadership | CISO |
| Customer / partner notice | comms + IR | legal, account owner | `<GC / CISO>` |
| Regulator notice | legal | IR lead | `<GC>` |
| Staff communication | comms | IR lead, HR if relevant | `<...>` |

- Legal / privacy contact: `<role, channel, out-of-hours number>`
- Communications / PR contact: `<role, channel>`
- Whether reports are prepared under legal privilege: `<yes: label with "Privileged & Confidential - prepared at direction of counsel" | no>`

## Cadence and distribution
- Status update cadence: P1 `<every 1 h>`, P2 `<every 4 h>`, P3 `<daily>`; always at status change
- Bridge / update channel: `<chat channel or bridge line>`; leadership distribution: `<list>`
- Executive briefing trigger: `<P1 always; P2 if customer data or > n users>`
- Post-incident report due: `<within 10 business days of closure>`; lessons-learned session within `<2 weeks>`
- Where reports live: `<wiki space / document repository>`; naming `<INC-YYYY-NNNN-PIR.md>`

## Conventions
- Incident ID format: `<INC-YYYY-NNNN>`; ticket system `<Jira | ServiceNow | TheHive>`
- Timestamps: UTC ISO 8601 in all documents; local time zone for regulator forms: `<Europe/London, America/New_York>`
- Classification labels: `<TLP:AMBER | Internal | Confidential>`
- Severity names as used in reports: `<P1..P4 | Sev1..Sev4>` (match `incident-triage`)
- Timeline gap threshold for `scripts/timeline_format.py`: `<4>` hours **(changes behaviour: `--gap-hours`)**
- Default assumed time zone for logs that lack one: `<Z | +02:00>` **(changes behaviour: `--assume-tz`)**
- ATT&CK version cited in reports: `<v17>`

## Stakeholder contacts
- Incident commander rota: `<schedule>`
- Executive sponsor for security incidents: `<role>`
- Customer support lead (for FAQ before customer notices): `<role>`
- Regulator portals / addresses we have used before: `<ICO portal, state AG links, ...>`
