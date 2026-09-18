# FLASH: <one-line headline: actor/campaign + what it does to whom>

**TLP:** <CLEAR | GREEN | AMBER | AMBER+STRICT | RED>   **Ref:** <TEAM-FLASH-YYYY-NNN>
**Issued:** <YYYY-MM-DD HH:MMZ>   **Author:** <name / team>   **Expires / next update:** <date or "on change">
**Source grading:** <A1..F6 per Admiralty code> (<source name or "internal telemetry">)
**Relevance to us:** <High | Medium | Low>: <one clause on why: matches PIR-N / we run the affected product / observed in our estate>

## What is happening
Three to five sentences. Who, what, against whom, since when, how it is known. State
what is confirmed vs. reported vs. assessed, and by whom. No indicator lists here.

## Why it matters to <yourcompany.example>
- Exposure: <systems/products/business units affected, count if known>
- Observed in our estate: <yes: ticket ID | no: checked <sources> over <window> | not yet checked>
- PIR link: <PIR-N: title>

## Key TTPs
| Tactic | Technique | Detail | Confidence |
|---|---|---|---|
| Initial Access | T1566.001 | Invoice-themed ISO attachment | high |

ATT&CK version: <Enterprise v17>. Full mapping via `mitre-attack-mapping` if needed.

## Indicators (defanged; full list attached / in TIP as <collection id>)
| Indicator | Type | Role | Confidence | Valid until |
|---|---|---|---|---|
| example[.]invalid | domain | C2 | high | <date> |

## Actions
| # | Action | Owner | Due | Status |
|---|---|---|---|---|
| 1 | Block/alert on the indicators above at <proxy/DNS/EDR> | SOC | <date> | open |
| 2 | Retro-hunt <window> for <indicator types / behaviour> | Hunt | <date> | open |
| 3 | Confirm patch level for <product> against <CVE> | Vuln mgmt | <date> | open |

## Detection and hunt asks
- Detection: <behaviour> -> `detection-engineering`
- Hunt: <hypothesis, data source> -> `threat-hunting`

## Confidence and gaps
Overall confidence <high/medium/low>. What we do not know: <list>. What would change the
assessment: <list>.

## Sources
1. <Title, publisher, date, URL or ticket> (grading <A1>)
2. <...>
