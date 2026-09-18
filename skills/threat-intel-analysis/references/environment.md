# Environment customization (edit me)

Replace the placeholders with your team's real values. Keep it short; it is loaded into
context whenever the skill needs it.

## Threat profile (drives every relevance judgement)
- Organisation: `yourcompany.example`; sector(s): `<financial services | healthcare | ...>`
- Regions of operation: `<countries / regions>`; languages: `<list>`
- Crown-jewel systems and data: `<payments platform, PHI store, source code, OT>`
- Key technologies (used to match advisories and KEV): `<Entra ID, Okta, Fortinet, Palo Alto, Citrix, VMware, M365, AWS, GCP, ...>`
- Sector ISAC / sharing communities we belong to: `<FS-ISAC, H-ISAC, MS-ISAC, national CERT, ...>`
- Actors already tracked as relevant (profile IDs): `<TEAM-ACTOR-001 ...>`

## PIRs
- Location of the current PIR document: `<path or wiki URL>` (structure in `references/pir-template.md`)
- PIR-1: `<question>`  PIR-2: `<question>`  PIR-3: `<question>` (list the top three so relevance can be scored without opening the document)

## Marking and distribution
- Default TLP for products we author: `<TLP:AMBER>`; TLP version used: `<2.0>`
- Distribution lists: TLP:CLEAR/GREEN -> `<all-security@yourcompany.example>`; AMBER -> `<soc@ | ir@>`; AMBER+STRICT/RED -> `<named individuals>`
- Product reference format: `<TEAM-FLASH-YYYY-NNN>`, `<TEAM-ACTOR-NNN>`, `<TEAM-DIGEST-YYYY-WW>`
- Where products are published: `<TIP | wiki | ticket project>`

## Source grading defaults (Admiralty)
- Our own telemetry / IR findings: `A`
- ISAC, national CERT, `<vendors we license>`: `B`
- Other vendors and named researchers: `C` unless track record says otherwise
- Social media, forums, unknown handles: `F` until corroborated
- Record deviations for specific sources here: `<source: grade, reason>`

## Tooling
- TIP: `<MISP | OpenCTI | ThreatConnect | none>`; URL: `<tip-url>`; STIX export path: `<...>`
- Feeds we ingest: `<list>`; feeds we lack (collection gaps): `<list>`
- Enrichment available in this session (MCP tools or APIs): `<list>`; anything not listed is "not checked"
- SIEM for retro-hunts: `<Sentinel | Splunk | Elastic | Chronicle>`; default look-back: `<30 days network, 90 days hashes>`

## Cadence and escalation
- Flash alert criteria: `<confirmed exploitation of a product we run | actor observed in estate | KEV entry for internet-facing asset | A1/B1 report matching a priority-1 PIR>`
- Flash alert goes to: `<SOC lead, IR lead, vuln mgmt>` within `<N hours>`
- Weekly digest: published `<day>` to `<audience>`
- Actor profile review: `<quarterly>` or on material change
