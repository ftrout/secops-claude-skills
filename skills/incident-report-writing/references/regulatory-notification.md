# Regulatory and contractual notification checklist

**Current as of September 2026. Verify every deadline with counsel before relying on it.**
Regimes change, thresholds depend on facts (data types, resident counts, sector, listing
status), and several clocks start from a *determination* rather than from discovery. This
file exists so the team asks the right questions early, not so it can skip the lawyer.

## How to use this file

1. Within the first hours, work through the **trigger questions** and hand the answers to
   counsel/privacy. Recording the answers, with times, is itself evidence of diligence.
2. Log every potentially applicable regime in the incident tracker with: clock-start event,
   clock-start time (UTC), deadline (UTC), owner, status. Use the table in
   `assets/post-incident-report.md` section 8.
3. Draft notifications early from the templates in this skill, but nothing goes out without
   the reviewers named in `environment.md`.

## Trigger questions (answer with evidence, not assumptions)

- What **types of data** were accessed, acquired, or exposed? Personal data (names, IDs,
  contact), sensitive categories (health, financial, credentials, biometrics, children),
  payment card data, regulated sector data (defense, critical infrastructure).
- **Whose** data: residents of which countries / US states, customers, employees, patients,
  minors? Approximate counts per jurisdiction.
- Is there evidence of **exfiltration or acquisition**, or only access/exposure? Encrypted at
  rest with keys not compromised? These distinctions drive many safe-harbour provisions.
- Are we a **controller or processor** (GDPR terms) for the data? Processors notify controllers.
- Are we a **public company** (SEC), a **financial entity** (DORA, banking rules, NYDFS, FTC
  Safeguards), a **covered entity or business associate** (HIPAA), an **essential/important
  entity** (NIS2), a **defense contractor** (DFARS), critical infrastructure (CIRCIA)?
- What do our **contracts** say: customer DPAs, cyber insurance policy, cloud/service provider
  terms, payment card agreements? Insurance policies commonly require notice within days and
  before engaging outside counsel or forensics.
- Was a **ransom** demanded or paid? Several regimes have separate payment-reporting clocks,
  and sanctions screening (OFAC and equivalents) applies before any payment.

## Regimes and clocks (verify with counsel)

| Regime | Applies to | Clock | Clock starts from | Notify | Notes |
|---|---|---|---|---|---|
| EU GDPR Art. 33 / 34 | Controllers of EU residents' personal data | 72 h to supervisory authority; data subjects "without undue delay" when high risk | Becoming *aware* of the breach | Lead supervisory authority; data subjects | Document every breach even if not notifiable (Art. 33(5)); processors notify controllers without undue delay |
| UK GDPR / DPA 2018 | Controllers of UK residents' data | 72 h | Awareness | ICO; data subjects if high risk | Mirrors EU GDPR |
| EU NIS2 (Directive 2022/2555) | Essential and important entities, per national transposition | Early warning 24 h; incident notification 72 h; final report within 1 month | Awareness of a *significant* incident | National CSIRT / competent authority | Transposition varies by member state; check your national law |
| EU DORA (Reg. 2022/2554, applies from 17 Jan 2025) | Financial entities | Initial 4 h after classification as major and no later than 24 h from awareness; intermediate 72 h; final within 1 month | Awareness / classification | Competent financial authority | Major ICT-related incidents; voluntary for significant cyber threats |
| US SEC Form 8-K Item 1.05 (adopted July 2023) | US-listed public companies | 4 business days | *Materiality determination*, which must be made without unreasonable delay after discovery | Public filing | AG may permit delay for national security / public safety; foreign private issuers use Form 6-K; immaterial or undetermined incidents may be disclosed under Item 8.01 instead |
| US HIPAA Breach Notification Rule (45 CFR 164.400-414) | Covered entities and business associates, PHI | Individuals: without unreasonable delay, max 60 calendar days; HHS: within 60 days if 500+ (plus media in the state/jurisdiction); under 500: annual log to HHS within 60 days of year end | Discovery | Individuals, HHS, media where required | Business associates notify the covered entity within 60 days (contracts often shorter); encrypted PHI safe harbour when keys are not compromised |
| US state breach laws | Any entity holding residents' PII; all 50 states plus DC and territories | Varies: many "without unreasonable delay"; several fixed, e.g. 30 days (Colorado, Florida, Washington), 60 days (Texas) | Discovery / determination that a breach occurred | Residents; AG or state agency above thresholds (often 500 or 1,000 residents); consumer reporting agencies above thresholds | Definitions of PII and of "breach" differ per state; check each state where affected residents live |
| US CIRCIA (2022) | Covered critical-infrastructure entities | 72 h for covered incidents; 24 h for ransom payments (as proposed) | Reasonable belief a covered incident occurred / payment made | CISA | Final rule status must be verified; obligations bind only once the final rule is effective |
| US federal banking rule (OCC/FRB/FDIC, effective April 2022) | Banking organizations and their service providers | 36 h | Determination that a notification incident occurred | Primary federal regulator | Service providers notify affected bank customers as soon as possible |
| US NYDFS 23 NYCRR 500.17 | NY-licensed financial services companies | 72 h; extortion payment 24 h plus written explanation within 30 days | Determination that a cybersecurity incident occurred | NYDFS | Amended November 2023 |
| US FTC Safeguards Rule (16 CFR 314, notification effective May 2024) | Non-bank financial institutions under GLBA | 30 days | Discovery of a notification event affecting 500+ consumers | FTC | Unencrypted customer information |
| US DFARS 252.204-7012 | DoD contractors handling covered defense information | 72 h | Discovery | DoD via DIBNet | Preserve images and logs for 90 days |
| US federal agencies (FISMA guidance) | Federal agencies and their systems | 1 h | Identification | CISA | Contractors operating federal systems inherit this via contract |
| PCI DSS v4.0 Req. 12.10 and brand rules | Merchants and service providers handling card data | Per acquirer / card brand rules, typically within days | Suspected or confirmed compromise | Acquirer, card brands, possibly PFI engagement | Check the merchant agreement; brand programmes differ |
| Canada PIPEDA | Organizations subject to PIPEDA | "As soon as feasible" | Determination of a real risk of significant harm | Privacy Commissioner; affected individuals | Keep breach records for 24 months; provincial laws (e.g. Quebec Law 25) add obligations |
| Australia Privacy Act NDB scheme | APP entities | Assess within 30 days; notify as soon as practicable | Suspicion of an eligible data breach | OAIC; affected individuals | Cyber Security Act 2024 adds ransomware-payment reporting within 72 h for in-scope businesses (from May 2025); verify thresholds |
| India CERT-In directions (April 2022) | Service providers, intermediaries, bodies corporate in India | 6 h | Noticing the incident | CERT-In | Very short clock; log retention obligations too |
| Singapore PDPA | Organizations subject to PDPA | 3 calendar days to PDPC after assessing the breach is notifiable; assessment within 30 days | Assessment | PDPC; affected individuals | Thresholds: significant harm or 500+ individuals |

## Contractual and voluntary

| Party | Typical requirement | Why it matters |
|---|---|---|
| Cyber insurer | Notice "as soon as practicable", often within days; pre-approval of vendors | Late notice can void coverage; the panel may dictate counsel and forensics |
| Customers under DPAs / MSAs | Often 24 to 72 h from awareness for processor-side incidents | Missing it is a contract breach independent of any regulator |
| Cloud / SaaS providers | Shared-responsibility terms; abuse reporting | Provider logs may be needed and have short retention |
| Law enforcement (FBI IC3, NCA, national CERTs) | Voluntary in most jurisdictions | Can enable asset recovery for BEC; may affect ransom sanctions exposure |
| Auditors, board, audit committee | Governance policies | Materiality assessment is a board-level process for listed companies |

## Drafting rules for any external notification

- Facts only, with dates in UTC and the local time of the recipient in parentheses.
- Say what is known, what is being investigated, and when the next update will come.
- Do not name the attacker, speculate on motive, or characterise the attack as
  "sophisticated" unless counsel and the evidence agree.
- Include concrete recipient actions (reset password, watch for X, contact Y) and a contact
  channel that is staffed.
- Keep a version log: which draft went to whom and when. Regulators ask.
- Attacker communications (ransom notes, "proof" listings) are evidence to quote carefully
  and never to act on as instructions.
