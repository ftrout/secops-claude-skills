# Severity model

Severity answers one question: **how fast, and by whom, must this be worked?** It is not
a measure of how interesting the alert is. The model here is deliberately simple so an
analyst can reproduce it in their head and defend it in a review.

```
exposure   = weighted mean of impact, asset_criticality, spread, data_sensitivity   (1..5 each)
score      = 100 x (exposure / 5) x (confidence / 5)
tier       = P1 (>= 75) | P2 (>= 50) | P3 (>= 25) | P4 (< 25), then floor/ceiling rules
```

"How bad is it if true" times "how sure are we" is the classic risk shape. Confidence is a
multiplier rather than a weighted term because a probable false positive on a domain
controller should not out-rank a confirmed compromise of a workstation. The weights,
thresholds, and rules live in `severity-weights.json` and are read by
`scripts/triage_score.py`; nothing in this file is hard-coded in the script except the
factor names.

## Factor definitions

Score each factor on what you can **evidence now**, not on what you fear. If you cannot
evidence a factor, score it 3 ("unknown") and say so in the triage note; the sensitivity
line in the script output tells you whether resolving that unknown would change the tier.

### Confidence (multiplier)
| Value | Meaning | Typical evidence |
|---|---|---|
| 1 | Probably benign; matches a documented false-positive pattern | Prior tickets, tuning notes, change ticket found |
| 2 | Unclear, benign explanation more likely than not | Plausible benign story, not yet verified out-of-band |
| 3 | Plausible either way, needs more data | Alert only, no corroboration, no benign explanation found |
| 4 | Likely true positive | One or two independent corroborating artifacts (process + network, sign-in + mail rule) |
| 5 | Confirmed | Hands-on-keyboard, payload retrieved, exfil observed, user admits credential entry |

### Impact (weight 1.2)
| Value | Meaning |
|---|---|
| 1 | No effect: blocked or quarantined before execution |
| 2 | Single low-privilege user or workstation affected |
| 3 | Service degradation, or a privileged user session involved |
| 4 | Server- or domain-level compromise, or data access confirmed |
| 5 | Business-critical outage, ransomware, or confirmed exfiltration |

### Asset criticality (weight 1.0)
| Value | Meaning |
|---|---|
| 1 | Lab, test, disposable |
| 2 | Standard workstation |
| 3 | Internal server or shared service |
| 4 | Production, customer-facing, or an admin's workstation |
| 5 | Crown jewel: domain controller, IdP, PKI, backup infrastructure, payment systems, PHI/PII stores |

Pull this from the asset inventory or CMDB where one exists; `environment.md` lists the
field. An admin's workstation is a 4 because it is one hop from everything.

### Spread (weight 0.8)
| Value | Meaning |
|---|---|
| 1 | One host or one account |
| 2 | Two to five hosts/accounts within one team |
| 3 | One site, VLAN, or business unit |
| 4 | Multiple sites or business units |
| 5 | Organization-wide, or supply-chain / third-party involvement |

Spread is weighted lower because most alerts start at 1 and it is the factor most likely to
be revised upward during scoping; the floor rule on spread 5 covers the extreme case.

### Data sensitivity (weight 0.8)
| Value | Meaning |
|---|---|
| 1 | Public or no data involved |
| 2 | Internal, low sensitivity |
| 3 | Confidential business data |
| 4 | Customer PII, credentials, source code |
| 5 | Regulated: PHI, PCI, financial records, classified, legal hold |

Sensitivity matters for notification clocks more than for response speed, which is why it
is weighted lower but has its own floor rule (likely-true activity on regulated data is at
least P2).

## Floors and ceilings

Weighted scores are smooth; real policy has cliffs. The rules encode the cliffs so the
score cannot argue its way around them:

| Rule | Effect | Why |
|---|---|---|
| confidence 5 and impact 5 | at least P1 | Confirmed business-critical impact is an incident, full stop |
| confidence 5 and asset 5 | at least P2 | Confirmed activity on a crown jewel is never worked "this shift" |
| confidence 4 and data 5 | at least P2 | Regulatory notification clocks may already be running |
| confidence 3 and spread 5 | at least P2 | Org-wide anything needs a coordinator |
| confidence 1 | at most P4 | Probable false positives are tuning work, not escalations |
| impact 1 and confidence 3 or lower | at most P3 | Blocked-before-execution with no confirmation is a tuning task |

Floors fire when every listed factor is **at least** the value; ceilings fire when every
listed factor is **at most** the value. Floors are applied before ceilings, so a ceiling
wins on conflict; if that is the wrong policy for you, reorder or remove the rule.

## Tier meanings (defaults)

| Tier | Response | Owner | Typical clock |
|---|---|---|---|
| P1 | Page on-call, open a bridge, name an incident commander | IR lead | Acknowledge in 15 min, update hourly |
| P2 | Work immediately, escalate to tier 2 / IR | Tier 2 | Acknowledge in 30 min, update every 4 h |
| P3 | Work this shift | Tier 1 | Resolve or hand over by end of shift |
| P4 | Queue, tune, or close with a note | Tier 1 / detection engineering | Weekly review |

Your SLAs and ownership go in `environment.md`; the labels in `severity-weights.json` are
what the script prints.

## Worked examples

| Alert | C | I | A | S | D | Score | Tier | Note |
|---|---|---|---|---|---|---|---|---|
| LSASS access by renamed archiver on a file server, one host | 4 | 4 | 4 | 1 | 4 | 53.9 | P2 | Confidence 3 would drop it to P3: get the corroboration first |
| New-country sign-in, user on travel list, MFA satisfied | 1 | 2 | 2 | 1 | 2 | 7.2 | P4 | Ceiling: close with note, consider tuning |
| Unknown script on internal server, plausible, one host | 3 | 3 | 3 | 2 | 3 | 33.5 | P3 | Work this shift; resolve the unknowns |
| Confirmed ransomware on DC, org-wide | 5 | 5 | 5 | 4 | 5 | 95.8 | P1 | |
| Confirmed web shell on one DC, no spread yet | 5 | 4 | 5 | 1 | 3 | 68.4 | P2 | Floor (confidence 5, asset 5) guarantees P2 |
| Gateway blocked a known malware attachment, 40 recipients | 3 | 1 | 2 | 3 | 2 | 22.7 | P4 | Blocked, unconfirmed: check who opened it, then re-score |
| Blocked exploit attempt against an exposed crown jewel, org-wide scan | 3 | 1 | 5 | 5 | 5 | 44.8 | P3 | Floor (spread 5) raises to P2, ceiling (impact 1) caps at P3 |

## Re-scoring

Severity is re-scored whenever a factor changes: after scoping (spread), after
corroboration (confidence), after the asset owner answers (criticality). Record each
re-score in the triage note with the time and the reason, because the timeline in
`incident-report-writing` will need to show when the team knew what.
