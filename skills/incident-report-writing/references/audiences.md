# Writing for each audience

The same incident is reported four or five times to people with different questions. The
mistake is writing one document and forwarding it. This file gives, per audience, what
they need, what they must not get, the shape of the document, and the cadence.

## Quick matrix

| Audience | Their question | Length | Template | Cadence during incident |
|---|---|---|---|---|
| Incident bridge / responders | What changed, what is next, who owns it | half page | `assets/status-update.md` | P1: every 1 to 2 h; P2: every 4 h or twice daily; always at status change |
| Executives / board | Are customers, money, and reputation at risk; what do you need from me | one page | `assets/exec-summary.md` | P1: at declaration, then daily and at major changes; P2: at declaration and close |
| Technical / audit / future responders | Exactly what happened, evidence, root cause, what to fix | as long as needed, with TOC | `assets/post-incident-report.md` | Once, within 5 to 10 business days of closure; draft sections as you go |
| Customers / partners | Am I affected, what should I do, can I trust you | one page or less | drafting rules below | As legal and contract require; then at resolution |
| Regulators | Did you meet the obligation; facts and timelines | per regime form | `references/regulatory-notification.md` | Per the clock; interim and final reports where required |
| Whole organisation / staff | What do I need to do differently | short | drafting rules below | Once, plus reminders if user action is required |
| Retro participants | What can we learn | facilitated session | `assets/lessons-learned.md` | Within 2 weeks of closure, before memories fade |

## Status updates (during the incident)

- One owner (the incident commander or scribe) publishes; everyone else contributes to
  them, not around them. Two competing update streams is how leadership hears two stories.
- Fixed cadence, announced in the first update, and **honoured even when there is nothing
  new**. "No change since 14:00Z, next update 16:00Z" prevents the side-channel questions
  that pull responders off the work.
- Structure: bottom line, what changed since last time, current impact, next steps with
  owners, decisions needed, notification clocks, confidence. Readers skim the first two
  sections; everything they need to act on goes there.
- Numbered updates with UTC timestamps in the title. Later, these become the response
  timeline, so each fact needs a source.
- Separate **confirmed** from **suspected** with words, not formatting. "We have confirmed
  X. We suspect Y and are checking Z."
- Never include live indicators, credentials, or attacker communications in a broad
  distribution update; defang and reference the ticket.

## Executive summary

- Bottom line up front: the first sentence says whether customers or regulated data are
  affected and whether it is contained.
- Plain language. Replace technique names with what they mean for the business ("the
  attacker could read email" rather than "T1114.002").
- Quantify: hours of downtime, number of accounts, records, currency. Ranges with a
  confidence statement are better than a false single number.
- Say what you need: approvals, budget, a decision on customer comms, or "nothing".
- Executives can handle uncertainty when it is explicit. What they cannot handle is a
  later fact that contradicts a confident earlier statement. Under-claim and update.
- One page. If it does not fit, the summary is not done.

## Technical post-incident report

- Written for a reader who was not there and for the auditor who reads it a year later.
  Every claim points to evidence (log source, query, ticket, screenshot hash).
- Timeline is the spine. Build it with `scripts/timeline_format.py` so it is UTC, ISO 8601,
  sorted, and gaps are visible. Flag gaps as **log gap** or **activity gap** and say how you
  know which.
- Distinguish confirmed / probable / unknown in the attack narrative. "We could not
  determine X because Y logs were retained for only 7 days" is a finding, not a failure to
  write.
- Root cause is a condition (missing MFA on a legacy protocol, unpatched edge device,
  runbook that did not include session revocation), not a person and not "the attacker".
- Map to ATT&CK with the version noted, using `mitre-attack-mapping`; it makes the report
  comparable with the next one and feeds `purple-team-exercise`.
- Action items are few, funded, owned, and dated. A report with 40 action items produces
  zero completed actions.

## Customer / partner notification drafts

- Always reviewed by legal and, where relevant, the account owner before sending.
- Structure: what happened (one paragraph, plain), what information was involved, what we
  have done, what you should do (specific steps), what we will do next and when, how to
  contact us (a staffed channel).
- Do not: speculate, blame a vendor by name without agreement, describe attacker tooling,
  promise that "no data was accessed" unless the evidence supports it, or use "sophisticated"
  as an explanation.
- Provide the same facts to all recipients of the same class at the same time; staggered or
  inconsistent notices generate complaints and regulatory attention.
- Pre-write the FAQ for support teams before the notice goes out.

## Regulator notifications

- Use the regulator's form or portal where one exists; keep a copy of exactly what was
  submitted and when.
- Interim notifications are normal under most regimes: submit what is known by the deadline
  and state when the next report will follow. Missing a clock to gather more facts is the
  wrong trade.
- Facts, dates (UTC and local), counts by jurisdiction, categories of data, measures taken,
  measures proposed, contact point. Nothing more.

## Blameless lessons-learned session

- Held within two weeks, facilitated by someone who was not a decision-maker in the
  incident. Attendees: responders, system owners, the IC, someone from the function that
  will fund fixes.
- Walk the timeline and stop at decisions, not at errors. For each: what was known, what
  was reasonable, what would have made a better decision available.
- Capture "where we got lucky" explicitly; those are the highest-value findings.
- Output is the action-item table with owners and dates, reviewed on a fixed date.
- The retro document is internal and blameless by design; if legal privilege is being
  asserted over the incident, agree with counsel how the retro is labelled and stored.

## Timeline conventions (all documents)

- UTC, ISO 8601, `Z` suffix: `2026-09-14T09:06:55Z`. Local time only in parentheses when a
  reader needs it (regulator forms, customer notices).
- One event per row; source per row; actor per row (attacker, account, analyst, system).
- Attacker actions and defender actions in the same table, tagged, so dwell and response
  intervals can be read directly.
- Precision matches the source: do not invent seconds for an event known to the minute.
- Never silently drop an event you cannot time; list it under "untimed" with the reason.
- When a time is inferred (from a file mtime, a user's recollection), say so in the
  evidence column.
