# Post-Incident Report: <INC-YYYY-NNNN> <short title>

| | |
|---|---|
| **Classification** | <TLP:AMBER / Internal / Privileged & Confidential - prepared at direction of counsel> |
| **Status** | <Draft / Final> v<n>, <YYYY-MM-DD> |
| **Author / reviewers** | <IR lead>; reviewed by <security leadership, legal, affected system owners> |
| **Incident window (UTC)** | <first malicious activity> to <containment confirmed> |
| **Severity** | <P1..P4> (final); initial <tier> at <time> |
| **Incident commander** | <name> |

## 1. Executive summary

<Three to six sentences, plain language, no jargon. What happened, what the attacker got
(or did not get), what it cost, what we did, what we are changing. Write this last, read it
first. A reader who stops here must not be misled by anything below.>

## 2. Impact

- **Systems affected:** <count and names or classes>
- **Accounts affected:** <count, privilege level>
- **Data affected:** <type, classification, record count, confidence in the count; "none
  observed" is not "none": state what evidence supports the claim>
- **Business impact:** <downtime, revenue, customer-facing effects, regulatory exposure>
- **Not affected (with evidence):** <systems the reader will ask about>

## 3. Timeline (UTC, ISO 8601)

<Paste the table from `scripts/timeline_format.py`. Every entry has a source. Mark
attacker actions (A), defender actions (D), and detection/notification events (N).
Call out gaps and how you know they are gaps in logs rather than gaps in activity.>

| # | Time (UTC) | T+ | Source | Actor | Action | Evidence | Flags |
|---|---|---|---|---|---|---|---|

Key intervals:

| Interval | Duration | Comment |
|---|---|---|
| Initial access to detection (dwell) | <h> | |
| Detection to triage verdict | <h> | |
| Verdict to containment | <h> | |
| Containment to eradication confirmed | <h> | |
| Eradication to recovery complete | <h> | |

## 4. Root cause and attack narrative

<How the attacker got in, what they did, in order, with the evidence for each step. Map
each step to MITRE ATT&CK (version noted, see `mitre-attack-mapping`). Separate what is
**confirmed**, what is **probable**, and what is **unknown**. The root cause is the
condition that allowed it, not the attacker.>

- **Initial access:** <...> (ATT&CK T....)
- **Execution / persistence:** <...>
- **Privilege escalation / credential access:** <...>
- **Lateral movement / discovery:** <...>
- **Collection / exfiltration / impact:** <...>
- **Root cause(s):** <control gap, misconfiguration, process failure>
- **Contributing factors:** <...>

## 5. Detection and response assessment

- **How it was detected:** <rule / user report / third party>, at <time>, <n> h after first activity
- **What should have detected it earlier and why it did not:** <...>
- **What went well:** <...>
- **What went poorly:** <...>
- **Where we got lucky:** <...>

## 6. Containment, eradication, and recovery

| Action | Time (UTC) | Approved by | Result / rollback |
|---|---|---|---|

Confirmation of eradication: <what was checked, across what scope, over what period, and
what "clean" was defined as>.

## 7. Indicators and detection content

<Summary table of indicators (defanged) with role and confidence, from `ioc-extraction`;
list of detections created or tuned, from `detection-engineering`; hunts run.>

## 8. Notifications and external parties

| Party | Obligation / reason | Notified (UTC) | By | Reference |
|---|---|---|---|---|
| <Regulator> | <regime, clock start, deadline> | | | |
| <Customers / partners> | <contract> | | | |
| <Cyber insurer> | <policy> | | | |
| <Law enforcement> | <voluntary / required> | | | |

## 9. Action items

| # | Action | Type (prevent / detect / respond / process) | Owner | Due | Status |
|---|---|---|---|---|---|

## 10. Open questions and limitations

<What could not be determined, why (log retention, unavailable evidence), and what would
be needed to close each item.>

## Appendix

- A. Evidence inventory (file, hash, location, chain of custody)
- B. Queries used (from `siem-query-authoring`)
- C. Related tickets and prior incidents
- D. Glossary for non-technical readers
