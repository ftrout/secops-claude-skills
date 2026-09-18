# Priority Intelligence Requirements (PIRs): template and guidance

PIRs are the questions leadership and defenders need answered so they can make decisions.
They exist so the intel function can say "this is relevant, this is not" without arguing
every time. Without PIRs, every vendor report looks important, digests become link dumps,
and nobody can tell whether the intel programme is working. Keep to five to eight; more
than that and they stop prioritising anything.

## Structure

Each PIR is a question, owned by a decision-maker, broken into specific sub-questions
(Specific Intelligence Requirements, SIRs) that a source can actually answer, and tied to
the collection that answers them.

```markdown
### PIR-<N>: <the question, as a question>
**Decision it supports:** <what someone will do differently with the answer>
**Owner (consumer):** <CISO | SOC lead | vuln mgmt | fraud team | product security>
**Priority:** <1 highest .. 3>   **Review date:** <quarterly>

**Specific requirements (SIRs)**
- SIR-<N>.1: <narrow, answerable question>
- SIR-<N>.2: <...>

**Collection plan**
| SIR | Source | Cadence | Gap? |
|---|---|---|---|
| N.1 | <vendor feed / ISAC / OSINT / internal telemetry> | <daily/weekly/on event> | <yes: what is missing> |

**Success looks like:** <what a good answer contains; how the consumer will judge it>
```

## Worked example set (edit to fit)

### PIR-1: Which threat actors are actively targeting our sector and region, and how do they get in?
**Decision it supports:** Where to spend detection engineering and purple-team effort this quarter.
**Owner:** SOC lead.  **Priority:** 1.
- SIR-1.1: Which actors have hit <sector> organisations in <region> in the last 12 months?
- SIR-1.2: What initial access techniques did they use (ATT&CK IDs)?
- SIR-1.3: Which of those techniques do our current controls not cover?
Collection: ISAC bulletins (weekly), vendor actor reports (on publication), our incident
history (quarterly review), `mitre-attack-mapping` diff against the coverage layer.

### PIR-2: Which vulnerabilities in products we run are being exploited in the wild?
**Decision it supports:** Emergency patch vs. normal cycle (feeds `vulnerability-triage`).
**Owner:** Vulnerability management.  **Priority:** 1.
- SIR-2.1: New CISA KEV entries matching our asset inventory.
- SIR-2.2: Vendor advisories or credible reports of exploitation before KEV listing.
- SIR-2.3: Exploit maturity (PoC public, weaponised, in ransomware toolkits).
Collection: KEV (daily), vendor PSIRT feeds, EPSS changes, ISAC.

### PIR-3: Are our credentials, data, or brand being sold, leaked, or abused?
**Decision it supports:** Forced resets, takedowns, customer notification.
**Owner:** IR lead / fraud.  **Priority:** 2.
- SIR-3.1: Corporate credentials in infostealer logs or combolists.
- SIR-3.2: Lookalike domains and phishing kits imitating our brand.
- SIR-3.3: Claims of our data on extortion sites.
Collection: Digital risk protection service, certificate transparency monitoring, leak-site monitoring.

### PIR-4: What ransomware and extortion groups are most likely to hit us, and what are their current TTPs?
**Decision it supports:** Tabletop scenario selection, backup/recovery validation priorities.
**Owner:** CISO.  **Priority:** 2.

### PIR-5: Which third parties and suppliers we depend on have been compromised?
**Decision it supports:** Access reviews, contract escalation.
**Owner:** Third-party risk.  **Priority:** 2.

### PIR-6: What is the threat to our cloud and identity platforms specifically?
**Decision it supports:** Conditional access policy changes, token lifetime tuning.
**Owner:** Identity team.  **Priority:** 2.

## Writing good PIRs

- Phrase as a question a source could answer, not a topic ("ransomware" is a topic;
  "which ransomware affiliates use the initial access brokers active in our sector" is a
  question).
- Name the decision. If no one would act differently on the answer, it is curiosity, not
  a requirement.
- Give each an owner who will say whether it was answered.
- Review quarterly; retire PIRs whose decisions are made; add PIRs when the business
  changes (new region, acquisition, new platform).

## Relevance scoring against PIRs

When assessing a report, score it: **High** = directly answers an SIR of a priority-1 PIR,
or names a product/sector/region that matches us, or is observed in our estate.
**Medium** = touches a PIR indirectly or a priority-2/3 PIR. **Low** = general awareness.
Record the PIR number in every product so the digest's "PIR status" section can be
assembled from the week's work rather than from memory.
