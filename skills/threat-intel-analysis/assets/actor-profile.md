# Actor profile: <primary name>

**TLP:** <marking>   **Last reviewed:** <YYYY-MM-DD>   **Owner:** <analyst>   **Profile ID:** <TEAM-ACTOR-NNN>
**Aliases:** <vendor names, with the vendor in brackets: e.g. "Storm-9999 (Microsoft)">
**Relevance to us:** <High | Medium | Low>: <targets our sector / region / technology; observed in our estate on <date>>
**Overall source confidence:** <based on the grading of the sources in the last section>

## Summary
Four to six sentences an executive can read: who they are (assessed sponsor or motivation),
what they want, whom they target, how they usually get in, and what happens if they succeed.
Mark each claim as *confirmed*, *reported*, or *assessed*.

## Diamond Model
| Vertex | What we know | Confidence | Source |
|---|---|---|---|
| Adversary | <assessed identity, sponsor, motivation, operating hours/timezone> | | |
| Capability | <malware families, tooling, exploits, tradecraft level> | | |
| Infrastructure | <hosting patterns, registrars, TLS/cert habits, C2 frameworks, reuse> | | |
| Victim | <sectors, regions, technologies, victim selection logic> | | |

Meta-features: <first seen>, <last seen>, <phase focus>, <result: espionage / extortion / disruption>,
<direction>, <methodology>, <resources>.

## Targeting
- Sectors: <list>   Regions: <list>   Technologies/products: <list>
- Victim profile that fits us: <which business units / assets / identities are attractive>

## Tradecraft (ATT&CK Enterprise v<NN>)
| Tactic | Technique | How this actor does it | Seen in our estate? |
|---|---|---|---|
| Initial Access | T1566.002 | <detail> | <no / INC-...> |

Keep to techniques the sources evidence. Full mapping and Navigator layer via `mitre-attack-mapping`.

## Tooling
| Name | Type | Role | Notes (public sandbox reports, YARA available?) |
|---|---|---|---|

## Infrastructure patterns
Registrars, hosting ASNs, naming conventions, certificate habits, ports, protocols, and how
quickly infrastructure rotates. This section drives hunting more than any indicator list.

## Timeline of notable activity
| Date | Event | Source (grading) |
|---|---|---|

## Our exposure and observed activity
- Past incidents / near misses: <ticket IDs>
- Controls that address their usual entry: <MFA on VPN, attachment sandboxing, ...>
- Gaps: <list; feed to detection-engineering / vulnerability-triage>

## Detection, hunt, and validation asks
- Detections to build or verify: <technique -> rule name / backlog ID>
- Hunt hypotheses: <hypothesis + data source>
- Purple-team scenarios: <technique list -> purple-team-exercise>

## PIRs this profile serves
<PIR-N: title> ...

## Sources
| # | Title / publisher | Date | Grading | Notes |
|---|---|---|---|---|

## Change log
| Date | Change | By |
|---|---|---|
