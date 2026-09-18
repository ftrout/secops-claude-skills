# Admiralty (NATO) source and information grading

Origin: the NATO System (also called the Admiralty Code), standardised in NATO AJP-2.1 and
adopted in US Army FM 2-22.3 (2006) Appendix B. Every piece of intelligence carries a
two-character grade: a **letter for the source's reliability** (a judgement about the
source's track record) and a **number for the information's credibility** (a judgement
about this specific claim). The two are graded independently: a normally reliable vendor
can publish an unconfirmed claim (B3), and an untested source can report something that
three others corroborate (F1 is possible but usually written C1 or better once corroborated).

## Source reliability (letter)

| Grade | Label | Meaning | Typical examples for a SOC |
|---|---|---|---|
| A | Completely reliable | No doubt of authenticity, trustworthiness, competence; history of complete reliability | Your own telemetry and forensics; your IR team's findings; a vendor's advisory about their own product |
| B | Usually reliable | Minor doubt; history of valid information most of the time | Major security vendors' research teams; CISA/NCSC/national CERTs; the ISAC for your sector |
| C | Fairly reliable | Some doubt; has provided valid information in the past | Smaller vendors, well-known independent researchers, established blogs |
| D | Not usually reliable | Significant doubt; has provided valid information occasionally | Anonymous forum posts, new accounts, marketing content with no data |
| E | Unreliable | Lacking authenticity or competence; history of invalid information | Sources caught fabricating, known disinformation outlets |
| F | Cannot be judged | No basis for evaluating reliability | A first-time source, a leaked document of unknown provenance, a tweet from an unknown handle |

Reliability is about the source, not the platform. A respected researcher posting on social
media is still B or C. A vendor with a track record of overclaiming attribution is C for
attribution and B for technical detail; it is fine to grade the same source differently by
topic.

## Information credibility (number)

| Grade | Label | Meaning | How you check it |
|---|---|---|---|
| 1 | Confirmed | Confirmed by other independent sources; logical; consistent with other information | Two or more independent sources with different collection (not two vendors quoting the same third party) |
| 2 | Probably true | Not confirmed but logical and consistent with other information | Fits known TTPs and infrastructure; nothing contradicts it |
| 3 | Possibly true | Not confirmed; reasonably logical; agrees with some other information | Plausible, partial fit |
| 4 | Doubtfully true | Not confirmed; possible but not logical; no other information on the subject | Contradicts some evidence or requires unusual assumptions |
| 5 | Improbable | Not confirmed; illogical; contradicted by other information | Multiple contradictions |
| 6 | Cannot be judged | No basis for evaluating validity | Nothing to compare it to yet |

"Independent" is the word that matters. Ten articles that all cite one vendor report are
one source. Retweets and re-reporting inflate apparent confirmation; trace every claim to
its origin before counting it.

## Using the grade in products

- Write the grade next to every source in the Sources section and next to any claim that
  drives an action: "Actor X is exploiting CVE-Y in the wild (B2, vendor advisory; C3,
  forum post)".
- Actions scale with the grade. A1/B1/B2 can justify blocking and paging. C3 justifies a
  hunt or a watchlist. Anything D/E or 4/5 goes in "noted" unless corroborated.
- Re-grade when new information arrives. A claim that starts F6 (an unknown handle on
  social media) can become B1 in a day when a vendor confirms it; record the change.
- Do not average. "B2 overall" for a report means the *typical* claim in it; individual
  claims in the same report can be A1 (hashes the vendor observed) and C4 (attribution).

## Quick self-check before grading

1. Who actually collected this, and how? (telemetry, sandbox, victim engagement, OSINT, hearsay)
2. Has this source been right before on this kind of claim?
3. Is there a second source with *different* collection?
4. Does anything already known contradict it?
5. Who benefits if this is believed? (marketing, political, extortion pressure)

## Common mistakes

- Grading a source A because it is famous. Fame is not a track record on this topic.
- Grading information 1 because it is repeated widely (see "independent" above).
- Grading your own team's inference as A1. Your telemetry is A; your interpretation of it
  is graded on credibility like anyone else's.
- Leaving F6 forever. F6 is a placeholder that means "go find out".
