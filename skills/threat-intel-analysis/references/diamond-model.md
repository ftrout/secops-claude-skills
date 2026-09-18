# The Diamond Model of intrusion analysis

Origin: Caltagirone, Pendergast and Betz, *The Diamond Model of Intrusion Analysis*
(2013). It describes every intrusion event as an **adversary** deploying a **capability**
over **infrastructure** against a **victim**, and gives analysts a structured way to pivot
from what they know to what they do not. ATT&CK describes *how*; the Diamond describes
*who, with what, through what, against whom*, and the two complement each other in an
actor profile.

## The four vertices

| Vertex | Question | What to record | Where it usually comes from |
|---|---|---|---|
| **Adversary** | Who is behind this and why? | Operator vs. customer (the group doing the work vs. who they do it for), motivation, operating hours/timezone, language artefacts, tradecraft maturity, aliases by vendor | Vendor attribution (grade it), your own timing analysis, law-enforcement indictments |
| **Capability** | What can they do? | Malware families, tooling (commodity vs. custom), exploits and CVEs used, C2 frameworks, tradecraft (how they evade, how they move), ATT&CK techniques | Sandbox reports, `malware-triage`, incident findings, `mitre-attack-mapping` |
| **Infrastructure** | Through what? | Domains, IPs, hosting ASNs, registrars, certificate patterns, email senders, proxies, compromised third-party infrastructure (Type 2), delivery services abused | `ioc-extraction`, passive DNS, WHOIS/RDAP, certificate transparency, your proxy/DNS logs |
| **Victim** | Against whom? | Sectors, regions, company sizes, specific technologies or products, specific roles targeted (finance, HR, admins), victim selection logic | Vendor victimology, ISAC reporting, your own incident history |

Infrastructure sub-types worth noting: **Type 1** is owned or controlled by the adversary
(registered domains, rented VPS). **Type 2** is controlled by an unwitting third party
(compromised websites, abused cloud services, botnet nodes). Blocking Type 2 wholesale
causes collateral damage; blocking Type 1 is usually safe.

## Meta-features

Attach these to each event or to the activity thread as a whole:

- **Timestamp** (start/end), **Phase** (kill-chain stage), **Result** (success/failure/unknown),
  **Direction** (adversary-to-infrastructure, infrastructure-to-victim, victim-to-infrastructure,
  bidirectional), **Methodology** (phishing, exploitation, supply chain), **Resources**
  (what the operation needed: money, access, knowledge, hardware).
- **Socio-political** axis (adversary-victim): why this adversary wants this victim.
- **Technology** axis (capability-infrastructure): how the tooling and infrastructure
  interoperate (e.g. the loader only talks to domains registered through one registrar).

## Using the model to pivot

The model's real value is pivoting: each vertex you know is a search key for the others.

| You know | Pivot to | How |
|---|---|---|
| Infrastructure (a C2 domain) | More infrastructure | Passive DNS for the resolving IP; other domains on the same IP; same registrant email; same nameserver pattern; same TLS certificate serial |
| Infrastructure | Capability | Which samples contacted it (VirusTotal relationships, sandbox reports) |
| Capability (a malware family) | Infrastructure | Extracted C2 configs; sandbox network traffic |
| Capability | Adversary | Who has used this family before, and is it commodity (weak signal) or custom (strong signal) |
| Victim (your sector) | Adversary | Which actors target this sector; ISAC reporting |
| Adversary | Victim | Their known victimology; where you fit |

A pivot produces a *hypothesis*, not a fact. "Same registrar" links thousands of unrelated
domains; "same registrant email plus same nameserver plus same certificate" is strong.
Record which pivots produced each link and grade the link's confidence.

## Activity threads and activity groups

- An **event** is one diamond (one adversary, capability, infrastructure, victim at a moment).
- An **activity thread** is a sequence of events against one victim (an intrusion).
- An **activity group** clusters threads that share features (the same capability and
  infrastructure patterns across victims). Vendors' named groups are activity groups
  built on their visibility; two vendors' groups can overlap partially, which is why
  aliases rarely map one-to-one.

When building an actor profile, say which features define the cluster ("we group on
loader family + registrar + victim sector"), so a reader can judge whether a new event
belongs.

## Filling the diamond in a product

Write the four vertices as a table with a confidence and a source per cell (see
`assets/actor-profile.md`). Empty cells are information: "Adversary: unknown; no
attribution claimed by any B-or-better source" is a valid and useful entry, and it tells
the reader what not to over-interpret.

## Common mistakes

- Attributing on infrastructure alone. Shared hosting and abused services (Type 2)
  connect unrelated actors constantly.
- Attributing on commodity capability. Cobalt Strike, AsyncRAT and rclone identify nothing
  by themselves.
- Treating a vendor's group name as an adversary. It is an activity group; the human
  organisation behind it is a separate, usually lower-confidence claim.
- Forgetting the victim vertex. Victimology is often the strongest relevance signal a
  defender has ("they only hit banks in our region" changes the priority more than any hash).
