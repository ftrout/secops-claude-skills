# threat-intel-analysis

Turn a vendor report, ISAC bulletin, STIX bundle, or leak-site post into a graded, marked
intel product that says what changed for *your* organisation and who owns the follow-up.

Part of [secops-claude-skills](../../README.md).

## Overview

The hard part of intel work is not reading the report. It is deciding, in writing, whether
it matters here, how much of it you believe, and what anyone should do differently by
Friday. Four failure modes dominate, and the skill is shaped around them.

**Forwarding instead of assessing.** A link with "FYI" transfers the work to the reader.
Every product this skill produces carries a relevance judgement, a source grade, and an
action — even when the action is "none, noted for the digest".

**Confirmation by echo.** Twelve news articles quoting one vendor report are one source, and
that apparent corroboration is the usual reason a C3 claim gets written up as fact. The
Admiralty code grades the source's track record and the individual claim separately, so the
same vendor can be A/B on hashes it observed and C on who it thinks is behind them.

**Fabricated estate checks and alert fatigue.** "Not observed in our environment" is a
strong claim about a search someone actually ran; if nobody ran it, the honest output is
"not checked" plus an owner. And if a flash alert goes out for every vendor blog, the one
that matters gets ignored — so flash criteria live in a config file, and everything else
goes in the weekly digest. STIX bundles have their own version of this: exports routinely
carry unmarked objects, indicators with no `valid_until`, and attack patterns with no
ATT&CK reference, and the summariser reports each gap rather than letting you guess.

## What it does

1. Captures the source and its provenance, summarising STIX bundles before you read them.
2. Grades source reliability and claim credibility separately with the Admiralty code.
3. Splits the content into TTPs, indicators, and CVEs, and routes each to the sibling skill
   that owns it.
4. Scores relevance against your threat profile and PIRs, checking the estate or saying
   plainly that nobody did.
5. Builds or updates the Diamond Model for the actor, treating empty cells as findings.
6. Writes the product from a template, applies TLP, and ends with owned, dated asks.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, the quick-assessment output shape, and the pitfalls |
| `scripts/stix_summary.py` | Summarises a STIX 2.1 bundle: object counts, actors, ATT&CK IDs, indicators, relationships, TLP coverage |
| `assets/flash-alert.md` | Same-day product: what is happening, exposure, TTPs, indicators, dated actions |
| `assets/actor-profile.md` | Living document: Diamond, tradecraft table, infrastructure patterns, change log |
| `assets/weekly-digest.md` | Cadence product: three-bullet bottom line, relevant items with owners, PIR status |
| `references/admiralty-code.md` | Source reliability A–F and claim credibility 1–6, with SOC-specific examples |
| `references/diamond-model.md` | The four vertices, infrastructure Type 1 vs Type 2, and the pivot table |
| `references/pir-template.md` | PIR/SIR structure, a worked six-PIR set, and relevance scoring |
| `references/environment.md` | Your customization file: threat profile, PIRs, TLP defaults, flash criteria |
| `examples/` | A synthetic STIX bundle and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *is this report actually relevant to us or is it just noise*

> *what's in this STIX bundle before I import it*

> *write this up as a flash for the SOC, we run that appliance*

> *draft this week's intel digest from these six links*

### As a standalone tool

The summariser is plain Python with no dependencies. It parses only — it never resolves a
URL and never executes anything in the bundle.

```bash
# Markdown overview, indicator values defanged by default
python scripts/stix_summary.py examples/sample_bundle.json

# Machine-readable, live values, for a TIP import script
python scripts/stix_summary.py examples/sample_bundle.json --format json --refang

# Just the indicator section, capped list length
python scripts/stix_summary.py examples/sample_bundle.json --indicators-only --max-list 100
```

Real output from the bundled sample, trimmed:

```
# STIX bundle summary
**Bundle:** `bundle--0f3d2c9a-7b1e-4c55-9a1d-2e6f8b4c1d10`
**Objects:** 39
**TLP:** TLP:AMBER
**Indicators:** defanged

## Markings
- TLP:AMBER: 10 objects
- unmarked objects: 28

## Attack patterns (ATT&CK)
| ATT&CK ID | Name | Tactic(s) |
|---|---|---|
| T1003.001 | OS Credential Dumping: LSASS Memory | credential-access |
| T1566.001 | Phishing: Spearphishing Attachment | initial-access |
| - | Vendor-specific behaviour with no ATT&CK reference | actions-on-objectives |

### ipv4 (2)
- `203[.]0[.]113[.]56` (malicious-activity; until 2026-09-30; conf 70) GlacierRAT C2 IP

1 indicator(s) had non-STIX or unparseable patterns; inspect them by hand.
```

Note the three data-quality lines: 28 of 39 objects carry no marking, one attack pattern has
no ATT&CK ID, and one indicator pattern would not parse. Those belong in the assessment, not
in a footnote you never write.

The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input.

### The product templates

`assets/` holds the three deliverables as Markdown skeletons. A flash alert is filled from
the source grade, the exposure check, a TTP table, a defanged indicator table with roles and
expiry, and a numbered action table with owners and due dates. An actor profile adds the
Diamond table, the infrastructure-pattern section that drives hunting, and a change log. The
digest is deliberately austere: three bullets, a relevance table, PIR status, and a "Noted,
no action" list of one-liners. Keep the marking, grading, relevance and actions sections if
you restyle them — siblings and readers depend on those.

## Install

This skill ships with the plugin. Inside Claude Code:

```
/plugin marketplace add ftrout/secops-claude-skills
/plugin install secops-skills@secops-claude-skills
```

To install just this skill, copy the folder:

```bash
git clone https://github.com/ftrout/secops-claude-skills
cd secops-claude-skills
./scripts/install.sh threat-intel-analysis          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 threat-intel-analysis         # Windows
./scripts/install.sh --project threat-intel-analysis   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with `references/environment.md`, specifically the threat profile block: sector,
regions, crown jewels, and the key technologies you run. Every relevance judgement in every
product keys off those lines, so with the placeholders left in, the skill can only guess
whether a report matters to you. Next in the same file: the top three PIRs (so relevance can
be scored without opening the full PIR document) and the flash alert criteria, which are
what stand between you and alert fatigue. Maintain the full PIR set in the structure from
`references/pir-template.md`; teams with a house style can edit `assets/` directly.

## Related skills

- TTPs go to [mitre-attack-mapping](../mitre-attack-mapping/) for technique IDs and a
  Navigator layer
- Indicator text goes through [ioc-extraction](../ioc-extraction/) for roles and shelf life
- CVEs and affected products go to [vulnerability-triage](../vulnerability-triage/)
- Detection asks go to [detection-engineering](../detection-engineering/)
- Hunt hypotheses go to [threat-hunting](../threat-hunting/)
- Validation scenarios go to [purple-team-exercise](../purple-team-exercise/)
