# mitre-attack-mapping

Turn an incident timeline, threat report, or detection rule set into a defensible ATT&CK
mapping — each technique tied to evidence, under the tactic it actually served — plus a
Navigator layer JSON and a coverage diff that names your gaps.

Part of [secops-claude-skills](../../README.md).

## Overview

Mapping to ATT&CK looks like a lookup exercise and behaves like an evidence exercise. There
are two ways to get it wrong, and they pull in opposite directions.

**Over-mapping** is the common one. "The actor used Cobalt Strike" becomes every technique
on the software's ATT&CK page; "they got in by phishing" becomes T1566.001 plus T1204.002
plus T1059.001 plus T1027 because that is what usually happens next. Every inferred row is a
claim a detection engineer or purple team may spend a week on, and a heat map built from
inferences is decoration. **Under-mapping** is the quieter failure: stopping at "they
achieved persistence" gives nobody anything to build a rule from.

Between those sit the errors that survive review because they look right. Discovery commands
(`whoami`, `net user`, `ipconfig`) mapped from background admin noise with no tie to the
adversary's session. T1078 filed under Persistence when it was the entry vector — the same
trap waits at T1053, T1055, T1548, T1133 and T1098. Sub-technique precision the evidence
cannot support: "creds were dumped" is T1003, not T1003.001, and the difference matters
because LSASS, NTDS and DCSync have unrelated detections. Stale IDs carried forward from old
reports (T1086, T1064 and T1175 were retired years ago).

Vendor reports that map themselves deserve particular suspicion: their ATT&CK table is a
hypothesis to verify against the described behaviour, not a result to copy. The last failure
is mechanical — Navigator rejects malformed layers silently, usually over a tactic shortname
(`defense-evasion`, not "Defense Evasion") or a version mismatch — which is why the script
exists and nobody should hand-write that JSON.

## What it does

1. Establishes what is being mapped — incident, intel, or coverage — since each needs
   different rigour, and pins the ATT&CK version.
2. Extracts discrete behaviours first ("who did what to what, evidenced how"), before any
   technique ID is written down.
3. Assigns tactic, then technique, then sub-technique only as far as the evidence reaches.
4. Adds a confidence and a rationale that points at telemetry, keeping unobserved guesses in
   a separate "likely but not observed" list.
5. Reviews the draft against the ten classic pitfalls and a kill-chain sanity check.
6. Generates the Navigator layer, or diffs a threat profile against detection coverage.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, the mapping-table output shape, and the pitfalls |
| `scripts/navigator_layer.py` | Builds a Navigator layer (format 4.5) from CSV or JSON; diff mode colours gaps, coverage, and extras |
| `references/tactics.md` | The 14 Enterprise tactics with Navigator shortnames, plus the multi-tactic technique table |
| `references/common-techniques.md` | ~140 frequently seen techniques with the telemetry that evidences each and the benign look-alike that causes false mappings |
| `references/mapping-pitfalls.md` | The ten errors that make a mapping misleading rather than merely incomplete |
| `references/environment.md` | Your customization file: pinned ATT&CK version, score scales, sanctioned tools, layer paths |
| `examples/` | An incident CSV, a report JSON, threat-profile and detection lists for `--diff`, and the CI smoke manifest |

ATT&CK version: Enterprise **v17** (April 2025) throughout, and it is a configurable default
rather than a hard-coded string.

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *map this incident timeline to ATT&CK, only what we actually saw*

> *which techniques in our threat profile have no detection behind them*

> *this vendor report has its own ATT&CK table, is it any good*

> *build me a Navigator layer from these rules so I can show coverage*

### As a standalone tool

The script is plain Python with no dependencies.

```bash
# Incident mapping -> layer JSON, with per-tactic counts on stderr
python scripts/navigator_layer.py examples/mapping.csv --name "INC-2026-0142" \
  --attack-version 17 --stats > layer.json

# Report mapping from JSON, filtered to one platform, single-line output
python scripts/navigator_layer.py examples/mapping.json --platforms Windows --compact

# Coverage gaps: A = what the threat profile needs, B = what detections cover
python scripts/navigator_layer.py --diff examples/threat_profile.csv \
  examples/detections.csv --name "Q3 gaps" > gaps.json
```

`--stats` on the incident sample:

```
techniques: 11 entries, 11 distinct parent techniques, 8 sub-techniques
  command-and-control      2
  discovery                2
  execution                2
  credential-access        1
  defense-evasion          1
  initial-access           1
  lateral-movement         1
  persistence              1
```

The diff prints `gap=7 covered=12 extra=2` to stderr and explains itself inside the layer,
with per-technique comments that survive into Navigator's tooltips:

```json
"description": "7 gaps (in threat_profile.csv only), 12 covered, 2 extra (in detections.csv only). Sub-techniques count as covered when the parent technique is covered.",
"comment": "GAP: in threat_profile.csv, not in detections.csv | Kerberoasting",
"comment": "covered: in threat_profile.csv and detections.csv | LSASS dumping",
```

The legend is `Gap` (`#e04a4a`), `Covered` (`#4caf50`), `Extra` (`#4a90e2`). The
parent-covers-child rule matters here: `detections.csv` lists T1566 at the parent level, so
T1566.001 and T1566.002 both come back green rather than showing as phantom gaps.

Beyond those, the script takes `--domain`, `--gradient`, `--score-min`/`--score-max`,
`--layer-version`, `--navigator-version`, `--expand-subtechniques` and `--hide-disabled`. It
takes `--help`, reads `-` for stdin, writes the layer to stdout, and exits 2 on bad input.

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
./scripts/install.sh mitre-attack-mapping          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 mitre-attack-mapping         # Windows
./scripts/install.sh --project mitre-attack-mapping   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Everything tunable lives in `references/environment.md`. The highest-value edit is the
**sanctioned tools** block: the remote-access product your helpdesk uses, your endpoint
management platform, your scanner hostnames, your backup and sync jobs, your identity sync
account. Those are what get mapped as adversary behaviour by mistake most often, and each
one poisons a different technique (T1219, T1059, T1046, T1567.002, T1003.006). Then pin your
ATT&CK version (it sets `--attack-version` and the citation in every output), set the score
scales the gradient uses, and record the paths of your threat-profile and detection-coverage
layers so `--diff` runs the same way every quarter.

## Related skills

- Mappings for an incident feed [incident-report-writing](../incident-report-writing/)
- Techniques with no coverage go to [detection-engineering](../detection-engineering/)
- Techniques worth validating go to [purple-team-exercise](../purple-team-exercise/)
- Hypotheses for the rest of the estate go to [threat-hunting](../threat-hunting/)
- An actor mapping goes into the profile in [threat-intel-analysis](../threat-intel-analysis/)
- Indicators set aside during extraction go to [ioc-extraction](../ioc-extraction/), CVEs to
  [vulnerability-triage](../vulnerability-triage/)
