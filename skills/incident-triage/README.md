# incident-triage

Turn a pasted alert into a verdict, a defensible severity tier, and a triage note that the
next analyst can pick up without re-running your investigation.

Part of [secops-claude-skills](../../README.md).

## Overview

Triage looks like a decision problem and is really a discipline problem. The verdict is
usually reachable in ten minutes; what goes wrong is everything around it.

**Verdicts get written before the evidence.** "Probably benign" typed in the first minute
anchors everyone who reads the ticket afterwards. The fix is structural: write the
evidence-for and evidence-against sections first and let the verdict fall out of them.

**Benign stories get believed instead of verified.** "Looks like admin activity" is not a
finding. A benign explanation counts only when confirmed out-of-band, and a reply to the
suspicious email or a chat with the possibly-compromised account is not out-of-band. This is
the failure mode that leaves intrusions sitting for months. The sibling failure is skipping
scope because it is "just one host": every intrusion is one host first, and the 30-day
prevalence query changes the tier more than any other step.

**Severity becomes a feeling.** Vendor severity is a property of the rule, not of your
environment: a "high" from a noisy rule on a lab box is a P4, an informational sign-in on a
global admin can be a P2. Scoring against a weights file the team owns makes the tier
reproducible and arguable on its merits rather than negotiated in chat.

## What it does

1. Classifies the alert into one of eight classes and opens the matching playbook; the
   questions and benign explanations differ completely per class.
2. Pulls that playbook's data in the order given, cheapest and highest-signal first, writing
   "not checked: <source>" wherever a source is unavailable.
3. Works the benign-explanation checklist, recording *how* each item was ruled in or out.
4. Scopes before scoring, since scope drives the spread factor and often changes the tier.
5. Scores severity with `scripts/triage_score.py`, which names the dominant factor and the
   single change that would move the tier.
6. Writes a fixed-shape triage note and hands off to the sibling skill that owns what's next.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, the triage-note template, and the pitfalls |
| `scripts/triage_score.py` | Five-factor severity scoring with floors, ceilings, and a sensitivity line |
| `references/severity-matrix.md` | Factor definitions, the reasoning behind the model, floor/ceiling rules, worked examples |
| `references/severity-weights.json` | Your customization file: weights, tier names and thresholds, floors, ceilings, label aliases |
| `references/playbooks/edr-process.md` | Process trees, LOLBins, LSASS access, persistence writes, ransomware flags |
| `references/playbooks/identity-signin.md` | Impossible travel, MFA fatigue, password spray, new MFA method, privilege escalation |
| `references/playbooks/email.md` | Gateway verdicts, post-delivery detections, DMARC failures, URL-clicked alerts |
| `references/playbooks/network-ids.md` | IDS signatures, DNS sinkhole hits, beaconing, scans, JA3 matches |
| `references/playbooks/cloud-control-plane.md` | GuardDuty, Defender for Cloud, SCC, IAM and logging changes in CloudTrail |
| `references/playbooks/dlp.md` | Endpoint and email DLP, CASB shares, mass download, insider-risk handling |
| `references/playbooks/vulnerability-scanner.md` | Scanner criticals, KEV hits, ASM findings, exploitation attempts |
| `references/playbooks/user-reported.md` | "I think I clicked something", lost devices, vishing, third-party reports |
| `references/environment.md` | Your customization file: tooling, escalation paths, containment approvals, known-benign context |
| `examples/` | Two scored alerts (one true positive, one benign) and the CI smoke manifest |

Every playbook has the same seven sections: questions to answer, data to pull, benign
explanation checklist, true-positive indicators, scoping questions, escalation criteria,
hand-offs.

## Using it

### In Claude Code

You do not invoke it by name. Describe the alert:

> *is this bad? EDR fired on lsass access from an unsigned binary on FS01*

> *impossible travel on a finance user, MFA passed. do I escalate or close it*

> *user says they clicked a link and typed their password. what do I check first*

### As a standalone tool

`triage_score.py` is standard library only, so it runs outside Claude too.

```bash
# Score from flags
python scripts/triage_score.py --confidence 4 --impact 4 --asset-criticality 4 --spread 1 --data-sensitivity 4

# Score an alert blob; factors may be integers or labels like "high"
python scripts/triage_score.py --json examples/alert-edr-lsass.json --format md

# Machine-readable for a ticket automation; --config takes the team's own weights
python scripts/triage_score.py --json examples/alert-signin-benign.json --format json

python scripts/triage_score.py --show-config   # the effective config and factor labels
```

Real output from the bundled LSASS example:

```
**Alert:** EDR-2026-091734 Suspicious LSASS memory access from unsigned binary on FS01
**Severity: P2** (High: work immediately, escalate to tier 2 / IR)
**Score:** 53.9 / 100 = exposure 67.4 x confidence 0.8 (base tier P2)

| Factor | Value | Weight | Meaning |
|---|---|---|---|
| confidence | 4 | multiplier | likely true positive, one or two corroborating artifacts |
...
- Exposure is pushed up most by `impact` and held down most by `spread`.
- What would change the tier: confidence 4->3 moves it down to P3; impact 4->3 moves it down to P3.
```

That last line is the point of the script: it tells you which unknown to resolve next. Policy
cliffs are shown too. A blocked exploit attempt against a crown jewel during an org-wide scan
(`--confidence 3 --impact 1 --asset-criticality 5 --spread 5 --data-sensitivity 5`) hits a
floor and a ceiling on the way to P3, and prints both:

```
- Rule applied: raised to P2: plausible org-wide spread needs coordination regardless of per-host impact.
- Rule applied: capped at P3: blocked before execution with no confirmation is a tuning task, not an incident.
```

The script takes `--help`, reads `-` for stdin with `--json -`, writes to stdout, and exits 2
on bad input (a factor outside 1..5, an unknown label, unreadable JSON).

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
./scripts/install.sh incident-triage            # POSIX, to ~/.claude/skills
.\scripts\install.ps1 incident-triage           # Windows
./scripts/install.sh --project incident-triage  # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the known-benign context block in `references/environment.md`: scanner ranges,
deployment accounts, corporate egress IPs, and phishing-simulation sender domains. Those four
lists remove the most common false positives before an analyst spends a minute on them. The
same file holds the containment approval table that decides what you may do without a ticket
at 03:00.

Then tune `references/severity-weights.json` if your tiers do not match your ticketing
system. Renaming `P1..P4` to `Sev1..Sev4` makes the script output paste straight into a
ticket; weights, thresholds, floors, ceilings, and label aliases all live in that file, and
`references/severity-matrix.md` explains the reasoning behind each one.

## Related skills

- Indicators go to [ioc-extraction](../ioc-extraction/); files and hashes to
  [malware-triage](../malware-triage/); emails to [phishing-analysis](../phishing-analysis/)
- Accounts go to [identity-threat-investigation](../identity-threat-investigation/), cloud
  events to [cloud-incident-investigation](../cloud-incident-investigation/), host timelines
  to [log-forensics](../log-forensics/)
- Scoping queries come from [siem-query-authoring](../siem-query-authoring/)
- Noisy rules go to [detection-engineering](../detection-engineering/)
- Anything that becomes an incident goes to
  [incident-report-writing](../incident-report-writing/)
