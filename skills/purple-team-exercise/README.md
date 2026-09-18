# purple-team-exercise

Turn a threat profile or a past incident into a planned, signed-off detection-validation exercise,
and turn the observations afterwards into a scorecard: coverage, time-to-detect, and a ranked
detection backlog with owners.

Part of [secops-claude-skills](../../README.md).

> **This skill contains no attack commands, and it never runs the tests.** It plans, coordinates,
> and scores. Emulation tests are referenced by published name or ID only — `T1003.001 Atomic Test
> #1`, `aws.defense-evasion.cloudtrail-stop`, `CTID APT29 plan Step 10` — so the authorized operator
> pulls the actual test from the source project at run time, under your ROE. Nothing offensive lives
> in this repository or ends up pasted into your tickets, and "just run the atomic" gets a decline.

## Overview

A purple team is a measurement exercise, not a red team engagement. The question is not "can we get
domain admin", it is "per adversary behavior, would the SOC see it, and how fast". That reframing is
also where most exercises go wrong.

**Telemetry and detection are different failures with different owners.** "No alert" on a technique
whose log source was never onboarded is a visibility gap; writing a rule will not help, and routing
it to the detection team wastes a sprint. The scoring model separates *none* (nothing collected it)
from *logged* (collected, nobody wrote a rule) from *alert* so each goes to the right team. That
only works if you write down the expected data source **before** the run.

**Green scorecards lie.** A test that errored, was blocked by a control, or never really executed
gets quietly marked "no alert needed" and inflates coverage. So does time-to-detect reconstructed
after the fact; it means something only when both timestamps come from systems of record.

**Safety and deconfliction are not paperwork.** Impact and defense-evasion techniques can cause real
harm, so they run on throwaway hosts or not at all. And if the SOC cannot tell the exercise from a
real intrusion, you either burn a genuine IR response or, worse, teach analysts to shrug off real
alerts as "probably the purple team". And a gap you found once and never retested is not closed,
which is why the scorecard compares against the previous run.

## What it does

1. Sets the objective and derives two or three realistic scenarios — chains, not a pile of atomics.
2. Maps each technique to a specific published emulation test, by identifier only.
3. Writes the rules of engagement and safety plan, and gets them signed, before anything runs.
4. Plans the run-of-show with an expected data source per technique, noisy steps last, gaps between
   steps so time-to-detect is measurable.
5. Keeps the books during the run — the operator executes; this skill records the timestamps.
6. Scores each test as alert / logged / none, computes coverage and TTD, and produces the backlog.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The eight-step workflow, the readout template, and the pitfalls |
| `scripts/scorecard.py` | Turns the observation CSV into coverage, per-tactic and per-technique rollups, TTD stats, gap list, and backlog |
| `assets/exercise-plan.md` | Fill-in plan template: objective, scenarios, technique table with expected sources, roles, data collection, sign-off |
| `assets/rules-of-engagement.md` | Fill-in ROE template: authorization, scope, safety, deconfliction, abort, evidence, comms, cleanup, sign-off |
| `references/emulation-catalog.md` | How Atomic Red Team, CALDERA, Stratus Red Team, and the ATT&CK Evals / CTID plans are organized, and how to cite a test from each |
| `references/environment.md` | Your customization file: tooling and where it may run, standing scope, deconfliction signal, SLAs, sign-off authorities |
| `examples/` | A synthetic 24-test scorecard CSV and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Say what you are trying to find out:

> *we want to know if we'd catch a ransomware precursor chain on our windows fleet, help me plan it*

> *ran a batch of atomics last week, here are my notes — turn them into something I can show the CISO*

> *did we actually improve since last quarter or did we just test different things*

### The templates

`assets/exercise-plan.md` (objective, scenarios, technique table, roles, sign-off) and
`assets/rules-of-engagement.md` (authorization, scope, safety, deconfliction, abort, cleanup) are
filled in before anything executes. The plan's technique table matters most, since it is also the
skeleton of the scorecard CSV afterwards — the same rows plus `observed` and `ttd_minutes`:

| Scenario | Technique | Tactic | Emulation test (ID only) | Platform | Expected source |
|---|---|---|---|---|---|
| Ransomware precursor | T1003.001 LSASS Memory | Credential Access | ART T1003.001 Test #1 (ProcDump) | Windows | Sysmon 10 + EDR |
| Cloud identity | T1562.008 Disable Cloud Logs | Defense Evasion | Stratus aws.defense-evasion.cloudtrail-stop | AWS | CloudTrail StopLogging |

The "Emulation test" column holds an identifier that resolves to exactly one test in the source
project, never a command.

### As a standalone tool

Plain Python, standard library only, read-only.

```bash
# Score a run against a 30-minute time-to-detect SLA
python scripts/scorecard.py results.csv --name "Q3 ransomware precursor exercise" --ttd-sla 30

# Machine-readable for a dashboard; or compare against the last run
python scripts/scorecard.py results.csv --format json
python scripts/scorecard.py results.csv --previous last_quarter.csv
```

Real output from the bundled 24-test sample, trimmed:

```
# Purple team scorecard: Q3 ransomware precursor exercise

- Tests executed: **24** across **22** techniques and 11 tactics
- Test outcomes: alert 11, logged only 8, not visible 5
- **Detection coverage (alert): 45.8% of tests, 50.0% of techniques (best test per technique)**
- Visibility (alert or logged): 79.2% of tests, 77.3% of techniques; blind: 20.8% of tests
- Time to detect (alerts with a TTD, n=11): median 6 min, mean 10.5 min, max 45 min; 1 over the 30 min SLA

## Gap list (13), prioritized

| # | Technique | Test | Tactic | Expected source | Observed | Pri | Notes |
|---|---|---|---|---|---|---|---|
| 1 | T1003.006 DCSync | DCSync (Active Directory) (ART #1) | Credential Access | Security 4662 (DC) | none | 1 | No SACL for replication rights on domain object |
| 6 | T1098.001 Additional Cloud Credentials | aws.persistence.iam-backdoor-user (stratus) | Persistence | CloudTrail CreateAccessKey | logged | 1 | CloudTrail present; no rule |

## Detection backlog (hand to detection-engineering)

- [ ] **T1003.006** DCSync / DCSync (Active Directory) (source: Security 4662 (DC), currently none): confirm the data source is onboarded and the event is generated, then write a rule
- [ ] **T1098.001** Additional Cloud Credentials / aws.persistence.iam-backdoor-user (source: CloudTrail CreateAccessKey, currently logged): telemetry exists: write or tune a detection rule and add a unit test
...
```

Most rows, the `Technique best` column, the per-tactic and per-technique tables, and the data-source
health table are cut here for width. The ordering is the point: telemetry-blind items first, weighted
by your `priority` column, then the logged-but-unruled ones, and each backlog line says which kind of
fix it needs. `--previous` adds a "Changes since previous run" section — on this data,
`Improved: T1566.001 (logged -> alert)`, `Regressed: none`, plus what is new and what was not
retested.

Tactics come from your CSV rather than a built-in lookup, so the script does not go stale as ATT&CK
versions change. It takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input.

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
./scripts/install.sh purple-team-exercise          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 purple-team-exercise         # Windows
./scripts/install.sh --project purple-team-exercise   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Fill in the standing scope and hard do-not-touch list in `references/environment.md` before your
first exercise. Every other decision — which tests survive the prune, which need a throwaway host,
what the ROE has to enumerate — falls out of that list, and it is the one thing you do not want to be
negotiating at 2pm on run day with an operator waiting.

Right behind it: the deconfliction signal and channel, which keeps a tested detection honest while
still letting the control group answer "is this real?" in seconds. Then your coverage targets and TTD
SLA (which becomes `--ttd-sla`), the platforms you actually run, and the sign-off and abort
authorities. Adapt the `assets/` ROE to your own legal and change-management requirements.

## Related skills

- The threat profile and priority actors driving scenario selection come from
  [threat-intel-analysis](../threat-intel-analysis/), and what you learn goes back to it
- Technique mappings and Navigator coverage layers come from
  [mitre-attack-mapping](../mitre-attack-mapping/)
- The detection backlog goes to [detection-engineering](../detection-engineering/), each item with a
  true-positive test from this exercise to validate against
- The readout and before/after comparison go to
  [incident-report-writing](../incident-report-writing/)
- Cloud control-plane tests pair with
  [cloud-incident-investigation](../cloud-incident-investigation/), which covers what those same
  events look like in a real investigation
