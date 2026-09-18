# cloud-incident-investigation

Turn a leaked access key, a GuardDuty finding, or a pile of CloudTrail JSON into an evidence-backed
account of which identity did what, from where, what it could have reached, and how to contain it
without destroying the trail.

Part of [secops-claude-skills](../../README.md).

## Overview

Cloud control planes log almost everything, so the answer is usually sitting in the logs. The hard
part is that the obvious first move is the wrong one.

**Containment destroys evidence.** Rotating the key ends the attacker's session, and with it the
record of what that session was doing. If the attacker already ran `StopLogging`, your rotation is
the second half of the cover-up. Export the window and snapshot the compute first; it costs minutes.
Deleting a key instead of deactivating it is the same mistake in miniature: nobody can match a
deleted key ID back to log lines afterward.

**One key is never the whole story.** Cloud intrusions are identity hops: a user key assumes a role,
that session assumes another, and somewhere in there a `CreateAccessKey` lands on a *different* user
or a new role trust policy quietly appears. Chasing the credential you were handed while the second
one survives your rotation is the classic bad outcome. So is looking only at the region and account
that alerted.

**"Could" is not "did".** Effective permissions size the worst case for a notification decision;
they are not a finding. The inverse trap is just as common: `readOnly: true` events like
`GetSecretValue`, `Decrypt`, and `GetObject` *are* the exfiltration. And if S3 data events or GCP
Data Access logs were off, the honest answer is "access cannot be confirmed or excluded", which is
precisely what counsel needs to hear.

## What it does

1. Pins the trigger, the accounts, and a UTC window starting at least 7 days before the alert.
2. Preserves first: confirms logging is intact, exports the window out of the attacker's reach,
   snapshots suspect compute to a forensic account.
3. Summarizes the logs mechanically and flags the high-signal control-plane events by identity.
4. Reconstructs the identity chain hop by hop, tracking source IP and user agent per hop.
5. Separates confirmed actions from effective permissions, and asks where the credential came from.
6. Contains in order, verifies the suspect identities only get `AccessDenied`, and hands off.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The nine-step workflow, the investigation-note template, and the pitfalls |
| `scripts/cloudtrail_summarize.py` | Reads CloudTrail in every shape you get handed and summarizes it |
| `references/aws.md` | CloudTrail field meanings, high-signal events by phase, Athena SQL, preservation, containment |
| `references/azure.md` | Activity Log / Entra tables, identity kinds, KQL, preservation, containment |
| `references/gcp.md` | Cloud Audit Log types, high-signal methods, Logging queries, BigQuery over a sink |
| `references/high-risk-events.txt` | The event-name list you can hand to `--high-risk` to replace the built-in one |
| `references/environment.md` | Your customization file: account inventory, where logs land, known-good automation, approvers |
| `examples/` | A synthetic 20-record CloudTrail export and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the situation:

> *an access key from our prod account showed up in a public repo, what do I do first*

> *here's the CloudTrail export for that GuardDuty finding, what did this role actually touch*

> *our AWS bill tripled overnight and there are instances in ap-southeast-2 we didn't launch*

### As a standalone tool

Plain Python, standard library only, read-only, never touches the network.

```bash
# Whole export directory: .json, .json.gz, and JSON Lines mixed together, recursive
python scripts/cloudtrail_summarize.py ./trail-export/ --format md

# One principal, machine-readable, for the timeline in your case notes
python scripts/cloudtrail_summarize.py events.json --identity "OrgAdmin" --format json

# Narrow to the window and the attacker IP
python scripts/cloudtrail_summarize.py events.json --from 2026-09-14T03:00:00Z --ip 203.0.113.77

# Replace the built-in high-risk list, or just add to it
python scripts/cloudtrail_summarize.py events.json --high-risk references/high-risk-events.txt
python scripts/cloudtrail_summarize.py events.json --extra-risk GetObject,ListBuckets
```

Real output from the bundled sample, trimmed to the sections that do the work:

```
## High-risk events (8)

| Time (UTC) | Event | Why it matters | Identity | Source IP | Error |
|---|---|---|---|---|---|
| 2026-09-14T02:11:05Z | `ConsoleLogin` | console sign-in (MFA: no) | `arn:aws:iam::123456789012:user/alice.dev` | 198.51.100.23 |  |
| 2026-09-14T02:15:48Z | `CreateAccessKey` | new long-lived credential | `arn:aws:iam::123456789012:user/alice.dev` | 198.51.100.23 |  |
| 2026-09-14T02:16:20Z | `AttachUserPolicy` | privilege change | `arn:aws:iam::123456789012:user/alice.dev` | 198.51.100.23 | AccessDenied |
| 2026-09-14T02:22:30Z | `StopLogging` | CloudTrail disabled | `arn:aws:sts::123456789012:assumed-role/OrgAdmin/ops2` | 198.51.100.23 |  |
| 2026-09-14T02:23:11Z | `GetSecretValue` | secret read | `arn:aws:sts::123456789012:assumed-role/OrgAdmin/ops2` | 198.51.100.23 |  |
| 2026-09-14T02:25:40Z | `PutBucketPolicy` | bucket policy changed | `arn:aws:sts::123456789012:assumed-role/OrgAdmin/ops2` | 198.51.100.23 |  |

Role chains (an assumed-role session assuming another role):
- `BackupOperator` -> `arn:aws:iam::123456789012:role/OrgAdmin` (1x)
```

(The `Params` column — target bucket, secret ID, policy ARN — is cut here for width.)

Twenty records, and the chain is already visible: a console login without MFA, a key minted on a
*different* user, a denied privilege escalation, then that user hopping `BackupOperator` into
`OrgAdmin` and turning logging off before reading two secrets. The full report also carries
per-identity counts (errors, recon volume, secret reads, distinct IPs, first and last seen), console
logins with MFA state, error codes, user agents, source IPs, and event sources.

The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input.

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
./scripts/install.sh cloud-incident-investigation          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 cloud-incident-investigation         # Windows
./scripts/install.sh --project cloud-incident-investigation   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the "Known-good automation" table in `references/environment.md`. Listing your CI roles,
Terraform service principals, and corporate egress ranges with their expected user agents is what
lets an investigation say "anything from a human principal outside these ranges deserves a look"
instead of re-deriving normal under time pressure.

Then record where each log source actually lands (Athena table, Log Analytics workspace, log bucket)
and whether data-plane events are on, because that yes/no decides whether you can answer the
data-exposure question at all. `references/high-risk-events.txt` is the defaults in `EventName,reason`
form: prune or extend it and pass it with `--high-risk`. The per-cloud references are meant to
accumulate your own query snippets.

## Related skills

- Indicators (IPs, user agents, key IDs, principal ARNs) go to [ioc-extraction](../ioc-extraction/)
- Techniques map in [mitre-attack-mapping](../mitre-attack-mapping/) against the cloud matrix
- Missing alerts ("no detection on `StopLogging`") go to [detection-engineering](../detection-engineering/)
- The narrative and timeline go to [incident-report-writing](../incident-report-writing/)
- Complex log queries are handed to [siem-query-authoring](../siem-query-authoring/)
- If the origin was an IdP compromise, [identity-threat-investigation](../identity-threat-investigation/)
  owns the user-side containment; run both in parallel
