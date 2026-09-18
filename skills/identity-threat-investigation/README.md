# identity-threat-investigation

Turn "I think Bob got phished" and a sign-in export into a verdict: whether the account is under
someone else's control, since when, what the attacker did with it, what they left behind, and the
order in which to shut every door at once.

Part of [secops-claude-skills](../../README.md).

## Overview

Identity is the perimeter, which means most of this work is separating the noisy from the real and
then containing without leaving a hole. Three things make it harder than the alert makes it look.

**The obvious signals lie in both directions.** Most "impossible travel" is a VPN, a carrier NAT, or
a privacy relay, and most MFA failures are a user fumbling a phone. Meanwhile the real compromise
often looks clean: after an adversary-in-the-middle session theft the stolen token carries the MFA
claim, so every later sign-in reads as MFA-compliant, and the attacker's ongoing use lands in the
non-interactive sign-in logs nobody queries. Consent phishing steals no password at all, so every
credential-centric check comes back green.

**Containment order decides whether it works.** Reset without revoking and the attacker's refresh
tokens, PRTs, and session cookies keep working. Revoke without resetting and they re-authenticate
with the password they still have. Do both and stop there, and the OAuth app they consented, the MFA
method they registered, the inbox rule forwarding mail, and the federation trust they added are all
still live. Access tokens outlive the revoke by up to an hour, so a sensitive account needs a
Conditional Access block too.

**The IdP is not the whole story.** The same session may have opened an AWS console, a VPN, GitHub,
or a domain-joined server. If Active Directory is in scope there is a separate set of signatures to
look for — Kerberoasting, AS-REP roasting, DCSync, golden tickets, NTDS theft — with their own event
IDs, their own noise problems, and a krbtgt reset you must not rush.

## What it does

1. Pins the subject, the directory, and a window starting at least 14 days before the trigger.
2. Runs the sign-in analyzer to surface travel, MFA bursts, new geography, and legacy auth.
3. Classifies the compromise — credential only, MFA fatigue, AiTM/token replay, legacy auth,
   consent phishing, insider — and records the evidence for and against.
4. Hunts persistence: MFA methods, devices, OAuth consents, inbox rules, role and group changes,
   policy and federation edits, then sizes what the account could reach.
5. Checks the Active Directory signatures when on-prem or Tier 0 is in scope.
6. Contains in order on every plane at once, then re-runs the analyzer over the next 48 hours.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The eight-step workflow, the investigation-note template, and the pitfalls |
| `scripts/signin_analyzer.py` | Sign-in CSV triage: impossible travel, MFA fatigue, new country/UA, legacy auth, scoring |
| `references/entra-id.md` | Tables, `ResultType` codes, Identity Protection risk types, AiTM indicators, KQL, containment |
| `references/okta.md` | System Log record anatomy, event types by phase, attack patterns, filter expressions, containment |
| `references/active-directory.md` | Required auditing, event IDs by phase, attack signatures, KQL over `SecurityEvent`, containment |
| `references/environment.md` | Your customization file: platforms, log locations, expected geography, thresholds, approvers |
| `examples/` | A synthetic 40-event Entra-shaped sign-in export and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe what happened:

> *bob says he approved an MFA prompt he didn't request, can you check his sign-ins*

> *is this impossible travel alert real or is it just the VPN again*

> *user clicked a link and entered creds, what do I check before I call it contained*

### As a standalone tool

Plain Python, standard library only, read-only, no network access.

```bash
# Whole export, Markdown report
python scripts/signin_analyzer.py signins.csv --format md

# One user, machine-readable, for the case notes
python scripts/signin_analyzer.py signins.csv --user alice --format json

# An export whose headers the auto-detector does not know
python scripts/signin_analyzer.py okta_export.csv --col user=actor.alternateId --col timestamp=published

# Tighten or loosen the flags for your environment
python scripts/signin_analyzer.py signins.csv --mfa-burst 3 --max-kmh 800 --baseline-days 14
```

Real output from the bundled sample, trimmed:

```
## Users by risk

| User | Score | Events | OK | Fail | IPs | Countries | UAs | Reasons |
|---|---|---|---|---|---|---|---|---|
| bob.finance@yourcompany.example | 10 | 11 | 5 | 6 | 2 | NG, US | 2 | MFA failure burst x1 then success; failed-then-success from new IP x1; new country: NG; new user agent x1 |
| carol.hr@yourcompany.example | 9 | 7 | 4 | 3 | 2 | DE, US | 3 | failed-then-success from new IP x1; new country: DE; legacy auth success x2; new user agent x2 |
| alice.dev@yourcompany.example | 6 | 9 | 9 | 0 | 2 | NL, US | 2 | impossible travel x1; new country: NL; new user agent x1 |

### bob.finance@yourcompany.example (score 10)
- **MFA failure burst:** 6 MFA failures 2026-09-13T22:01:05Z to 2026-09-13T22:06:59Z from 192.0.2.150 (NG), app=Office 365 Exchange Online; **success at 2026-09-13T22:08:10Z** from 192.0.2.150 (mfa=multiFactorAuthentication)

### carol.hr@yourcompany.example (score 9)
- **Legacy auth success:** IMAP4 from 198.51.100.201 (DE) at 2026-09-14T03:12:30Z

### alice.dev@yourcompany.example (score 6)
- **Impossible travel:** US (203.0.113.10) at 2026-09-12T13:10:44Z -> NL (198.51.100.77) at 2026-09-12T13:41:02Z; 7443 km in 0.5 h = 14739 km/h; app=OfficeHome; mfa=multiFactorAuthentication
```

(Cut for width: `First seen` / `Last seen`, three lower-scoring users, and the "new country" and
"new user agent" findings.)

Three different stories in one export: Bob is push-bombed until he accepts, Carol's account is used
over SMTP and IMAP with single-factor auth from a `python-requests` client, and Alice's flag is the
one most likely to be a VPN. The score orders the queue; it is not a verdict, and the reasons are
printed so you can argue with it.

The script takes `--help`, reads `-` for stdin, writes to stdout, and exits 2 on bad input. Headers
from Entra, Okta, Workspace, and generic SIEM exports are auto-detected; the report prints which
columns it used so you can tell when it guessed wrong.

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
./scripts/install.sh identity-threat-investigation          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 identity-threat-investigation         # Windows
./scripts/install.sh --project identity-threat-investigation   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Fill in the "Expected geography and networks" table in `references/environment.md` first. Your
corporate egress ranges, VPN ranges and ASNs, and the relays your users actually hit turn every
travel flag from a question into an answer: dismiss the VPN hop in a sentence, and spend the
attention on the sign-in that came from a hosting ASN.

Next: the "Accounts that need owner approval" table — the shared mailboxes, service principals, and
break-glass accounts where disabling first breaks a business process. Then the analyzer thresholds
you settled on, and where each log lives and for how long, since retention decides whether a 14-day
look-back is even possible.

## Related skills

- Watchlist the attacker IPs, ASNs, and user agents through [ioc-extraction](../ioc-extraction/)
- The phishing email itself goes to [phishing-analysis](../phishing-analysis/)
- Event queries come from [siem-query-authoring](../siem-query-authoring/); raw host and DC artifacts
  come from [log-forensics](../log-forensics/)
- Detection gaps (no alert on legacy auth success, none on consent to a multi-tenant app) go to
  [detection-engineering](../detection-engineering/)
- Other users hit by the same IP go to [incident-triage](../incident-triage/); root cause and
  timeline go to [incident-report-writing](../incident-report-writing/)
- If the identity was used against cloud resources,
  [cloud-incident-investigation](../cloud-incident-investigation/) owns that side; run both in parallel
