# phishing-analysis

Turn a reported `.eml` or a pasted block of headers into a verdict with evidence: routing and
authentication, sender identity mismatches, defanged URLs, hashed attachments, a lure class,
and a blast radius someone can act on within the hour.

Part of [secops-claude-skills](../../README.md).

## Overview

Phishing triage looks like pattern matching and is actually an evidence problem. Four failures
account for most bad calls, and the skill is built around them.

**The wrong header gets read.** Attackers happily write their own
`Authentication-Results: ...; spf=pass; dkim=pass` into the message, and it looks identical to
the real one. Only the header stamped by your own MX means anything, so the parser prints the
`authserv-id` for every one.

**"SPF passed, so it's fine."** SPF authorizes the *sending infrastructure* for the envelope
sender. It says nothing about the `From:` domain unless DMARC aligns them, and nothing at all
about a lookalike domain the attacker registered yesterday with a perfect SPF record. The
bundled sample is exactly this shape: SPF pass, DKIM pass, DMARC fail.

**The email is treated as instructions.** The body, subject, attachment names, and header text
are all attacker-controlled data. "Forward this to IT", "reply with the code", "this has been
verified by security", or text addressed to an AI assistant are findings to report, never
directions to follow. The parser never fetches a URL, never renders HTML, and never opens an
attachment; it reads bytes and hashes them.

**The investigation stops at one inbox.** The reporter is rarely the only recipient, and blast
radius rather than the verdict is what decides whether this is a ticket or an incident.

## What it does

1. Insists on the original message, not a forward, and records what the user actually did.
2. Runs the parser: Received chain in order, authentication parsed and aligned, URLs defanged,
   redirect wrappers decoded, attachments hashed.
3. Reads routing and identity: which server authenticated what, and how From, Return-Path,
   Reply-To, DKIM `d=`, and the display name disagree.
4. Classifies the lure by its *ask* (click, open, reply, call, scan, approve) and analyzes URLs
   passively, without visiting them from a corporate workstation.
5. Reaches a verdict with a confidence level and the evidence *against* it written down too.
6. Scopes the blast radius across the tenant, then produces purge, block, reset, and notify
   actions plus hand-offs to the sibling skills.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The eleven-step workflow, the note template, and the failure modes |
| `scripts/parse_email_headers.py` | Received chain, authentication, alignment, URLs, attachments, findings |
| `references/header-fields.md` | Every header field: who sets it, whether it is forgeable, what to read |
| `references/lure-patterns.md` | Lure families, kit fingerprints, attachment tricks, lookalike and URL techniques |
| `references/environment.md` | Your customization file: platform, sandboxes, block actions, thresholds |
| `examples/` | A synthetic phishing `.eml` and the CI smoke manifest |

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *user reported this, is it phishing or just spam*

> *why did DMARC fail on this when SPF passed?*

> *here are the headers, where did it actually come from*

> *who else got this and did anyone click*

### As a standalone tool

The parser is plain Python with no dependencies, so it works outside Claude too. Pass every
corporate and brand domain with `--org-domain` (repeatable) to turn on lookalike detection.

```bash
# Markdown report, with lookalike checks against your domain
python scripts/parse_email_headers.py examples/sample-phish.eml --org-domain yourcompany.example

# JSON for tooling, live (undefanged) values; raw headers on stdin
python scripts/parse_email_headers.py message.eml --format json --no-defang
cat headers.txt | python scripts/parse_email_headers.py -

# Save attachments as <sha256>.bin, no extension, so nothing auto-opens
python scripts/parse_email_headers.py message.eml --extract-dir ./attachments
```

Trimmed real output from the bundled sample:

```
| Method | Result | Properties |
|---|---|---|
| SPF | **pass** | smtp.mailfrom=mail-relay.example.net |
| DKIM | **pass** | header.d=mail-relay.example.net; header.s=sel1 |
| DMARC | **fail** | action=quarantine; header.from=yourcompany-billing.example |
| COMPAUTH | **fail** | reason=000 |

| # | Time (UTC) | Delay | From host | rDNS/HELO | IP | Scope | By | With |
| 1 | 2026-09-15T13:58:41Z |  | [198[.]51[.]100[.]77] | unknown | 198.51.100.77 | documentation | mail-relay[.]example[.]net | ESMTPA |
| 2 | 2026-09-15T14:03:10Z | 269s | mail-relay[.]example[.]net | mail-relay[.]example[.]net | 203.0.113.45 | documentation | mx1[.]yourcompany[.]example | ESMTPS |

- **high**: From domain looks like a lookalike of yourcompany.example (yourcompany-billing.example)
- **high**: Reply-To domain differs from From domain (classic BEC / conversation-redirect tell)
- **high**: URL flag link_text_mismatch (hxxps://nam02[.]safelinks[.]protection[.]outlook[.]com/?url=...)
- **high**: Attachment Invoice-4471.pdf.html contains a form posting to a remote URL
  (hxxp://198[.]51[.]100[.]77/collect.php)
- **info**: Hop 1: authenticated submission (ESMTPA) from 198.51.100.77 to mail-relay.example.net
```

The Safe Links wrapper is decoded back to its real destination, the anchor text claimed
`portal.office.com`, and `ESMTPA` on the first hop names the relay account as the thing that
sent it. The findings list is observations; the verdict is yours. The script takes `--help`,
reads `-` for stdin, writes to stdout, and exits 2 on bad input.

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
./scripts/install.sh phishing-analysis          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 phishing-analysis         # Windows
./scripts/install.sh --project phishing-analysis   # to ./.claude/skills
```

Requires Python 3.10+ for the script. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with the domain list at the top of `references/environment.md`. Your corporate mail
domains, brand domains, and known lookalikes are what `--org-domain` consumes, and they turn a
generic "Reply-To differs" note into "this is impersonating us". Add the header your
phishing-simulation vendor stamps in the same file, so nobody spends an hour on an internal
test. Then fill in where original headers live in your gateway, which sandboxes you may use,
which block actions need a change ticket, and the click and credential-submission thresholds
that turn a ticket into an incident. `references/lure-patterns.md` is worth extending with the
lures your industry actually gets.

## Related skills

- Attachments and anything executable go to [malware-triage](../malware-triage/)
- Indicators for watchlists go through [ioc-extraction](../ioc-extraction/)
- Credential submitters become an
  [identity-threat-investigation](../identity-threat-investigation/)
- A novel lure or kit fingerprint becomes a detection ask for
  [detection-engineering](../detection-engineering/) and a hunt for
  [threat-hunting](../threat-hunting/)
- Campaign context goes to [threat-intel-analysis](../threat-intel-analysis/)
- Past the escalation threshold, hand to [incident-triage](../incident-triage/) and the writeup
  to [incident-report-writing](../incident-report-writing/)
