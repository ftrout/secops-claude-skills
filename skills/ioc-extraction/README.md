# ioc-extraction

Turn a threat report, advisory, phishing email, or pasted log into a clean, de-duplicated
indicator list with roles, confidence, and shelf life, in the format your tooling ingests.

Part of [secops-claude-skills](../../README.md).

## Overview

Getting indicators out of a document sounds like a regex problem. It is not. Three things go
wrong in practice, and this skill is built around them.

**Indicators hide.** Reports defang URLs (`hxxp`, `[.]`, `(dot)`), PDFs insert spaces into
long hashes, and tables wrap addresses across lines. A naive grep misses these entirely.

**Noise gets shipped.** Vendor reports cite their own blog, link VirusTotal, and mention that
the malware checks connectivity to a Microsoft endpoint. Blocking those causes an outage. The
most damaging output of a bad extraction is not a missed indicator, it is a blocklist entry
that breaks legitimate traffic.

**Context gets lost.** An indicator with no role and no expiry is nearly useless downstream.
An analyst needs to know whether an address is command-and-control or a sandbox reference,
how confident the source was, and when it stops being worth alerting on.

The skill handles the mechanical parts with a script and reserves your judgment for the parts
that need it: deciding what is noise, assigning roles, and setting shelf life.

## What it does

1. Reads the source text, whatever the format.
2. Runs the extractor, which refangs, de-duplicates, classifies by type, and drops
   allow-listed values.
3. Triages the results against a noise checklist, so the vendor's own infrastructure and
   analysis services do not end up on a blocklist.
4. Assigns a role, a confidence, and a shelf life to each surviving indicator.
5. Emits the deliverable in the shape the consumer needs, then names the follow-up action and
   which sibling skill owns it.

### What is included

| File | Purpose |
|---|---|
| `SKILL.md` | The workflow Claude follows, output templates, and pitfalls |
| `scripts/extract_iocs.py` | Extraction, refanging, classification, de-duplication, output formatting |
| `scripts/defang.py` | Defang or refang an entire block of text, for safe pasting into tickets |
| `references/ioc-types.md` | Every emitted type, the noise checklist, role and confidence vocabularies, shelf-life table |
| `references/enrichment.md` | What each enrichment source actually tells you, internal sources included |
| `references/environment.md` | Your customization file: tooling, formats, enrichment access |
| `references/allowlist.txt` | Glob patterns dropped from extraction, so your own domains never appear |
| `examples/` | A synthetic advisory and the CI smoke manifest |

Supported types: URLs, emails, MD5/SHA-1/SHA-256/SHA-512, CVEs, IPv4, IPv6, domains, registry
keys, Windows and Unix paths, Bitcoin and Ethereum addresses, and MAC addresses.

## Using it

### In Claude Code

You do not invoke it by name. Describe the work:

> *pull the IOCs out of this advisory and tell me what we should actually block*

> *defang these before I paste them into the ticket*

> *turn this report into a Sentinel watchlist*

> *is this indicator list clean, or is there junk in it?*

### As a standalone tool

The scripts are plain Python with no dependencies, so they work outside Claude too.

```bash
# Markdown table, safe to paste into a ticket
python scripts/extract_iocs.py examples/sample-report.txt --format md --defang

# CSV for a SIEM watchlist, with the sentence each indicator came from
python scripts/extract_iocs.py report.txt --format csv --context

# Just the network indicators, one per line, for a blocklist
python scripts/extract_iocs.py report.txt --types domain,url,ipv4 --format list

# STIX 2.1 bundle for a threat intel platform
python scripts/extract_iocs.py report.txt --format stix

# From stdin
cat report.txt | python scripts/extract_iocs.py - --format json
```

Real output from the bundled sample:

```
| Indicator                                       | Type         | Count |
|-------------------------------------------------|--------------|-------|
| hxxp[://]evil-domain[.]example/payload[.]php     | url          | 1     |
| billing[@]invoices-fake[.]com                    | email        | 1     |
| 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1... | sha256       | 1     |
| CVE-2024-3400                                    | cve          | 1     |
| C:\Users\Public\update.exe                       | windows_path | 1     |
```

Note what is absent: the sample mentions `www.microsoft.com` as a connectivity check, and it
does not appear. That filtering is the point.

Defanging a whole block of text:

```bash
python scripts/defang.py --defang notes.txt
python scripts/defang.py --refang ticket_excerpt.txt
```

Both scripts take `--help`, read `-` for stdin, write to stdout, and exit 2 on bad input.

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
./scripts/install.sh ioc-extraction          # POSIX, to ~/.claude/skills
.\scripts\install.ps1 ioc-extraction         # Windows
./scripts/install.sh --project ioc-extraction   # to ./.claude/skills
```

Requires Python 3.10+ for the scripts. Full options in
[docs/installation.md](../../docs/installation.md).

## Customize

Start with `references/allowlist.txt`. Add your corporate domains, mail domains, and public IP
ranges as glob patterns, and the extractor will never emit them as indicators. This is the
single highest-value edit, because your own infrastructure appearing on a blocklist is the
expensive failure.

Then fill in `references/environment.md` with the CSV column order your SIEM expects, which
enrichment sources you have access to, and your retro-hunt look-back windows.

## Related skills

- Hashes and suspicious files go to [malware-triage](../malware-triage/)
- CVEs go to [vulnerability-triage](../vulnerability-triage/); a CVE is not blockable
- Retro-hunt queries come from [siem-query-authoring](../siem-query-authoring/)
- Host artifacts feed [detection-engineering](../detection-engineering/) or
  [threat-hunting](../threat-hunting/)
- Surrounding TTPs go to [mitre-attack-mapping](../mitre-attack-mapping/) and
  [threat-intel-analysis](../threat-intel-analysis/)
