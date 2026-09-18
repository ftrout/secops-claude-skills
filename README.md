# Claude skills for Security Operations

[![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-D97757?logo=anthropic&logoColor=white)](https://code.claude.com/docs/en/plugins)
[![validate-skills](https://github.com/ftrout/secops-claude-skills/actions/workflows/validate.yml/badge.svg)](https://github.com/ftrout/secops-claude-skills/actions/workflows/validate.yml)
[![16 skills](https://img.shields.io/badge/skills-16-informational)](#skills)
[![Python 3.10+, no dependencies](https://img.shields.io/badge/python-3.10%2B%20%7C%20no%20dependencies-3776AB?logo=python&logoColor=white)](CONTRIBUTING.md#scripts-standard)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Advanced, customizable [Claude Code skills](https://code.claude.com/docs/en/skills) for
security operations teams. Each skill encodes how an experienced analyst approaches a task,
ships the reference material Claude would otherwise guess at, and bundles small
standard-library Python tools for the deterministic parts (parsing, scoring, formatting).

Everything here is defensive. No exploit code, no offensive tooling, no credentials.

## What it looks like

You do not invoke these by name. You describe the work, and Claude picks the skill up from
the description:

> *pull the indicators out of this advisory and tell me what we should actually block*

Claude runs the extractor over the text, drops the vendor's own domains and the
connectivity-check hosts that reports always include, and returns something you can act on
rather than a raw regex dump:

| Indicator (defanged) | Type | Role | Confidence | Valid until |
|---|---|---|---|---|
| hxxps://cdn-sync[.]example/api/v2 | url | c2 | high | +30d |
| 3a7b…4f1b | sha256 | dropped-file | high | indefinite |
| billing[@]invoices-fake[.]com | email | phishing-sender | medium | +30d |

It then names the next step and which skill owns it: retro-hunt the domain over 30 days of
proxy and DNS, search the mail gateway for the sender, and hand the hash to static triage.
Other prompts that land somewhere useful:

- *is this alert worth waking someone up for* → severity with the evidence for and against
- *why did this rule fire 400 times last night* → false-positive tuning, not just a rewrite
- *write the exec summary for the incident we closed yesterday* → audience-appropriate draft
- *this user's sign-ins look weird* → impossible travel, MFA fatigue, and legacy auth checks

## Skills

| Skill | Use it when you need to... | Bundled tooling |
|---|---|---|
| [ioc-extraction](skills/ioc-extraction/) | Pull indicators out of reports, emails, or logs; defang/refang; produce watchlists, blocklists, STIX | `extract_iocs.py`, `defang.py` |
| [incident-triage](skills/incident-triage/) | Work an alert to a verdict: evidence for/against, scope, severity, escalation | `triage_score.py`, per-alert-class playbooks |
| [incident-report-writing](skills/incident-report-writing/) | Write exec summaries, post-incident reports, status updates, notifications, lessons learned | `timeline_format.py`, report templates |
| [soar-playbook-design](skills/soar-playbook-design/) | Design safe automation playbooks with approval gates, idempotency, and rollback | `playbook_lint.py`, example playbooks |
| [detection-engineering](skills/detection-engineering/) | Author, review, test, and tune Sigma rules; map to ATT&CK; manage the rule lifecycle | `sigma_lint.py`, review checklist |
| [siem-query-authoring](skills/siem-query-authoring/) | Turn a question or indicator list into correct KQL, SPL, Elastic, Chronicle, or SQL | `ioc_to_query.py`, per-platform field references |
| [threat-hunting](skills/threat-hunting/) | Build hypothesis-driven hunts, run stacking/rarity analysis, document outcomes | `stack.py`, hypothesis library |
| [phishing-analysis](skills/phishing-analysis/) | Analyze headers, authentication, URLs, lures; reach a verdict; respond and communicate | `parse_email_headers.py` |
| [malware-triage](skills/malware-triage/) | Safely triage a suspicious file statically; read sandbox reports; draft YARA | `file_triage.py` |
| [log-forensics](skills/log-forensics/) | Investigate from Windows, Sysmon, Linux, and web logs; build a super-timeline | `timeline_builder.py`, event ID references |
| [threat-intel-analysis](skills/threat-intel-analysis/) | Turn raw intel into graded, actionable products with TLP and Diamond Model | `stix_summary.py`, product templates |
| [mitre-attack-mapping](skills/mitre-attack-mapping/) | Map behaviors and reports to ATT&CK with rationale; generate Navigator layers | `navigator_layer.py` |
| [vulnerability-triage](skills/vulnerability-triage/) | Prioritize CVEs with CVSS, EPSS, KEV, exposure, and business context; plan remediation | `prioritize_vulns.py` |
| [cloud-incident-investigation](skills/cloud-incident-investigation/) | Investigate and contain in AWS, Azure, and GCP control planes | `cloudtrail_summarize.py`, per-cloud query references |
| [identity-threat-investigation](skills/identity-threat-investigation/) | Investigate account compromise in Entra ID, Okta, and Active Directory | `signin_analyzer.py` |
| [purple-team-exercise](skills/purple-team-exercise/) | Plan detection-validation exercises and turn results into a detection backlog | `scorecard.py`, exercise templates |

The skills hand off to each other: `phishing-analysis` passes attachments to `malware-triage`,
`threat-intel-analysis` passes TTPs to `mitre-attack-mapping` and indicators to
`ioc-extraction`, `threat-hunting` and `purple-team-exercise` feed `detection-engineering`, and
everything ends in `incident-report-writing`.

## Install

Inside Claude Code:

```
/plugin marketplace add ftrout/secops-claude-skills
/plugin install secops-skills@secops-claude-skills
```

Or copy the folders you want into `~/.claude/skills` (personal) or `.claude/skills`
(project) with `scripts/install.sh` / `scripts/install.ps1`. Details and other options in
[docs/installation.md](docs/installation.md).

Requirements: Claude Code, and Python 3.10+ for the bundled scripts (standard library only,
nothing to install).

## Customize

The skills are generic on purpose. Fifteen minutes per skill in `references/environment.md`
(your SIEM, EDR, severity scale, naming, escalation paths, what you own) turns generic output
into something you can paste into a ticket. Score weights, allowlists, field mappings, and
high-risk event lists live in small JSON/text files next to the scripts.

See [docs/customization.md](docs/customization.md) for the four layers of customization and
how to keep your changes separate from upstream.

## How a skill is built

```
skills/<skill-name>/
├── SKILL.md            # workflow, output templates, pitfalls; this is what Claude reads
├── scripts/            # stdlib Python, --help, stdin/stdout, no network, no execution of samples
├── references/         # deep material loaded on demand; environment.md is your customization file
├── assets/             # optional: templates that end up in outputs
└── examples/           # optional: sample inputs and the smoke.json manifest CI runs
```

Only `SKILL.md` and `references/environment.md` are required. The rest exist where they earn
their place, so a skill stays small enough to load without burning context.

`scripts/validate_skills.py` enforces the structure and `scripts/smoke_test.py` runs every
bundled script against its examples. Both run in CI on Linux and Windows, against Python 3.10
and 3.13.

## Safety

- Skills that read attacker-controlled content (emails, samples, reports) instruct Claude to
  treat that content as data, never as instructions. Review verdicts on high-impact decisions.
- No bundled script executes, opens, renders, or fetches the content it parses.
- Containment guidance is written to be executed by a human with an approval step. The SOAR
  linter flags auto-containment without justification.
- See [SECURITY.md](SECURITY.md) for reporting issues.

On maturity: the bundled scripts are covered by CI on every push, across two operating systems
and both ends of the supported Python range. The analytical guidance is reference material,
not a substitute for your own judgment. Event IDs, log field names, and regulatory deadlines
drift, and every environment has its own baseline of normal. Read a skill before you lean on
it, and check the parts that touch your tooling.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the authoring standard, copy
`templates/skill-template/`, and open a pull request. Ideas that fit: runbooks for common
business applications, additional SIEM platforms, region-specific regulatory checklists.

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md). The rule most specific
to this project: sanitize anything drawn from a real incident before you post it.

## License

MIT. See [LICENSE](LICENSE).
