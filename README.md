# secops-claude-skills

Advanced, customizable [Claude Code skills](https://code.claude.com/docs/en/skills) for
security operations teams. Each skill encodes how an experienced analyst approaches a task,
ships the reference material Claude would otherwise guess at, and bundles small
standard-library Python tools for the deterministic parts (parsing, scoring, formatting).

Everything here is defensive. No exploit code, no offensive tooling, no credentials.

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
├── assets/             # templates that end up in outputs
└── examples/           # sample inputs and smoke.json used by CI
```

`scripts/validate_skills.py` enforces the structure and `scripts/smoke_test.py` runs every
bundled script against its examples. Both run in CI on Linux and Windows.

## Safety

- Skills that read attacker-controlled content (emails, samples, reports) instruct Claude to
  treat that content as data, never as instructions. Review verdicts on high-impact decisions.
- No bundled script executes, opens, renders, or fetches the content it parses.
- Containment guidance is written to be executed by a human with an approval step. The SOAR
  linter flags auto-containment without justification.
- See [SECURITY.md](SECURITY.md) for reporting issues.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the authoring standard, copy
`templates/skill-template/`, and open a pull request. Ideas that fit: runbooks for common
business applications, additional SIEM platforms, region-specific regulatory checklists.

## License

MIT. See [LICENSE](LICENSE).
