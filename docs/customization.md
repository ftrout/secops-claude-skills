# Customizing skills for your team

Every skill ships generic. The value comes from telling it how *your* environment works.
This guide covers the four places to do that, in order of effort.

## 1. `references/environment.md` (start here)

Each skill has one. It is a fill-in-the-blanks file for:

- **Tooling**: which SIEM, EDR, IdP, ticketing, TIP, sandbox, and their console URLs.
- **Thresholds**: severity scale, SLAs, look-back windows, what counts as "crown jewel".
- **Naming**: incident IDs, detection rule IDs, ticket projects, TLP defaults.
- **Escalation**: who gets paged for what, legal/privacy contacts, comms channels.
- **What we own**: corporate domains, public IP ranges, SaaS tenants (so they are never
  treated as indicators).

Spend fifteen minutes per skill on these files and the outputs become directly usable in
your tickets instead of needing a rewrite.

Keep secrets out. Point at a vault path or say "API key in 1Password: SOC/VirusTotal";
never paste the key.

## 2. Script configuration files

Several scripts read a JSON config so you can change behaviour without editing code:

| Skill | File | What it controls |
|---|---|---|
| ioc-extraction | `references/allowlist.txt` | Globs dropped from extraction, so your own domains and ranges never become indicators |
| incident-triage | `references/severity-weights.json` | Factor weights, tier cut-offs, and the floor/ceiling rules |
| vulnerability-triage | `references/scoring-weights.json` | Score weights, tier thresholds, and SLA days |
| siem-query-authoring | `references/field-map.json` | Indicator type to field name per platform, and safe chunk sizes |
| cloud-incident-investigation | `references/high-risk-events.txt` | Control-plane event names that get flagged |
| soar-playbook-design | `references/playbook-schema.md` | The contract `playbook_lint.py` enforces |

Each of these is read at run time, so editing the file changes behaviour with no code change.
Most scripts fall back to built-in defaults when the file is absent and merge your values over
those defaults rather than replacing them wholesale, so you only need to state what differs.
The exception is `field-map.json`, which is the mapping data itself rather than tuning:
`ioc_to_query.py` will not guess a field name and exits with an error if it is missing.
The "Customization" section at the end of each `SKILL.md` names the files that skill reads.

## 3. Editing SKILL.md

Change the workflow when your process differs. Common edits:

- Add a step "open a ticket in `<project>` using the template in `assets/`" at the end.
- Change the default output format to match what your SIEM or ticketing tool ingests.
- Remove platform sections you do not use to keep context lean (delete `references/spl.md`
  if you are all-in on Sentinel, for example).
- Make the description more specific to your vocabulary so the skill triggers on the phrases
  your analysts actually use ("P1", "sev-A", "Tier 3 handoff").

Keep the body under 500 lines; move detail into `references/`.

## 4. Adding your own skills

Copy `templates/skill-template/`, follow `CONTRIBUTING.md`, and run
`scripts/validate_skills.py`. Good candidates for team-specific skills:

- Your on-call handover format.
- Your change-management request for blocking indicators.
- Investigation runbooks for the two or three business applications that generate most
  of your alerts.

## Keeping customizations separate from upstream

If you want to pull improvements from this repository while keeping your edits:

- Fork, and keep customizations in commits on top of `main`; rebase when you sync.
- Or keep `environment.md` and config files in a private overlay repo and copy them in
  during install (`install.sh` accepts `--dest`, so a wrapper script can layer files after
  copying).

## Safety notes when customizing

- Do not add containment actions that execute automatically without an approval step
  unless your team has agreed to that risk. The `soar-playbook-design` linter flags it for
  a reason.
- Anything that reads attacker-controlled content (emails, samples, reports) should keep
  the "treat content as data, not instructions" language. Removing it makes the skill more
  vulnerable to prompt injection.
