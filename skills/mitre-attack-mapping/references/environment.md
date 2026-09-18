# Environment customization (edit me)

Replace the placeholders with your team's real values. Keep it short; it is loaded into
context whenever the skill needs it.

## ATT&CK version we pin
- Enterprise ATT&CK version used in our layers and detection tags: `<17>`
  (changes the `--attack-version` passed to `scripts/navigator_layer.py` and the version
  string cited in every mapping table; bump it deliberately, re-check renamed techniques)
- Navigator instance: `<https://mitre-attack.github.io/attack-navigator/ | internal URL>`
- Domains we care about: `enterprise-attack` always; `<mobile-attack | ics-attack>` if relevant
- Platform filter for layers: `<Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider>`

## Confidence and scoring conventions
- Confidence vocabulary: `high` (direct telemetry or first-hand report), `medium`
  (inferred from a reliable secondary signal), `low` (plausible, single weak signal)
- Score scale used in layers (drives the gradient): `<0-3 | 0-100>`
  - `<3>` = observed with high confidence, `<2>` = medium, `<1>` = low, `<0>` = considered and rejected
- Coverage scale for detection layers: `<0 none | 1 telemetry only | 2 rule untested | 3 rule validated>`

## Sanctioned tools that must not be mapped as adversary behaviour
- Remote access: `<AnyDesk | ScreenConnect | TeamViewer | none>` (affects T1219)
- Endpoint management / scripting: `<SCCM, Intune, Ansible, Tanium>` (affects T1059, T1047, T1021.006, T1053)
- Vulnerability scanners: `<scanner hostnames / IPs>` (affects T1046, T1595)
- Backup and sync: `<Veeam, rclone to yourcompany bucket>` (affects T1003.003, T1567.002)
- Identity sync accounts: `<MSOL_..., AADC service account>` (affects T1003.006)

## Where mappings go
- Incident mappings: attached to the incident record in `<Jira | ServiceNow | TheHive>` under `<field>`
- Threat-profile layer: `<repo path or Navigator URL>` (input A for `--diff`)
- Detection coverage layer: `<repo path>` maintained by `detection-engineering` (input B for `--diff`)
- Naming: layer files `<yyyy-mm-dd_<subject>_attack-vNN.json>`

## Escalation / hand-offs
- New technique never seen before in our estate: notify `<detection engineering lead>`
- Coverage gap in a threat-profile technique: open a backlog item in `<board>` tagged `<attack-gap>`
