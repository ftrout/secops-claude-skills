# Adversary-emulation content catalog (reference by ID only)

This file explains how the main public emulation projects are organized and how to cite a
specific test in a plan, ticket, or scorecard. It deliberately contains no commands or
payloads. The authorized operator pulls the actual test from the source project at run time
under the rules of engagement. Project structures and licenses are summarized as of
September 2026; verify against the project when you plan, since they update frequently.

Contents: why ID-only; Atomic Red Team; MITRE CALDERA; Stratus Red Team; ATT&CK Evaluations
and CTID emulation plans; other sources; how to record a mapping.

## Why reference by ID only

A purple-team plan needs to say *what* will be tested so everyone can agree it is in scope and
safe, and so the result is reproducible. It does not need the command in the plan: the command
lives in the source project, is run by one authorized operator, and changes as the project is
maintained. Keeping commands out of the plan also keeps this repository free of offensive
content and keeps your tickets safe to share. Cite the test precisely enough that the operator
can find exactly one thing.

## Atomic Red Team

- Maintained by Red Canary. A library of small, per-technique tests organized by ATT&CK
  technique. Licensed MIT (verify current license).
- Structure: one folder per technique ID (for example `T1003.001`), each containing a set of
  numbered "Atomic Tests", each with a name, supported platforms, input arguments, and a
  cleanup command.
- Cite as: **technique ID + "Atomic Test #N" + the test name**, plus platform. Example:
  `T1003.001 Atomic Test #1 "Dump LSASS.exe Memory using ProcDump" (windows)`. The number
  alone is not stable across edits, so always include the name.
- Runner: `Invoke-AtomicTest` (the operator's tool), which also runs the `--check-prereqs`
  and `--cleanup` phases. Your ROE should require prereq-check and cleanup for every test.
- Good for: fast, granular Windows/macOS/Linux technique validation. Note that many atomics
  are single-behavior and benign-ish; a few (impact, defense evasion) are destructive and
  belong on throwaway hosts only.

## MITRE CALDERA

- MITRE's automated adversary-emulation platform. Open source (Apache 2.0; verify).
- Structure: **abilities** (atomic actions, each tagged with an ATT&CK technique and an ID),
  grouped into **adversary profiles** (ordered chains), executed by **agents** on target hosts
  via **operations**. Plugins (for example `stockpile`, `atomic`) provide ability libraries.
- Cite as: **ability name + ability ID (a GUID) + the adversary profile** it runs in. Example:
  `CALDERA ability "Find files" (<ability-guid>) in profile "Hunter"`. Include the plugin if
  the ability is not in core stockpile.
- Good for: chained, sequenced emulation that resembles an intrusion, and for measuring
  detection across a whole profile rather than one behavior at a time. The operation timestamps
  are a convenient source of execution times for time-to-detect.

## Stratus Red Team

- Maintained by DataDog. "Atomic Red Team for the cloud": self-contained cloud attack
  techniques with built-in warm-up and cleanup. Open source (Apache 2.0; verify).
- Structure: techniques identified by a dotted string of the form
  `<platform>.<tactic>.<name>`, for example `aws.defense-evasion.cloudtrail-stop`,
  `aws.persistence.iam-backdoor-user`, `aws.credential-access.ec2-get-password-data`,
  `azure.execution.vm-run-command`, `gcp.persistence.backdoor-service-account-policy`. Each
  maps to one or more ATT&CK techniques.
- Cite as: **the Stratus technique ID** plus the ATT&CK technique it validates. Example:
  `Stratus aws.defense-evasion.cloudtrail-stop -> T1562.008`.
- Good for: validating cloud control-plane detections (pairs naturally with
  `cloud-incident-investigation`). Run only in the dedicated purple-team cloud account; some
  techniques create real (billable, and if left, exploitable) resources, so cleanup is
  mandatory.

## MITRE ATT&CK Evaluations and CTID adversary emulation plans

- The MITRE Engenuity ATT&CK Evaluations program and the Center for Threat-Informed Defense
  (CTID) publish **adversary emulation plans** that reproduce a specific named actor's
  operation as an ordered set of steps, each mapped to ATT&CK. Examples of covered actors have
  included APT3, APT29, FIN6/FIN7, Carbanak, Sandworm, menuPass, OilRig, and others; check the
  current library for what exists and its ATT&CK version.
- Structure: a scenario document with numbered steps, each citing the technique(s), the intent,
  and the expected artifacts.
- Cite as: **plan name + step number + technique**. Example: `CTID APT29 emulation plan, Step
  10 (T1547.001)`. These are the best source when your objective is "how well would we detect
  <named actor>", because the chain is realistic and already ATT&CK-mapped.
- Good for: threat-informed exercises derived from `threat-intel-analysis`. Heavier to run than
  atomics; often a lab-only, operator-led effort.

## Other sources you may cite the same way

- **Vendor and community detection tests** tied to a technique (cite by their published ID).
- **Purple Team Exercise Framework (PTEF)** by SCYTHE — a process framework, useful for
  structuring the engagement rather than as a test source.
- **Internal tests** your team has written: give each a stable internal ID and treat it like
  any other cited test.

Whatever the source, the plan cites the identifier; the command stays in the source project.

## Recording a mapping (what goes in the plan and the scorecard)

For each technique, capture: scenario, ATT&CK technique ID and name, tactic, the emulation
source and its test ID/name, target platform, the operator, and the **expected data source**.
That last column is what lets the scorecard distinguish a telemetry gap from a detection gap.
Example plan row:

| Scenario | Technique | Tactic | Emulation test (ID only) | Platform | Expected source |
|---|---|---|---|---|---|
| Ransomware precursor | T1003.001 LSASS Memory | Credential Access | ART T1003.001 Test #1 (ProcDump) | Windows | Sysmon 10 + EDR |
| Ransomware precursor | T1490 Inhibit System Recovery | Impact | ART T1490 Test #1 (delete shadow copies) | Windows (throwaway) | Sysmon 1 + EDR |
| Cloud identity | T1562.008 Disable Cloud Logs | Defense Evasion | Stratus aws.defense-evasion.cloudtrail-stop | AWS | CloudTrail StopLogging |

After the run, the same rows plus `observed` (alert/logged/none) and `ttd_minutes` become the
scorecard CSV. Keep the ATT&CK version noted at the top of the plan; the tactic travels in the
data so nothing here needs a hard-coded lookup that would go stale.
