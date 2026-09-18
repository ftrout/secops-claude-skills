# Rule review checklist

Use this for peer review before a rule moves from `experimental` to `test`, and again
before `stable`. Copy the checklist into the review comment and tick each line with a
one-word answer or a link. A blank line is a review finding.

## A. Requirement and scope

- [ ] There is a written requirement (threat report, hunt finding, purple-team gap,
      incident lesson, compliance control). Link it in `references`.
- [ ] The rule detects a *behaviour*, not a single indicator. (Indicator matches belong in
      watchlists built by `ioc-extraction` and queried with `siem-query-authoring`.)
- [ ] The ATT&CK technique/sub-technique tag matches what the logic actually observes, not
      the whole kill chain the report described. (`mitre-attack-mapping` for hard cases.)
- [ ] The rule does not duplicate an existing rule; if it overlaps, `related` says how.

## B. Data source

- [ ] The logsource exists in our environment with the fields the rule uses, on the hosts
      that matter (servers vs. workstations vs. cloud).
- [ ] Field names in the rule are Sigma-taxonomy names, and the pipeline maps them for our
      backend. Conversion was run, not hand-written.
- [ ] Log retention covers the time window the rule (or its correlation) needs.
- [ ] Volume of the underlying event type is known; the rule will not time out or cost more
      than the alert is worth.
- [ ] Known telemetry gaps (hosts without Sysmon, unmanaged devices) are noted in the
      deployment record.

## C. Logic

- [ ] `sigma_lint.py` passes with zero errors. Warnings are either fixed or justified.
- [ ] No wildcard-only selections; no `contains` on a token an attacker can trivially drop
      or rename (`mimikatz`, `evil`, tool names) unless paired with a behavioural constraint.
- [ ] Every filter has a comment with reason, owner, and expiry.
- [ ] Case sensitivity is intentional (`|cased` where it matters, e.g. base64 blobs).
- [ ] Path matching uses `endswith` for binaries (`'\cmd.exe'`), not `contains: 'cmd'`.
- [ ] Regexes are anchored where possible and have been checked for catastrophic
      backtracking on long command lines.
- [ ] The condition is readable: parentheses present, filters named `filter_*`.
- [ ] Attacker-controlled strings (command lines, URLs, user agents) are treated as data
      in the rule and the alert; the rule does not assume they are well-formed.

## D. Tests

- [ ] A true-positive sample exists (real incident log, purple-team run, or a public
      emulation test referenced by name/ID) and the rule fires on it.
- [ ] A benign sample exists for the closest legitimate activity and the rule does not fire.
- [ ] Tests are stored with the rule (path or ticket linked in the deployment record).
- [ ] A backtest over the agreed window (default 30 days) was run and the numbers recorded:
      hits, distinct hosts, distinct users, top noisy values.

## E. Operational

- [ ] `level` matches the FP rate and impact, per the table in
      `false-positive-tuning.md`.
- [ ] The alert has a triage note: what the analyst should check first, what benign looks
      like, when to escalate. `incident-triage` consumes this.
- [ ] `fields` lists the columns that make the alert readable without a second query.
- [ ] Owner and review date are set (default: review `experimental` after 2 weeks, `test`
      after 30 days, `stable` every 6 months or when the data source changes).
- [ ] Rollback path is known (disable the rule, revert the commit).

## F. Safety

- [ ] The rule contains no secrets, internal hostnames that should not leave the team, or
      customer data in the samples.
- [ ] Any automated response attached to the alert goes through an approval gate
      (`soar-playbook-design`), especially for `high`/`critical` rules that are still
      `experimental`.

## Review outcome template

```markdown
**Rule:** <title> (<id>)
**Reviewer:** <name>  **Date:** <YYYY-MM-DD>
**Verdict:** approve | approve with changes | reject
**Findings:**
- B2: field `ProcessCommandLine` used directly; should be Sigma `CommandLine` (pipeline maps it)
- D2: no benign sample for the installer case in falsepositives
**Backtest (30d):** 42 hits / 6 hosts / 3 users; top value: `C:\Program Files\Backup\agent.exe` (31)
**Next status:** test, review again 2026-10-17
```
