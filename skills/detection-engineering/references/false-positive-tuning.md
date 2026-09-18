# False-positive tuning

A rule that fires 200 times a day on backup jobs is not "a noisy rule", it is a rule that
nobody reads. Tuning is the difference between a detection and a dashboard tile. The goal
is not zero false positives; it is a rate the responding team can sustain while still
catching the behaviour the rule was written for.

## 1. Measure before you touch anything

Run the rule's query over a representative window (7 to 30 days, longer for rare events)
and record:

| Metric | Why it matters |
|---|---|
| Total hits | Raw volume |
| Distinct hosts / users | 500 hits on 2 hosts is one problem; 500 hits on 400 hosts is a baseline |
| Hits per day (min/median/max) | Bursty rules hide inside daily averages |
| Top 10 values of the noisiest field | Usually one or two values explain 80% of hits |
| Share attributable to service accounts, admins, scanners, install windows | Points to the tuning lever |

Keep the numbers in the rule's deployment record; a year later "why is this filter here?"
is answered by the data, not by memory.

## 2. Classify the false positives

| Class | Example | Preferred lever |
|---|---|---|
| Known-good software | Backup agent spawns `vssadmin`, RMM tool runs encoded PowerShell | Filter on `ParentImage` or signer, not on the command string |
| Admin behaviour | Helpdesk runs `net user` from a jump host | Filter on the jump host / admin group, with an expiry |
| Scanner / security tooling | Vulnerability scanner touching many hosts | Filter on source host or account, keep the behaviour |
| Misconfiguration | A script that should not exist runs every hour | Fix the source; do not tune the rule around it |
| Broad logic | Rule matches on a substring that is common (`update`, `temp`) | Tighten the selection, add a second condition |
| Wrong data source | Rule assumes Sysmon fields but gets 4688 without command line | Fix logsource / pipeline; do not tune |
| Actual true positives you were not expecting | Red team, developer tooling that is genuinely risky | Escalate; not a tuning problem |

Tuning around a misconfiguration or a genuinely risky practice hides a problem that
should be fixed elsewhere. Say so in the ticket.

## 3. Tuning levers, safest first

1. **Tighten the positive selection.** Add a constraint the attacker cannot avoid (a
   process ancestry, a specific switch, a path). This raises precision without creating a
   hole. Ask: "could the adversary trivially change this?" If yes, it is a weak constraint.
2. **Add a narrow exclusion filter.** `filter_main_<what>` with the most specific fields
   available: full path plus signer, or parent path plus command line. Avoid excluding on a
   single wildcard-heavy field (`CommandLine|contains: 'backup'`) because an attacker who
   reads your rules (or guesses) can carry the token.
3. **Move the noisy population, not the rule.** Route service-account hits to a lower
   severity or a separate hunting output instead of dropping them.
4. **Add a threshold or correlation.** Rare-by-design behaviour on one host is a signal;
   the same event across all hosts at 02:00 is patching. Correlation rules (event count,
   value count, temporal) express this in Sigma v2.
5. **Lower the level.** If the behaviour is worth recording but not paging, `low` or
   `informational` keeps it available for correlation and hunts.
6. **Retire.** If the data source cannot distinguish good from bad, a rule that always
   needs manual context is a hunt, not a detection. Hand it to `threat-hunting`.

## 4. Exclusion hygiene

- Every filter gets a comment or a `description` line: what it excludes, why, ticket
  number, owner, expiry date. Unexplained filters are never removed and never trusted.
- Never exclude an entire user, host, or subnet without an expiry. Default expiry: 90 days,
  then re-measure.
- Prefer exclusions that name *legitimate* things (a signed binary, a known service
  account) over ones that name *attacker* things you are tired of seeing.
- Check that the exclusion does not also cover the true-positive sample from the unit
  test. Re-run the TP test after every tuning change.
- Do not fix FPs by editing the converted SPL/KQL. Edit the Sigma rule, re-lint, re-convert.

## 5. Sanity checks after tuning

- Re-run the true-positive and benign unit tests.
- Re-run the volume measurement. Record before/after in the deployment record.
- Confirm the new filter is not the whole story: if the filter removes 99% of hits, ask
  whether the rule's premise was wrong.
- Peer review the change with the rule-review checklist, even for "small" filters.

## 6. When to stop

Rough targets for a team that triages within a shift; adjust in `environment.md`:

| Level | Acceptable FP rate | Acceptable daily volume |
|---|---|---|
| critical | < 5% | < 3 |
| high | < 20% | < 10 |
| medium | < 50% | < 50 |
| low / informational | not paged | n/a |

If a `high` rule cannot get below 20% FP after two tuning rounds, it is probably a
`medium` rule, or a hunt.
