# Environment customization (edit me)

Fill this in before your first exercise. The skill uses it to keep tests inside your
authorized scope, to make the SOC able to tell exercise from real, and to score against
your own targets.

## Emulation tooling and where it may run

| Project | How we run it | Authorized environment | Owner |
|---|---|---|---|
| Atomic Red Team | `Invoke-AtomicTest` from a controlled runner | lab domain `range.yourcompany.example`, tagged non-prod endpoints | `<team>` |
| MITRE CALDERA | server at `<internal-url>`, agents on lab hosts only | lab only | `<team>` |
| Stratus Red Team | CLI from `<jump-host>` with a scoped IAM role | dedicated purple-team AWS account `<account-id>` | `<team>` |
| Adversary emulation plans (ATT&CK Evals / CTID) | manual, operator-led, per the published plan | lab | `<team>` |

We reference tests by ID/name only in plans and tickets. Commands live in the source
projects, run by the authorized operator, never pasted into skill output or tickets.

## Standing scope and do-not-touch

| In scope by default | Out of scope (needs explicit written add) |
|---|---|
| Lab endpoints tagged `purple-lab`, the purple-team AWS account | Production servers, domain controllers, customer-data stores |
| Test user accounts `pt-user-*` | Real employee or admin accounts, break-glass accounts |
| Synthetic data only | Any real customer or employee data |

Hard do-not-touch: `<list DCs, crown-jewel systems, safety/OT systems, backup infrastructure>`.
Destructive techniques (impact, log deletion, shadow-copy removal, security-tool tampering)
run only on isolated throwaway hosts that can be rebuilt.

## Deconfliction (how the SOC tells exercise from real)

- Control group (people who know before the run): `<names/roles>`
- Deconfliction channel: `<#channel or bridge>`
- In-band signal so an analyst can verify: `<e.g. a known benign canary string in test file
  names / a specific source host range / a header value>` — kept from the wider SOC so the
  detections are tested honestly, but verifiable by the control group on request.
- Emergency "is this real?" contact: `<name/pager>`

## Targets and SLAs (feed the scorecard)

| Metric | Target | Scorecard flag |
|---|---|---|
| Technique detection coverage (alerted) | `<e.g. 70%>` | `technique_coverage_pct` |
| Technique visibility (alerted or logged) | `<e.g. 90%>` | `technique_visibility_pct` |
| Time-to-detect SLA | `<e.g. 30 min>` | `--ttd-sla 30` |
| Priority-1 techniques with a gap | 0 | top of the gap list |

## Platforms we run on

`<Windows 10/11, Server 2019/2022, macOS 14, Ubuntu 22.04, AWS, Azure, GCP>` — prune tests
that target platforms you do not run.

## Sign-off and abort authority

| Action | Who signs / who can call it |
|---|---|
| Approve an exercise plan and ROE | `<IR lead + platform owner + (for prod-adjacent) CISO delegate>` |
| Add an out-of-scope target | `<system owner + IR lead, in writing>` |
| Call abort | any of: the operator, the control-group lead, the on-call IR lead |
| Approve a destructive test | `<IR lead + system owner>` |

## Cadence

- Full exercise: `<quarterly>`; targeted validation after a new detection ships: `<per change>`.
- Always run with `--previous <last run CSV>` so progress and regressions are visible.
