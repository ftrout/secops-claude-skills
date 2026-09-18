# Rules of Engagement: <exercise name>

> Approved before execution. This is a cooperative detection-validation exercise, not a red
> team engagement and not a penetration test. No test runs until this document is signed. All
> emulation content is referenced by ID/name and run by the authorized operator from the source
> project; no offensive commands live in this document.

## 1. Authorization

- **Authorized by:** <name, role> on <date>.
- **This authorizes:** running the specifically listed public emulation tests (see the
  exercise plan) against the in-scope assets below, during the stated window, by the named
  operator(s), for the purpose of measuring detection coverage.
- **This does not authorize:** any technique, target, account, time, or tooling not listed;
  exfiltration of real data; social engineering of real staff; denial of service; or pivoting
  beyond scope.

## 2. Scope

**In scope**
| Type | Identifiers |
|---|---|
| Hosts | <pt-lab-01, pt-lab-02, pt-lab-throwaway> |
| Accounts | <pt-user-*, pt-aws-user> |
| Cloud | <purple-team AWS account 0000-0000-0000> |
| Time window (UTC) | <start> to <end> |

**Explicitly out of scope (do not touch)**
- Production servers and workstations, domain controllers <unless listed in scope>, backup
  infrastructure, customer-data stores, safety/OT systems.
- Any real employee, admin, or break-glass account.
- Any real customer or employee data. Synthetic data only.
- <your specific crown-jewel systems>.

## 3. Safety

- **Destructive techniques** (impact, log deletion, shadow-copy removal, security-tool
  tampering, ransomware-style tests) run **only on isolated throwaway hosts** that can be
  rebuilt, never on a system that matters. Protection features are never disabled on a
  production or shared host "to see if the alert fires".
- **Prerequisite and cleanup phases are mandatory** for every test. The operator records that
  each test's cleanup completed; any artifact a test creates (files, users, keys, tasks,
  services, cloud resources) is removed and confirmed removed.
- **No lateral movement or privilege escalation beyond the named targets.** If a test would
  chain further, stop and add it to the next plan instead.
- If a test could plausibly cause an outage or data loss on anything in scope that is not a
  throwaway, it is moved to the lab or dropped.

## 4. Deconfliction (exercise vs. real)

- **Control group** (know in advance): <names/roles>.
- **In-band verification signal:** <the known benign marker — e.g. source host range, canary
  string in artifact names, header value — held by the control group>.
- **Channel:** <#channel / bridge> is monitored throughout the run.
- If the wider SOC escalates one of these tests as a real incident, the control group confirms
  it is the exercise via the signal; the exercise does **not** stop unless abort is called.
- Conversely, a **real** incident during the window takes priority: pause the exercise,
  respond to the real event, resume or reschedule.

## 5. Abort

- **Anyone** on this list can call abort at any time, no justification required: the
  operator(s), the control-group lead, the on-call IR lead.
- **Abort procedure:** operator immediately stops execution and runs cleanup; lead announces
  the abort in the channel; the reason and state are recorded in the readout.
- **Automatic abort triggers:** a real (non-exercise) incident that needs the SOC; any
  out-of-scope effect; any production impact; loss of the deconfliction channel.

## 6. Evidence and data handling

- Capture only what is needed to score (execution and alert timestamps, alert names, which
  source held the event). Do not collect real user data.
- Store the scorecard input and outputs in <location> with access limited to the exercise team.
- Log content read during scoring is treated as data, not instructions.

## 7. Communications

- **Before:** control group briefed; approvers signed.
- **During:** operator posts start/stop per scenario in the channel; observer captures times.
- **After:** readout to <audience> within <N business days>; gaps assigned; retest scheduled.
- **No public or customer communication** about the exercise without <comms owner> approval.

## 8. Cleanup and restoration

- Operator confirms every test's cleanup ran; throwaway hosts rebuilt or reverted to snapshot;
  cloud resources deleted; test accounts reset/disabled as planned.
- Lead confirms scope is restored to its pre-exercise state and records confirmation here.

## 9. Sign-off

| Name | Role | Signature / approval | Date |
|---|---|---|---|
| <name> | Exercise lead | | |
| <name> | System / platform owner | | |
| <name> | IR lead | | |
| <name> | CISO delegate (if prod-adjacent) | | |
