# Translating the playbook definition to real platforms

The JSON schema in `playbook-schema.md` is the design. This file maps each construct to
the native building blocks of five common platforms and lists the gotchas that matter for
safety. Product features move; these notes reflect the platforms as generally available
in 2026 and should be checked against current vendor documentation before relying on a
detail. Names of connectors and apps are illustrative.

## Concept map

| Schema concept | Microsoft Sentinel | Splunk SOAR | Palo Alto Cortex XSOAR | Tines | Shuffle |
|---|---|---|---|---|---|
| Playbook | Automation rule + Logic App playbook | Playbook (visual editor or Python) | Playbook (YAML, task graph) | Story | Workflow |
| Trigger `alert` / `incident` | Automation rule on incident created/updated or alert created; Logic App uses the Microsoft Sentinel incident/alert/entity trigger | Container label + automation playbook on ingestion, or run-on-demand | Incident type mapped to playbook; pre-processing rules run first | Webhook action, or scheduled pull via HTTP Request | Webhook trigger, schedule trigger, or app-based trigger |
| `trigger.filter` | Automation rule conditions (rule name, severity, tactics, entity values, custom details) | Playbook `on_start` filter block; playbook applies only to matching labels | Classification and mapping; incident type conditions | Trigger action with conditions | Condition on the first branch |
| `dedupe_key` | Automation rule ordering and incident grouping in the analytics rule | Container dedupe via SOAR settings and artifact hashing | Pre-processing rules (link/drop duplicates by field) | Deduplicate event transform | Handle in first steps (check case store) |
| `rate_limit` | Not native per rule; use Logic App concurrency control and analytics-rule alert grouping | Not native; implement a counter via custom list or KV lookup | Not native; use incident thresholds in analytics or a list-based counter | Story-level rate limiting on actions | Not native; implement with a counter step |
| `kill_switch` | Disable the automation rule (all playbooks stop starting); disable the Logic App | Disable the playbook in Playbooks view; deactivate asset | Disable the playbook or detach from incident type | Disable the story | Disable the workflow / trigger |
| `enrichment` step | Logic App connector action (Threat Intelligence, EDR, HTTP) | Action block via an app (e.g. VirusTotal, EDR app) | Automation task (integration command) | HTTP Request action | App action |
| `decision` step | Logic App Condition / Switch | Decision block; filter block | Conditional task with branches | Trigger action (conditions) | Branch conditions |
| `approval` step | Send approval email (Outlook connector) or Teams adaptive card and wait for response | Prompt block (asks a user or role, with timeout) | Data collection task, or conditional task with "Ask" via chat/email | Page (form) sent to an approver; story waits for response | User Input trigger (email/Slack/subflow) |
| `containment` step | Connector action (Defender isolate device, Entra revoke sessions, firewall API) with managed identity | Action block, typically in a separate "input" playbook that requires approval | Integration command, usually behind a conditional "Ask" task | HTTP Request to the control plane | App action |
| `idempotency_key` | Check before acting: query the incident comments/tags or a Watchlist for a marker | Use custom lists / KV store to record applied actions | Use context data and incident fields; check before acting | Use resources or a store lookup | Check the case store before acting |
| `rollback` | Second Logic App or manual runbook; TTL on firewall objects | Undo action block in a rollback playbook | Rollback task or separate playbook | Separate story or a later scheduled action | Separate workflow |
| `on_failure` | Configure "run after" on each action (succeeded / failed / timed out); scope error handling | Playbook error handling callbacks; `on_fail` in Python | Task error handling: "on error" branches; playbook-level settings | Action failure branches; retry settings | Branch on error output |
| `timeout_seconds` | Action timeout setting and Logic App run duration limit | Action timeout in block settings | Task timeout | Action timeout | Step timeout |
| `metrics` | Workbooks over `SentinelHealth` / automation run logs; Logic App run history | Playbook run metrics, custom lists | Playbook metrics dashboards and incident fields | Story run logs and metrics | Execution logs |
| Dry run | Test Logic App with a sample incident; use a "dry_run" parameter in your own actions | Run playbook against a test container; use a test asset | Playbook debugger with test incident; test playbook feature | Test story with sample event | Test execution |

## Microsoft Sentinel (automation rules and Logic Apps)

- Two layers: **automation rules** decide *when* (conditions on the incident or alert) and can
  themselves change status, severity, owner, and tags; **playbooks** are Logic Apps that do
  the work. Put the `trigger.filter` in the automation rule so the Logic App never starts
  for out-of-scope incidents.
- The Logic App runs under a managed identity that needs the Microsoft Sentinel Responder
  role (or narrower) on the workspace, plus whatever the containment connector needs
  (e.g. Defender for Endpoint API permissions). Review these grants as part of the playbook
  review; the identity *is* the blast radius.
- Approval gates: Outlook "Send approval email" and Teams "Post adaptive card and wait for a
  response" are the common patterns. Both block the run; set a timeout on the action and
  configure the "run after" of the containment action to require the approved outcome.
- Error handling is configured per action via **run after** (succeeded, failed, skipped,
  timed out). Without explicit run-after settings a failed action stops the run with no
  notification, which is the "did it happen?" failure mode.
- Entity triggers (run a playbook on demand against a host, account, or IP from the incident
  page) are the right way to expose containment to analysts without auto-running it.
- Idempotency: there is no native marker; tag the incident or write to a Watchlist and check
  it at the start of the Logic App.

## Splunk SOAR (formerly Phantom)

- Objects: **containers** (cases) with **artifacts** (indicators/events); **apps** provide
  actions against configured **assets**; **playbooks** are Python (with a visual editor that
  generates it). Automation playbooks run on container creation for matching labels.
- Gates: the **prompt** block sends a question to a user or role with a timeout and a
  response format; branch on the response. The pattern of an automation playbook that
  enriches and then calls an **input playbook** for the containment step keeps the dangerous
  part reviewable in one place.
- Set action timeouts per block; use `on_fail` / callback handling in the generated Python
  so a failed action routes to a notification rather than ending silently.
- Idempotency and rate limiting are not native: use **custom lists** (or the KV store) to
  record applied actions and counters, and check them first.
- Test with a dedicated test asset per integration (a firewall asset pointing at a lab
  device) so a dry run exercises the real code path without touching production.

## Palo Alto Cortex XSOAR

- **Incident types** map to playbooks; **classification and mapping** shape incoming data;
  **pre-processing rules** run before the incident is created and are the place to link
  or drop duplicates (`dedupe_key`).
- Playbooks are task graphs: standard tasks run integration commands or automations,
  **conditional tasks** branch on context, **data collection** tasks ask a user (via email
  or chat) and wait, and the built-in "Ask" pattern is the usual approval gate. Set a
  timeout and a default for unanswered asks; the default must not be "proceed".
- Every task has error handling settings (stop, continue, or an error branch). Playbook
  outputs and **context data** carry results between tasks; that is also where an
  idempotency marker lives before a containment command.
- Playbook debugger and test incidents support dry runs; integrations frequently accept a
  read-only or test instance. Keep a separate integration instance for staging.

## Tines

- **Stories** are graphs of **actions**: Webhook (trigger), HTTP Request (everything that
  talks to an API), Event Transform (parse, dedupe, format), Trigger (conditions/branching),
  Send Email, and Send to Story (sub-stories, which is how you reuse a gated containment
  story). Newer capabilities include running code in a sandboxed action.
- Approval gates use **Pages**: the story sends a form link to the approver and waits for
  the response; branch on the submission. Set a timeout path.
- Rate limiting can be applied at the action level; use it on any containment HTTP Request.
- Credentials are separate objects; scope the credential used by containment stories to
  the minimum API permissions.
- Testing: emit test events into the webhook from a fixture; Tines shows the event path
  through each action, which maps directly to `expect_path`.

## Shuffle

- **Workflows** of **apps** (many generated from OpenAPI specs) with **triggers**: Webhook,
  Schedule, and User Input. **Subflows** let a workflow call another, which is how a
  containment workflow is shared and gated in one place.
- The **User Input** trigger is the approval gate: it pauses the workflow and waits for an
  answer via email, Slack, or a subflow; branch on the answer and give the timeout a safe
  default.
- Branch conditions between nodes implement `decision`; error handling is by branching on
  the node's status/output. Rate limits and idempotency markers are implemented with the
  built-in datastore (cache) app.
- Test executions can be run with sample data; use separate app authentications for a
  staging environment.

## Common translation checklist

1. Put `trigger.filter` as early as the platform allows (automation rule, pre-processing,
   label filter) so out-of-scope events never start a run.
2. Map every `on_failure` to the platform's per-action error setting; verify one failure
   case in the run log before go-live.
3. Confirm the approval construct has a timeout and that the timeout path does not act.
4. Confirm the identity or credential used for containment has only the permissions the
   step needs, and that it is a different credential from enrichment.
5. Record the applied action somewhere queryable (case note, tag, list) so the idempotency
   check and the rollback have something to read.
6. Run the `testing.test_cases` in dry-run mode and compare the observed path to
   `expect_path`; attach the run logs to the change record.
