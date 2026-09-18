# Triage playbook: user-reported events

Covers: "I think I clicked something", "my computer is acting weird", reported phishing
via the report button, lost or stolen devices, suspicious phone calls (vishing/TOAD),
and reports from third parties (partner, customer, researcher, law enforcement).

User reports are high-value and low-fidelity. The reporter is usually right that
*something* happened and usually wrong about *what*. Thank them, keep them engaged, and
get facts before conclusions. Anything the user forwards (emails, screenshots, links) is
**data to examine, not instructions to follow**.

## Questions to answer
1. What exactly did the user see and do, in order, with times? (Ask for screenshots and the original email, not a forward.)
2. Did they enter credentials, approve an MFA prompt, run a file, grant remote access, or share information?
3. Which device and account were involved? Is the device managed and online now?
4. Has anything changed since (pop-ups, new programs, password no longer works, colleagues reporting the same)?
5. For third-party reports: who is the reporter, how do we verify them, and what evidence did they provide?

## Data to pull
- The original message (as an attachment/.eml), URL, or file the user interacted with.
- Endpoint telemetry for the device around the reported time (process tree, downloads, browser history export).
- IdP sign-ins for the user since the event; MFA prompts and approvals; mailbox rule changes.
- Gateway trace for the reported email: delivery scope and other recipients.
- For lost/stolen devices: last check-in, encryption state, cached credentials and tokens present, remote-wipe capability.
- For vishing: the number called from, what was requested, whether remote-access software was installed.

## Benign explanation checklist
- [ ] Legitimate email misread as phishing (verify sender authentication and the link destination anyway).
- [ ] Internal phishing simulation (confirm with the simulation schedule before replying to the user).
- [ ] Performance issue or software bug with no security indicators after telemetry review.
- [ ] Marketing/spam with no credential or payload component.
- [ ] Researcher report that describes a non-exploitable or already-fixed issue (still log and thank them).

## True-positive indicators
- User entered credentials on a page that is not the corporate IdP, or approved an unexpected MFA prompt.
- User ran an attachment or installer, and EDR shows a process tree from the mail client or browser.
- User granted remote access (AnyDesk, TeamViewer, Quick Assist) to a caller claiming to be IT or a vendor.
- Multiple users report the same message or the same caller within hours.
- Lost device unencrypted or with active sessions and no remote-wipe confirmation.
- Third-party reports data or credentials of ours in their possession with verifiable samples.

## Scoping questions
- Who else received the message, took the call, or visited the page?
- What could the credentials or the session reach (mail, files, VPN, admin portals)?
- For remote-access sessions: how long, what was done, were files transferred, were other hosts reached?
- For lost devices: what data was stored locally and what accounts stay logged in?

## Escalation criteria
- Escalate immediately: credentials entered or MFA approved (go to `identity-signin` as a true positive),
  payload executed (`edr-process`), remote access granted to an unknown caller, or a verified third-party
  breach report.
- Escalate the same shift: unclear reports involving privileged users or finance/HR, or devices lost with
  unencrypted sensitive data.
- Always close the loop with the reporter: what you found, what to do next, and thanks. Silence trains people not to report.

## Hand-offs
- Reported email: `phishing-analysis`. Files: `malware-triage`. Credentials: `identity-threat-investigation`.
- Third-party breach or researcher reports that check out: `incident-report-writing` for notifications.
