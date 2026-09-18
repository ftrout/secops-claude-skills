# Triage playbook: DLP alerts

Covers: endpoint DLP (USB, print, clipboard, upload), email DLP, cloud-app / CASB DLP
(sharing links, external shares, bulk downloads), and SaaS "mass download" or
"anomalous exfiltration" detections.

DLP triage is as much an HR and legal question as a security one. Establish facts, avoid
speculation about motive in the ticket, and involve the contacts named in `environment.md`
before contacting the user when insider risk is plausible.

## Questions to answer
1. What data was involved (classification, volume, record count, specific file names) and does the
   classifier match reality (false matches on test data, templates, or public documents are common)?
2. Which channel: removable media, personal email/webmail, cloud storage, print, share link, API?
3. Who is the user, what is their role, and is this within their job (sales exporting CRM vs. engineer uploading source)?
4. Was the transfer **completed**, blocked, or only attempted?
5. Are there context signals: resignation notice, access review, performance process, unusual hours?

## Data to pull
- The DLP event with matched rule, evidence snippet (handle as sensitive), file names, sizes, destination.
- The user's 30-day DLP history and baseline: is this a first event or a step change in volume?
- Cloud-app audit logs: downloads, share-link creations, external shares, sync-client activity.
- Endpoint logs: USB device IDs, file copy events, browser upload events, printer jobs.
- HR context only via the designated contact (departure date, role change), never by asking the user's manager casually.
- Whether the destination is a corporate-sanctioned tenant (a personal OneDrive and the corporate one look alike in logs).

## Benign explanation checklist
- [ ] Destination is a sanctioned corporate tenant, partner data room, or approved vendor with a DPA.
- [ ] Data is a template, public marketing material, or synthetic test data that trips the classifier.
- [ ] Job function requires it (auditor, legal export, finance close, sales quote), and volume matches history.
- [ ] Backup/sync client re-uploading after a device rebuild.
- [ ] Encrypted archive sent to a known counterparty via an approved process.

## True-positive indicators
- Personal webmail or consumer cloud destination; USB device never seen before on the fleet.
- Volume spike (10x baseline), bulk download of a repository or shared drive, then upload elsewhere.
- Files renamed or zipped before transfer; classification labels removed; archives with passwords.
- Activity in the days before a known departure, after an access-review denial, or during off-hours.
- Access to data outside the user's team scope followed by transfer.
- Share links set to "anyone with the link" on sensitive folders.

## Scoping questions
- What else did the user move in the last 30 to 90 days across all channels?
- Did the data include regulated categories (PII, PHI, PCI) that start notification clocks?
- Did anyone else receive or open the share links? Are they external?
- Is the data recoverable / revocable (share links can be revoked; USB copies cannot)?

## Escalation criteria
- Escalate immediately: regulated data confirmed leaving to an uncontrolled destination, or volume that
  suggests wholesale theft; loop in legal/privacy per `environment.md` before any user contact.
- Escalate the same shift: unexplained transfer to personal destination, even at low volume.
- Do not contact the user, revoke access, or disable the account without the approvals defined for
  insider-risk cases; premature contact destroys the evidence trail and can create employment-law exposure.

## Hand-offs
- Regulated data confirmed: `incident-report-writing` (regulatory notification checklist) and legal.
- Account compromise rather than insider (unfamiliar sign-in preceded the transfer): `identity-threat-investigation`.
- Cloud share auditing queries: `siem-query-authoring`.
