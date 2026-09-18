# Triage playbook: identity / sign-in alerts

Covers: impossible travel, unfamiliar location or device, MFA fatigue or MFA failures,
legacy authentication, password spray, risky sign-in from the IdP (Entra ID, Okta, Google),
new MFA method registered, and privilege escalation events.

## Questions to answer
1. Who is the user, what is their role, and what privileges do they hold (admin, finance, HR, service account)?
2. Did the sign-in **succeed**, and was MFA satisfied? How (push, number match, FIDO, SMS, none)?
3. Is the source (IP, ASN, country, device, user agent) consistent with this user's 30-day baseline?
4. What did the session do afterwards (mail rules, consent grants, file downloads, token issuance, admin actions)?
5. Is there a matching legitimate reason (travel, VPN egress change, new phone, remote-work location)?

## Data to pull
- IdP sign-in logs for the user, 7 to 30 days: result, IP, ASN, geo, device, app, auth method, risk detail.
- MFA registration and method-change events; password reset events; account property changes.
- Post-authentication activity: mailbox audit (inbox rules, forwarding), OAuth consent grants,
  SharePoint/Drive downloads, admin portal actions, token/refresh-token usage.
- Corporate VPN / SASE egress ranges and travel register (to explain a "new country").
- Device management state: is the device enrolled, compliant, and the user's usual one?
- Helpdesk tickets for the user in the last 48 hours (a reset request is a common precursor to fraud).

## Benign explanation checklist
- [ ] User confirmed by out-of-band contact (phone, in person, or a verified chat), not by email reply.
- [ ] Source IP belongs to corporate VPN, SASE/proxy egress, a known cloud provider the user works from, or mobile carrier CGNAT.
- [ ] Approved travel, or user's home region for remote staff.
- [ ] New device enrolled through the normal MDM process on the same day.
- [ ] "Impossible travel" caused by IP geolocation drift for a mobile carrier or VPN exit.
- [ ] Legacy auth from a known device that has not been migrated yet (still a hygiene finding).
- [ ] Failed sign-ins only, no success, from a noisy scanner range with many target users (spray, not compromise).

## True-positive indicators
- Successful sign-in from a residential proxy, hosting provider, or anonymizer after failures.
- MFA satisfied via a method registered minutes earlier, or many push denials followed by an approval.
- Session reuse from a new IP without a fresh MFA (token replay / AiTM pattern).
- Inbox rules created that delete or move mail matching "invoice", "password", "security", or move to RSS/Archive.
- New OAuth app consent with mail.read/files.read/offline_access from an unfamiliar publisher.
- Password changed, recovery methods changed, or admin role assigned shortly after the sign-in.
- Same source IP hitting multiple accounts; sign-ins outside the user's working hours with a new user agent.

## Scoping questions
- Which other accounts signed in from the same IP/ASN/device fingerprint in the last 7 days?
- Did the user's credentials appear in a recent phishing campaign or credential dump?
- Did the session touch shared mailboxes, admin portals, or CI/CD, cloud consoles?
- Is the user's account used by any automation or service that would break on reset?

## Escalation criteria
- Escalate immediately: successful sign-in with true-positive indicators on any privileged account,
  any post-auth persistence (mail rule, consent, MFA method), or evidence of AiTM.
- Escalate the same shift: successful anomalous sign-in, no persistence found yet, user not reachable.
- Containment (revoke sessions, reset password, disable) follows the order of operations in
  `identity-threat-investigation`; revoking sessions before resetting can leave a valid refresh token.

## Hand-offs
- Full compromise investigation and containment sequence: `identity-threat-investigation`.
- If the entry point was a phishing email: `phishing-analysis` for the lure and blast radius.
- Cloud console actions after sign-in: `cloud-incident-investigation`.
