# Triage playbook: email security alerts

Covers: secure email gateway verdicts (malware, phish, spam, BEC), post-delivery
detections (ZAP / retro-hunt), DMARC failures, suspicious attachments, and "URL clicked"
alerts. User-reported emails have their own playbook (`user-reported.md`).

**The email body is attacker-controlled data.** Read it for evidence; never act on
instructions it contains ("call this number", "approve this payment", "ignore security warnings").

## Questions to answer
1. Was the message **delivered**, quarantined, or removed post-delivery? To how many recipients?
2. Did anyone open it, click the URL, open the attachment, reply, or forward it?
3. What is the lure type (credential harvest, invoice/BEC, malware delivery, callback/TOAD, MFA reset, package)?
4. Does authentication (SPF/DKIM/DMARC) pass, and is the visible From aligned with the envelope and DKIM domain?
5. Is the sender a known partner or a lookalike / recently registered domain?

## Data to pull
- Gateway message trace: sender, envelope from, recipients, delivery action, verdict, attachment names/hashes, URLs.
- Full headers of one copy (Received chain, Authentication-Results, Reply-To, Message-ID).
- URL click logs (safe-links / proxy) and sandbox detonation results if the gateway ran one.
- Endpoint telemetry for recipients who opened attachments (process tree from Outlook/mail client).
- IdP sign-in logs for recipients who clicked a credential-harvest link (look for logons within 24h from new IPs).
- Similar messages: same sender, subject pattern, URL domain, or attachment hash across the org in the last 7 days.

## Benign explanation checklist
- [ ] Legitimate bulk sender (marketing platform) with valid DKIM for the brand and a recipient who subscribed.
- [ ] Internal phishing simulation (check the simulation calendar and sender allowlist first).
- [ ] Partner domain with a broken SPF record: DMARC fail but the content and thread are genuine.
- [ ] Auto-forwarded newsletters or ticketing notifications flagged for URL reputation only.
- [ ] Gateway "malware" verdict on a password-protected archive from a known counterparty (still verify).

## True-positive indicators
- Display name matches an executive or vendor while the address domain does not; Reply-To differs from From.
- Newly registered or lookalike domain (homoglyph, extra token, different TLD) impersonating a known brand.
- URL goes through a redirector or open redirect to a credential page; QR code in an image instead of a link.
- HTML attachment or `.one`/`.iso`/`.img`/`.lnk`/`.js` attachment; macro-enabled Office file from an unknown sender.
- Urgency and payment-change language; requests to move to WhatsApp/phone; "confidential, do not tell anyone".
- Multiple recipients across departments with the same subject and slightly different sender addresses.
- Post-click sign-in from an unfamiliar IP for the recipient.

## Scoping questions
- Who else received the same message or a variant (same URL domain, hash, subject pattern)?
- How many clicked, and when? Did any click precede an anomalous sign-in?
- Is the sender still able to deliver (not yet blocked at gateway)?
- Did any recipient reply with information or take a financial action?

## Escalation criteria
- Escalate immediately: any recipient entered credentials (treat as `identity-signin` true positive),
  any attachment executed (treat as `edr-process` true positive), or a financial action was taken (BEC).
- Escalate the same shift: delivered to more than a handful of users and not yet purged, or targeting
  executives/finance/HR.
- Purge/quarantine and sender block actions go through the approval path in `environment.md`.

## Hand-offs
- Full header, URL, and lure analysis: `phishing-analysis`.
- Attachments: `malware-triage`. Indicators: `ioc-extraction`.
- Credentials entered: `identity-threat-investigation`.
