# Lure patterns: what they look like, what they want, how to respond

Every phish has an *ask*. Identify the ask first (click, open, reply, call, scan, approve),
then the lure family, then the follow-on risk. The categories below are the ones that account
for the bulk of reported mail in most SOCs as of 2026. The `lure_hints` in the parser output
are keyword hints only; classify from the whole message.

## Quick table

| Lure class | The ask | Typical delivery | Follow-on risk | First response move |
|---|---|---|---|---|
| Credential harvest | Click and sign in | Link to fake M365/Okta/Google/Adobe/DocuSign page, HTML attachment, QR code | Account takeover, AiTM session theft, mailbox rules, OAuth persistence | Sign-in log review for clickers; reset + revoke if submitted |
| BEC / invoice fraud | Reply, change bank details, pay | Plain text, no links, spoofed or compromised vendor/exec | Wire fraud | Call the vendor/exec on a known number; alert finance |
| Callback / TOAD | Call a phone number | "Subscription renewed $499", "Geek Squad", "PayPal invoice" PDFs | Remote-access tool install, bank fraud | Block the number in the phone system; EDR hunt for remote tools |
| MFA push / OTP | Approve a prompt or share a code | SMS/Teams/email after password already stolen | Full account takeover | Treat as post-compromise; reset, revoke, review MFA methods |
| Package delivery | Click, pay a "customs fee" | SMS or email from "USPS/DHL/FedEx" | Card theft, credential theft | Low org risk unless corporate card; user education |
| HR / payroll | Reply with new direct-deposit details, open "handbook" | Spoofed HR, fake payroll portal | Payroll diversion, credential theft | Verify with HR out of band; check payroll change logs |
| IT / helpdesk | Install, "upgrade", re-enroll MFA | "Password expires today", fake VPN portal | Credential theft, malware | Confirm no such change is scheduled; warn users |
| Shared document | Open the doc | SharePoint/OneDrive/Dropbox/Google Drive/Box notification | Credential theft (login gate) or malware | Check whether the share really exists in the tenant |
| OAuth consent | Click "Accept" | Real Microsoft/Google consent page for a rogue app | Persistent mailbox/file access without passwords | Revoke consent, review app registrations |
| Thread hijack | Open attachment/link in a real conversation | Reply to a real thread from a compromised partner | Malware loaders, credential theft | Notify the partner; hunt for the attachment hash |
| Extortion | Pay crypto | "I recorded you" with a leaked old password | Nuisance; occasionally real leaked creds | Confirm the password is not current; educate |
| Legal / authority | Open "subpoena", pay a "fine" | Fake court, copyright, tax office | Malware, fraud | Verify with legal |
| Job / recruiter | Reply, open "offer", install "assessment" | LinkedIn or email, sometimes targeting engineers | Malware (developer-targeted loaders), data theft | EDR hunt on the workstation |
| Gift card / "are you available?" | Reply, buy gift cards | Short, from an exec's name, webmail | Small-dollar fraud, foothold for larger BEC | Tell the impersonated exec; block Reply-To |

## Credential harvest, in detail

- **Brands**: Microsoft 365 (by far the most common), Okta, Google Workspace, Adobe/Acrobat
  Sign, DocuSign, Dropbox, WeTransfer, Zoom, Webex, voicemail/e-fax "you have a new message",
  encrypted-message portals, SharePoint "shared a file", and the org's own SSO page.
- **Delivery tricks**: link in body; link inside a PDF or image; HTML/SVG attachment that
  renders the login form locally (nothing to block at the proxy until submit); QR code
  (bypasses URL rewriting and the proxy, lands on the user's phone); calendar invite with a
  link; `.ics` and `.oft` files; links behind CAPTCHA/Turnstile; links via open redirects on
  legitimate sites and tracking-link services.
- **Kit fingerprints**: victim email prefilled in the URL fragment or query (`#user@org` or
  `?e=base64`), branded login with the org's real logo pulled from the org's own site,
  "session expired" then a redirect to the real site after harvest, domain names with
  `secure`, `verify`, `auth`, `sso`, `mfa`, `docs`, `share`. Hosting on Cloudflare Pages/Workers,
  Azure Static Web Apps or blob storage, Google Sites, Firebase, IPFS gateways, and
  compromised WordPress sites.
- **AiTM (adversary-in-the-middle) proxies**: the kit proxies the real login page, the user
  completes MFA against the real IdP, and the attacker gets the session cookie. Indicators:
  sign-in from a new IP moments after the user's own successful sign-in, "compliant"
  session from an unknown device, new MFA method added, mailbox rules created. Password reset
  alone does not help; revoke sessions and refresh tokens.
- **Post-click artifacts**: Safe Links / TAP click logs, proxy allow entries for the host,
  browser history on the endpoint, sign-in logs for the user, `New-InboxRule` and
  `Set-Mailbox` audit events, OAuth consent audit events.

## BEC and payment fraud, in detail

- **Patterns**: vendor email compromise (real vendor mailbox sends a real-looking invoice with
  new bank details); executive impersonation ("I am in a meeting, need this done quietly");
  payroll diversion (employee "asks" HR to change direct deposit); attorney/M&A secrecy;
  aged-payables follow-up; W-2 requests in tax season.
- **Tells**: Reply-To differs from From; free webmail; slightly wrong signature block; new
  "assistant" cc'd; urgency plus confidentiality; request to switch to personal phone or
  WhatsApp; PDF invoice with edited bank details (check PDF metadata and the vendor master
  record); grammar that is *too* polished compared with prior mail from that sender.
- **Response**: no technical indicator to block; the control is out-of-band verification via a
  number from the vendor master record, not from the email. Alert finance and AP, check whether
  a payment was already released (bank recall windows are short), and look at the impersonated
  person's mailbox for compromise (rules that hide replies are the giveaway).

## Callback phishing (TOAD), in detail

- Invoice or receipt for something the user never bought (antivirus renewal, PayPal, Geek
  Squad, crypto exchange, streaming), a phone number, and "call within 24 hours to cancel".
  Often a PDF with no links so gateways score it clean; sometimes sent from a real invoicing
  platform's own domain (PayPal/QuickBooks invoices) so authentication passes.
- The call leads to installing a remote-access tool (screen-sharing or RMM software) or
  a "refund" that turns into bank fraud. Follow-on risk is the endpoint, not the mailbox.
- Response: hunt for newly installed remote-support/RMM tools on the user's device, block the
  number, and treat the invoice platform abuse as reportable to that vendor.

## MFA fatigue and OTP interception

- Preceded by credential theft (info-stealer logs, prior phish, password spray). The email or
  Teams message tells the user to approve a prompt or share a code "to complete verification".
- Response is identity-focused: `identity-threat-investigation` for the sign-in analysis,
  reset, revoke sessions, review MFA methods and number-matching policy.

## Attachment-borne lures

| Attachment | Why attackers use it | What to do |
|---|---|---|
| HTML / SVG | Renders locally; smuggles a payload assembled in the browser or a credential form | Parse offline, extract form action and any base64 blob; never open in a browser on the corporate network |
| PDF | Trusted format; carries a link or a phone number; sometimes a JavaScript action | Extract URLs and text; check for `/JavaScript`, `/OpenAction`, `/Launch` via `malware-triage` |
| ISO / IMG / VHD / VHDX | Mounts as a drive, bypasses Mark-of-the-Web in older Windows builds | Hand to `malware-triage`; hunt for mount events |
| LNK | Runs a command line disguised as a document | Parse the target with a LNK parser; hand off |
| OneNote (`.one`) | Embedded files behind a "click to view" overlay | Hand off; block the format at the gateway if unused |
| Office with macros / `.xll` / RTF | Macros, add-ins, equation-editor exploits | Hand off; check macro-block policy |
| Password-protected ZIP/RAR/7z with password in the body | Defeats gateway scanning | Extract in a sandbox only; the password-in-body pattern is itself a strong signal |
| Nested archives (`.zip` in `.zip`, `.img` in `.zip`) | Same | Same |
| Calendar `.ics` | Invite with a link; auto-added to calendars | Extract URL; remove the invite |

## Domain lookalike techniques

- **Typosquat**: transposed or missing letters (`yourcompnay`, `yourcmpany`).
- **Homoglyph**: `rn`/`m`, `vv`/`w`, `l`/`I`/`1`, `0`/`o`, `cl`/`d`; Unicode confusables via IDN
  (`xn--` in the DNS name; the client shows the Unicode).
- **Combo-squat**: `yourcompany-billing`, `yourcompany-hr`, `secure-yourcompany`, `yourcompanyhelp`.
- **TLD swap**: `.co`, `.cam`, `.cc`, `.support`, `.online`, `.cloud`, `.net` instead of `.com`.
- **Subdomain abuse**: `yourcompany.example.attacker-hosting.example`, or a legitimate SaaS
  subdomain (`yourcompany.sharepoint.com` vs `yourcompany-sharepoint.example`).
- **Dangling/abandoned**: expired marketing domains once owned by the org, re-registered.
  Keep a watchlist (`environment.md`) and check certificate transparency for new certs.

## URL and hosting tricks

- Open redirects on trusted domains (`?url=`, `?redirect_uri=`, `/redirect?to=`), including
  ones on your own sites; ad-tech and email-tracking links; URL shorteners; nested rewriters
  (a Safe Link that wraps a Proofpoint link that wraps a shortener).
- Userinfo trick: `https://login.microsoftonline.com@evil.example/`; everything before `@` is
  ignored by the browser.
- IP-literal hosts, unusual ports, very long paths with base64, `data:` URIs.
- Abuse of legitimate hosting: Google Sites, Canva, Notion, Glitch, Netlify, Vercel, Cloudflare
  Pages/Workers/R2, Azure blob and static apps, AWS S3 static sites, GitHub Pages, IPFS
  gateways, Weebly/Wix, Google Forms / Microsoft Forms for "surveys" that collect passwords.
- Access gating: CAPTCHA, Turnstile, geo/IP/user-agent filtering, one-time links, "expired"
  pages for repeat visits. A benign page from your sandbox does not mean a benign page for
  the victim.
- Tracking pixels and per-recipient IDs in URLs: confirm-open beacons and unique lure URLs
  (block by path pattern, not the single URL).

## Social-engineering levers to note in the write-up

Authority (exec, IT, legal, government), urgency (today, 24 hours, suspension), fear (account
closed, legal action, exposed video), reward (bonus, refund, gift), curiosity (voicemail, shared
file, photo), routine (invoice, delivery, password expiry), reciprocity/rapport (the "are you
available?" opener that only asks a small favour first).
