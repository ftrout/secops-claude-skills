# Email header field reference for phishing analysis

Standards referenced: RFC 5321 (SMTP, 2008), RFC 5322 (message format, 2008), RFC 7208 (SPF,
2014), RFC 6376 (DKIM, 2011), RFC 7489 (DMARC, 2015; DMARCbis in progress as of 2026), RFC 8601
(Authentication-Results, 2019), RFC 8617 (ARC, 2019). Vendor header names are current as of
2026 and may change.

## Trust model in one paragraph

Headers are appended top-down as the message moves: each MTA adds its `Received` line (and
sometimes `Authentication-Results`) *above* everything it received. So the headers at the top
were written by servers closest to you and the headers at the bottom by the sender. Everything
below the first hop you control (your MX or gateway) could be written by the attacker,
including fake `Received`, fake `Authentication-Results`, fake `X-Originating-IP`, and fake
`Date`. Authentication and routing conclusions come only from headers your infrastructure
added.

## Identity headers

| Header | What it is | Who sets it | Forgeable | What to look for |
|---|---|---|---|---|
| `From` | RFC 5322 author; shown to the user | Sender | Yes (unless DMARC enforced) | Display name vs address, lookalike domain, multiple addresses, brand name in display name |
| `Sender` | Agent sending on behalf of From (mailing lists, delegates) | Sender | Yes | Mismatch with From is normal for lists/calendars, suspicious for personal mail |
| `Reply-To` | Where replies go | Sender | Yes | Different domain from From is the classic BEC/conversation-hijack tell |
| `Return-Path` | Envelope sender (SMTP MAIL FROM); where bounces go; the identity SPF checks | Your MTA writes it at final delivery | Not by sender once your MX writes it | Domain differs from From on bulk mailers (legit) and on spoofed mail (not) |
| `To` / `Cc` | Visible recipients | Sender | Yes | Reporter not in To/Cc means Bcc or undisclosed recipients: mass campaign |
| `Message-ID` | Unique ID, normally `<random@sending-host>` | Sending MUA/MTA | Yes | Domain part should match the sending system; missing or malformed IDs are a spam signal; the host part leaks the real platform (PHPMailer, hosting panel) |
| `In-Reply-To` / `References` | Threading | Sender | Yes | Present on a message that fails authentication suggests thread hijacking or a faked reply |
| `Date` | Sender's claimed time | Sender | Yes | Compare with first Received; large gaps mean queuing or a forged Date |
| `Subject` | Content | Sender | Yes | `RE:`/`FW:` prefixes without thread headers; urgency; invoice numbers |

## Routing headers

### `Received`

Format (RFC 5321 section 4.4): `from <helo-name> (<rdns> [<ip>]) by <receiving-host> with
<protocol> id <queue-id> for <recipient>; <date>`.

- Read **bottom to top** for chronology (the script reverses them for you).
- `from` name is what the client said in HELO/EHLO (attacker-controlled); the bracketed IP is
  what the receiving server saw (trustworthy *if* you trust that server); the parenthesized
  name is reverse DNS as resolved by the receiving server.
- `with` protocol values: `SMTP`, `ESMTP`, `ESMTPS` (TLS), `ESMTPA` (authenticated),
  `ESMTPSA` (TLS + authenticated), `HTTP`/`HTTPS` (webmail/API submission), `LMTP`, `MAPI`.
  An `A` means a login on that server sent it: the account is compromised or attacker-owned.
- Private IPs (10/8, 172.16/12, 192.168/16) in the first hops mean the message originated
  inside that organization's network (or a webmail/API submission behind it).
- Delay between hops is normal at seconds to a few minutes. Hours mean greylisting, retries,
  or a stale relay; negative values mean clock skew or a forged line.
- Microsoft 365 internal hops look like `from A.prod.outlook.com (2603:...) by B.prod.outlook.com
  with Microsoft SMTP Server`; the first external hop into Exchange Online is usually the
  `mail-*.protection.outlook.com` line.

### `X-Originating-IP`, `X-Sender-IP`, `X-Source-IP`

Client IP as recorded by the submission server (webmail/API). Useful when the sender used
Outlook Web/Gmail web; meaningless if the attacker wrote it. Exchange Online strips or rewrites
it for internal senders.

## Authentication headers

### `Authentication-Results` (RFC 8601)

`authserv-id; method=result [property=value ...] (comment); method=result ...`

- The `authserv-id` (first token) is the server that evaluated. Trust it only if it is yours;
  the script prints one row per header so you can see which server said what.
- **SPF** (`spf=`): evaluates the connecting IP against the **Return-Path** (MAIL FROM) domain,
  or HELO if MAIL FROM is empty. Results: `pass`, `fail` (`-all`), `softfail` (`~all`),
  `neutral` (`?all`), `none` (no record), `temperror`, `permerror` (broken record, often
  too many DNS lookups). Property `smtp.mailfrom=` is the domain checked.
- **DKIM** (`dkim=`): cryptographic signature over selected headers and body. Results: `pass`,
  `fail` (body/headers modified or bad key), `none`, `policy`, `neutral`, `temperror`,
  `permerror`. Properties: `header.d=` (signing domain), `header.s=` (selector), `header.i=`
  (agent/user identity), `header.b=` (first chars of signature, to match multiple signatures).
  A `pass` for `d=mailchimp.example` says Mailchimp signed it, not that the From is honest.
- **DMARC** (`dmarc=`): passes if SPF **or** DKIM passes **and** the passing identity's domain
  aligns with the From domain (relaxed: same organizational domain; strict: exact). Properties:
  `header.from=`, `action=` or `policy=` (`none`, `quarantine`, `reject`), sometimes
  `reason=`. `dmarc=none` means no policy published: the domain is spoofable and the mail
  may still be legitimate. `bestguesspass` (Microsoft) means no record but it would have passed.
- **ARC** (`arc=`): `pass` means an intermediary (forwarder, mailing list) sealed the original
  authentication results and the chain validates; used to rescue mail that legitimately broke
  SPF/DKIM in transit. Related headers: `ARC-Seal`, `ARC-Message-Signature`,
  `ARC-Authentication-Results` (instance number `i=`).
- **compauth** (Microsoft composite authentication): `pass`, `fail`, `softpass`, `none`, with a
  `reason=` code. `fail` means Microsoft's implicit authentication decided the sender is not
  who it claims even if SPF/DKIM technically passed; see Microsoft's "Anti-spam message
  headers" doc for the current reason codes.
- `iprev=`: reverse DNS check of the connecting IP.

### `Received-SPF`

Older, per-hop SPF result written by the receiving MTA: `Pass (…) client-ip=…;
envelope-from=…; helo=…`. Same trust rule: only the one your MX wrote counts.

### `DKIM-Signature`

Tags worth reading: `d=` signing domain, `s=` selector (look it up at
`<s>._domainkey.<d>` TXT to confirm the key exists), `h=` signed headers (a signature that
does not cover `From` or `Subject` is weak), `bh=` body hash, `t=` timestamp, `x=` expiry,
`i=` identity. `a=rsa-sha1` is deprecated. Multiple signatures are normal for mail that
transits an ESP.

## Vendor and platform headers (read, do not trust blindly)

| Header | Platform | Meaning |
|---|---|---|
| `X-MS-Exchange-Organization-AuthAs` | Exchange / M365 | `Internal` (authenticated org sender), `Anonymous` (arrived from outside), `Partner`, `External`. A From on your domain with `Anonymous` is a spoof or an unlisted third-party sender |
| `X-MS-Exchange-Organization-SCL` | M365 | Spam confidence level, -1 (bypassed) to 9 |
| `X-Forefront-Antispam-Report` | M365 | Semicolon list. `CIP:` connecting IP, `CTRY:` country, `SFV:` filter verdict (`SPM` spam, `NSPM` not spam, `SKN`/`SKI`/`SKB`/`SKA`/`SFE` skipped or overridden by a rule/allow/block list), `CAT:` category (`PHSH` phish, `HPHSH`/`HPHISH` high-confidence phish, `SPM`, `HSPM`, `MALW`, `BULK`, `SPOOF`, `DIMP` domain impersonation, `UIMP` user impersonation, `GIMP` mailbox-intelligence impersonation, `NONE`), `SCL:`, `PTR:` reverse DNS, `DIR:INB` inbound, `H:` HELO |
| `X-Microsoft-Antispam` | M365 | `BCL:` bulk complaint level and internal codes |
| `X-MS-Exchange-Transport-Rules-Loop`, `X-MS-Exchange-Organization-MessageDirectionality` | M365 | Transport rule and direction hints |
| `X-Google-DKIM-Signature`, `X-Gm-Message-State`, `X-Received` | Gmail / Workspace | Google's internal signing and receipt; `X-Received` shows the Google-internal hop |
| `X-Proofpoint-Virus-Version`, `X-Proofpoint-Spam-Details` | Proofpoint | Rule and score details; `urldefense.proofpoint.com/v2/url?u=` and `urldefense.com/v3/__…__;` are rewritten links |
| `X-Mimecast-Spam-Score`, `X-Mimecast-Originator` | Mimecast | Score; `protect-*.mimecast.com/s/` are rewritten links (decode in the console) |
| `X-Mailer`, `User-Agent` | Client | Sending software; PHPMailer/Sendinblue/Zoho on a "Microsoft" email is a tell; absence is normal for Outlook/Gmail web |
| `X-Priority`, `Importance`, `X-MSMail-Priority` | Client | High priority is a mild spam signal |
| `List-Unsubscribe`, `List-Id`, `Precedence: bulk` | Bulk mailers | Presence suggests marketing/graymail; absence on a "newsletter" is odd |
| `Auto-Submitted`, `X-Auto-Response-Suppress` | Automation | Auto-replies and notifications |
| `X-PHISHTEST`, `X-Gophish-*`, `X-KnowBe4-*`, vendor-specific | Simulation platforms | Check `environment.md` for the header your simulation vendor stamps |

## Lookalike and spoofing patterns seen in headers

- Display name spoofing: `"CEO Name" <random@gmail.com>` or `"it-support@yourcompany.example" <x@other.example>`.
- Lookalike From domains: typo, homoglyph (Unicode confusables, IDN `xn--`), combo-squat
  (`yourcompany-hr.example`), TLD swap (`.co`, `.cam`, `.support`), subdomain abuse
  (`yourcompany.example.attacker.example`).
- Exact-domain spoof: From is genuinely your domain; look for `AuthAs: Anonymous`, SPF fail,
  DMARC fail. Only possible when your DMARC is `p=none` or the receiving side does not enforce.
- Reply-To swap: legitimate-looking From (sometimes a compromised real account) with Reply-To
  on webmail or a lookalike.
- Compromised-account sends: everything authenticates because it *is* the real account.
  Tells are content, timing, Reply-To, new inbox rules on the sender side, and links.
- Header injection in `Subject`/`From` (newlines) from broken web forms: rare now, but a
  `From` with two addresses or an extra `To` is worth a note.
