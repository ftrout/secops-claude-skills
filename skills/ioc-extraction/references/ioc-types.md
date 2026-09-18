# Indicator types, noise checklist, and vocabularies

## Types emitted by the script

| Type | Notes |
|---|---|
| `url` | Full URL incl. scheme and path. Matches http(s), ftp, sftp, tftp, smb, ws(s). The host inside is **not** separately emitted as `domain`. |
| `email` | Lower-cased. Sender/reply-to/from addresses are indicators; victim mailboxes are not. |
| `sha512` / `sha256` / `sha1` / `md5` | Lower-cased. Length-based; JA3 (32 hex) collides with MD5, so check the surrounding text. |
| `cve` | Upper-cased. A CVE is a vulnerability reference, not a blockable indicator; route to the `vulnerability-triage` skill. |
| `ipv4` / `ipv6` | Private, loopback, link-local, multicast and reserved ranges dropped unless `--keep-private`. Version strings like `10.0.19041.1` are dropped when preceded by "version/build/v". |
| `domain` | Lower-cased. Filenames (`update.exe`) are rejected via an extension list. Well-known vendor/reference domains dropped unless `--keep-noise`. |
| `registry` | Keys and values under HKLM/HKCU/HKCR/HKU. Persistence artifacts for EDR hunts, not for blocking. |
| `windows_path` / `unix_path` | File system artifacts. Useful for EDR/Sysmon hunts. Highly environment-dependent; verify before use. |
| `btc` / `eth` | Ransom wallets. Useful for attribution and law-enforcement referrals. |
| `mac` | Rarely useful beyond internal investigations. |

## Noise checklist (remove before shipping)

Ask, for each candidate: "If I block or alert on this, will a legitimate user be affected?"

- The publishing vendor's own domains, blog, and CDN.
- Sandbox/analysis services (VirusTotal, ANY.RUN, Hybrid Analysis, urlscan) referenced as *sources*.
- Legitimate services abused for hosting (Discord CDN, GitHub, Dropbox, Google Drive, pastebin,
  ngrok, Cloudflare Workers). The **full URL or path** may be an indicator; the domain is not.
  Keep the URL, drop the domain, note the abuse pattern.
- Microsoft/Apple/Google update and telemetry hosts listed as "the malware checks connectivity to".
- Living-off-the-land binaries and admin tools (PsExec, AnyDesk, rclone, 7-Zip). Label as `tool`,
  do not add to blocklists without a discussion.
- Hashes of clean decoy documents or clean installers used in DLL side-loading. Keep them
  labelled `decoy`/`sideload-host` so hunters can pivot, but don't block.
- Test/RFC ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.*`.
- Anything inside a YARA/Sigma rule body: it is detection logic, not a raw IOC.

## Role vocabulary

Use these values consistently so downstream automation can key off them:
`c2`, `download`, `staging`, `phishing-sender`, `phishing-landing`, `exfil`, `dropped-file`,
`persistence`, `scanner`, `tool`, `decoy`, `sideload-host`, `wallet`, `unknown`.

## Confidence vocabulary

- `high`: directly attributed to the actor/campaign by the source with supporting evidence.
- `medium`: observed in the campaign but on shared infrastructure, or reported second-hand.
- `low`: mentioned without attribution, or derived from a single sighting.

## Shelf life (default `valid_until` suggestions)

| Type | Typical validity | Rationale |
|---|---|---|
| Cloud/VPS IP | 7 to 14 days | Rotated quickly; risk of hitting a new, legitimate tenant |
| Residential proxy IP | 1 to 3 days | Very high churn |
| Domain (actor-registered) | 90 days | Often parked then reused |
| Domain (compromised legit site) | 30 days | Owner usually cleans it up |
| URL path on legit service | 30 days | Content gets taken down |
| File hash | Indefinite | Exact-match; low FP risk, low recall |
| Email sender | 30 days | Accounts get suspended |
