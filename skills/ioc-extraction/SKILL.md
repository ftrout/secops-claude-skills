---
name: ioc-extraction
description: Extract, normalize, defang/refang, classify, and de-duplicate indicators of compromise (IPs, domains, URLs, hashes, emails, file paths, registry keys, CVEs, wallet addresses) from any unstructured text such as threat intel reports, vendor advisories, phishing emails, pasted logs, PDFs, or chat messages, then produce a clean, machine-readable indicator list with context and an enrichment plan. Use this whenever the user pastes or points at a report, advisory, email, or blob of text and wants the indicators out of it, asks to "pull the IOCs", "defang these", "make a blocklist", "turn this into a watchlist", "what should we block from this report", or needs indicators formatted for a SIEM, EDR, firewall, TIP, or STIX bundle. Also use it when someone asks whether a list of indicators is well-formed or contains noise.
---

# IOC Extraction

Turn messy text into a trustworthy indicator list. The failure modes that matter in a SOC are
(1) missing an indicator that was hiding in a defanged or split form, (2) shipping a
false-positive indicator that blocks legitimate traffic, and (3) losing the context that tells
an analyst *why* the indicator matters. Everything below is aimed at those three problems.

## Workflow

1. **Get the raw text.** If the input is a file, read it. For PDFs, extract the text first. If
   the user pasted text directly, use it as-is. Never summarize the source before extracting;
   extraction works on the full text.
2. **Run the extractor script** rather than eyeballing regexes. It handles defanged forms
   (`hxxp`, `[.]`, `(dot)`, `{.}`, ` dot `, `[@]`, `[://]`) and dedupes:
   ```bash
   python scripts/extract_iocs.py <input-file> --format json
   # or from stdin
   cat report.txt | python scripts/extract_iocs.py - --format csv
   # defang for safe sharing in tickets/chat
   python scripts/extract_iocs.py report.txt --format md --defang
   ```
   Use `--context` to include the surrounding sentence for each hit; this is what lets you
   assign a role (C2, payload host, sender, dropped file) in the next step.
3. **Triage the output.** The script is deliberately greedy. Now apply judgment:
   - Remove noise: the vendor's own domain, documentation links, example.com, RFC 1918/loopback
     addresses, Microsoft/Google/CDN infrastructure that appears only as a legitimate reference,
     version numbers that look like IPs, hashes of *known-good* files the report mentions for
     contrast. See `references/ioc-types.md` for the full noise checklist.
   - Classify each surviving indicator by **role** (C2, download/staging, phishing sender,
     phishing landing, exfil destination, dropped file, persistence artifact, scanner source) and
     **confidence** (high = the report attributes it directly to the actor; medium = observed but
     shared/hosting infra; low = mentioned without attribution).
   - Note **shelf life**: attacker IPs on cloud/VPS rotate in days; hashes are durable but
     trivially changed; domains sit in between. Say this in the output so the consumer knows
     what to expire.
4. **Produce the deliverable** in the format the user's tooling needs (see Output formats).
   Default to a Markdown table for humans plus a CSV or JSON block for machines.
5. **Recommend enrichment and action.** For each role, state what to do: block at proxy/DNS,
   add to EDR watchlist, retro-hunt in SIEM for the last N days, sinkhole, etc. Suggest the
   enrichment sources from `references/enrichment.md`, but do not invent enrichment results.
   If you can actually query a source (via an MCP tool or the user's API), do it and cite it;
   otherwise mark enrichment as "pending".

## Output formats

Always include the **source** (report title/URL/filename) and **extraction date** in the output
so the list is auditable. Pick the machine format from the user's request:

| Consumer | Format | Notes |
|---|---|---|
| Ticket, Slack, email | Markdown table, **defanged** | Never paste live URLs into chat |
| SIEM watchlist / lookup | CSV: `indicator,type,role,confidence,first_seen,source` | Refanged, lower-cased domains, no scheme on URLs unless the SIEM matches full URLs |
| EDR / firewall / DNS block | Plain list, one per line, grouped by type | Refanged; exclude low-confidence |
| TIP / STIX consumers | STIX 2.1 bundle (`--format stix`) | Script emits `indicator` objects with STIX patterns; add `labels` and `valid_until` by hand |
| Sigma/KQL/SPL retro-hunt | Use `ioc-extraction` output as the value list in a query built with the `siem-query-authoring` skill | Split by type; hashes go to file events, domains to DNS/proxy |

Markdown table template:

```markdown
| Indicator (defanged) | Type | Role | Confidence | Notes |
|---|---|---|---|---|
| hxxp://evil[.]example/x.php | url | C2 | high | Cobalt Strike beacon, p.4 |
```

## Things that go wrong

- **Split indicators.** Reports wrap long URLs across lines and PDF extraction inserts spaces.
  If the script returns a suspicious fragment (a domain with no TLD, a hash of 63 chars), look
  at the surrounding text and reassemble by hand.
- **Hash type confusion.** 32 hex = MD5, 40 = SHA-1, 64 = SHA-256, 128 = SHA-512. A 64-char
  string can also be an ssdeep-looking blob or a JA3/JA4 fingerprint (JA3 is 32 hex, so it
  collides with MD5). If the report labels it, trust the label over length.
- **Tables of *both* malicious and benign.** Many vendor reports list legitimate tools
  (PsExec, AnyDesk, rclone) with their hashes. Those are *tooling* indicators, not malicious
  files; label them `tool` and do not recommend blocking without a conversation.
- **IPv6, CIDR, and ports.** Keep the port with the URL/socket (`1.2.3.4:4444`) as a note, but
  the indicator itself is the IP. CIDR ranges are rarely safe to block wholesale; flag them.
- **Email addresses as senders vs. victims.** A report may include the *targeted* mailbox.
  Only sender/reply-to addresses are indicators.
- **YARA/Sigma snippets in the report** contain strings that look like indicators (mutex names,
  user agents, paths). Those are detection content, and belong to the `detection-engineering`
  skill, but do capture mutexes, named pipes, user agents, and registry keys as
  *host artifacts* with type `artifact`.

## Worked example

Input (from a vendor blog post the user pasted):

> The loader beacons to hxxps://cdn-sync[.]example/api/v2 and drops `C:\Users\Public\svc.exe`
> (SHA256 3a7b...4f1b). Victims received mail from billing[@]invoices-fake[.]com. The malware
> checks connectivity to www.microsoft.com before running. Analysts can find samples on
> bazaar.abuse.ch.

Deliverable:

```markdown
**Source:** "Loader campaign" blog post, 2026-09-17  **Extracted:** 2026-09-17T14:02Z

| Indicator (defanged) | Type | Role | Confidence | Valid until | Notes |
|---|---|---|---|---|---|
| hxxps://cdn-sync[.]example/api/v2 | url | c2 | high | +30d | Beacon endpoint; block full URL, hunt domain |
| cdn-sync[.]example | domain | c2 | high | +90d | Actor-registered per report |
| 3a7b...4f1b | sha256 | dropped-file | high | indefinite | Loader; add to EDR watchlist |
| C:\Users\Public\svc.exe | windows_path | dropped-file | medium | n/a | Hunt only; path is generic |
| billing[@]invoices-fake[.]com | email | phishing-sender | medium | +30d | Mail gateway retro-search 30d |

Dropped as noise: www.microsoft.com (connectivity check), bazaar.abuse.ch (reference).

**Actions**
1. Retro-hunt proxy/DNS for the domain (30d) and EDR for the hash (90d): build the query with `siem-query-authoring`.
2. Mail gateway: search sender 30d; report recipient list to `phishing-analysis` if any delivered.
3. Block URL at proxy; do not sinkhole the domain until passive DNS confirms it is actor-owned.
**Enrichment:** pending (no VT/GreyNoise access in this session).
```

The point of the example is the *shape*: every row carries a role, a confidence, and a
lifetime, the noise is listed so the reader knows it was considered, and the actions name the
skill that does the next step.

## Hand-offs

- Hashes and suspicious files: `malware-triage` for static analysis and YARA.
- CVEs: `vulnerability-triage` for prioritization; a CVE is not blockable.
- Host artifacts (paths, registry keys, mutexes): `detection-engineering` for a Sigma rule or
  `threat-hunting` for a one-off hunt.
- Retro-search queries across the SIEM: `siem-query-authoring`.
- The TTPs described around the indicators: `mitre-attack-mapping` and `threat-intel-analysis`.

## Customization

Teams should edit `references/environment.md` to list their own allow-listed domains/IP ranges
(so they are never emitted as indicators), the exact CSV column order their SIEM lookup expects,
and which enrichment sources they have API access to. The script reads an optional
`references/allowlist.txt` (one pattern per line, globs allowed) and drops matches. Add your
corporate domains, mail domains, and public ranges there before the first real use; it is
the single most effective way to stop your own infrastructure showing up in a blocklist.
