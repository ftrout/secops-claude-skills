#!/usr/bin/env python3
"""Extract indicators of compromise from unstructured text.

Standard library only. Handles common defanging conventions, de-duplicates,
classifies by type, optionally drops allow-listed values, and emits JSON, CSV,
Markdown, a plain list, or a STIX 2.1 bundle.

Usage:
    python extract_iocs.py report.txt --format json
    cat report.txt | python extract_iocs.py - --format csv --context
    python extract_iocs.py report.txt --format md --defang
    python extract_iocs.py report.txt --types ipv4,domain,sha256 --format list

Exit code 0 on success, 2 on bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- refang

_REFANG_RULES = [
    (re.compile(r"\bhxxps?://", re.I), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\bfxp://", re.I), "ftp://"),
    (re.compile(r"\[://\]|\(://\)|\{://\}"), "://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.I), "."),
    (re.compile(r"(?<=\w)\s+dot\s+(?=\w)", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[:\]|\(:\)"), ":"),
]


def refang(text: str) -> str:
    """Reverse common defanging so regexes see the real indicator."""
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    """Make a network indicator safe to paste into chat or tickets."""
    if ioc_type == "url":
        value = re.sub(r"^http", "hxxp", value, flags=re.I)
        value = value.replace("://", "[://]", 1)
        return value.replace(".", "[.]")
    if ioc_type in {"ipv4", "domain"}:
        return value.replace(".", "[.]")
    if ioc_type == "ipv6":
        return value.replace(":", "[:]")
    if ioc_type == "email":
        local, _, dom = value.rpartition("@")
        return f"{local}[@]{dom.replace('.', '[.]')}"
    return value


# --------------------------------------------------------------------------- patterns

# Ordered: URLs first so their components are not double-counted as domains/IPs.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("url", re.compile(r"\b(?:https?|ftp|sftp|tftp|smb|wss?)://[^\s'\"<>()\[\]{}|\\^`]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("sha512", re.compile(r"\b[a-fA-F0-9]{128}\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("ipv6", re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")),
    ("domain", re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"(?:[a-z]{2,24}|xn--[a-z0-9]{2,59})\b", re.I)),
    ("registry", re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)"
        r"\\[^\s\"'<>|]+", re.I)),
    ("windows_path", re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]*")),
    ("unix_path", re.compile(r"(?<![\w.])/(?:etc|tmp|var|usr|opt|home|root|dev|bin|sbin|lib|proc)/[^\s\"'<>|)]+")),
    ("btc", re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("mac", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
]

# Extensions that are commonly mistaken for TLDs when a filename is matched by the domain regex.
FILE_EXT_NOT_TLD = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta", "scr", "lnk",
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "txt", "log",
    "zip", "rar", "7z", "gz", "tar", "iso", "img", "vhd", "msi", "jar", "py", "sh", "php",
    "asp", "aspx", "jsp", "html", "htm", "xml", "json", "yml", "yaml", "ini", "cfg", "conf",
    "dat", "bin", "tmp", "db", "sqlite", "csv", "png", "jpg", "jpeg", "gif", "bmp", "svg",
    "ico", "mp3", "mp4", "avi", "mov", "wav", "so", "dylib", "elf", "class", "apk", "ipa",
    "dmg", "pkg", "deb", "rpm", "cab", "ocx", "cpl", "drv", "pyc", "pyd", "ts", "tsx", "jsx",
    "md", "pem", "key", "crt", "cer", "p12", "pfx", "der", "ps", "bak", "old", "sql",
}

DEFAULT_NOISE_DOMAINS = {
    "example.com", "example.net", "example.org", "localhost.localdomain", "schemas.microsoft.com",
    "www.w3.org", "schema.org", "mitre.org", "attack.mitre.org", "cve.mitre.org", "nvd.nist.gov",
    "virustotal.com", "www.virustotal.com", "github.com", "raw.githubusercontent.com",
    "microsoft.com", "www.microsoft.com", "learn.microsoft.com", "docs.microsoft.com",
    "support.microsoft.com", "google.com", "www.google.com", "apple.com", "www.apple.com",
    "twitter.com", "x.com", "linkedin.com", "www.linkedin.com", "youtube.com", "wikipedia.org",
    "en.wikipedia.org", "sigmahq.io", "github.io", "urlhaus.abuse.ch", "bazaar.abuse.ch",
    "threatfox.abuse.ch", "otx.alienvault.com", "shodan.io", "censys.io", "any.run", "app.any.run",
    "tria.ge", "hybrid-analysis.com", "www.hybrid-analysis.com", "malwarebazaar.com",
}


# --------------------------------------------------------------------------- helpers

def _load_allowlist(path: Path | None) -> list[str]:
    if path and path.is_file():
        return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and not ln.startswith("#")]
    return []


def _allowed(value: str, allowlist: list[str]) -> bool:
    v = value.lower()
    return any(fnmatch.fnmatch(v, pat.lower()) for pat in allowlist)


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


def _looks_like_version(text: str, start: int) -> bool:
    """'version 10.0.19041.1' or 'build 6.1.7601.0' should not become an IP."""
    window = text[max(0, start - 12):start].lower()
    return any(w in window for w in ("version", "ver ", "build", "release", " v"))


def _sentence(text: str, start: int, end: int, width: int = 80) -> str:
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    snippet = text[lo:hi].replace("\n", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    v = value.replace("\\", "\\\\").replace("'", "\\'")
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "sha512": f"[file:hashes.'SHA-512' = '{v}']",
        "windows_path": f"[file:name = '{v}']",
        "unix_path": f"[file:name = '{v}']",
        "registry": f"[windows-registry-key:key = '{v}']",
        "mac": f"[mac-addr:value = '{v}']",
    }.get(ioc_type)


# --------------------------------------------------------------------------- core

def extract(text: str, *, types: set[str] | None = None, allowlist: list[str] | None = None,
            keep_private: bool = False, keep_noise: bool = False, with_context: bool = False) -> list[dict]:
    text = refang(text)
    allowlist = allowlist or []
    seen: dict[tuple[str, str], dict] = {}
    consumed: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < ce and e > cs for cs, ce in consumed)

    for ioc_type, pattern in PATTERNS:
        if types and ioc_type not in types:
            continue
        for m in pattern.finditer(text):
            s, _ = m.span()
            value = m.group(0).rstrip(".,;:'\")]}>")  # strip glued punctuation
            e = s + len(value)
            if not value or overlaps(s, e):
                continue

            if ioc_type in {"md5", "sha1", "sha256", "sha512"}:
                value = value.lower()
                if len(set(value)) < 4:  # 000000... padding, not a hash
                    continue
            elif ioc_type == "domain":
                value = value.lower()
                tld = value.rsplit(".", 1)[-1]
                if tld in FILE_EXT_NOT_TLD:
                    continue
                if not keep_noise and value in DEFAULT_NOISE_DOMAINS:
                    continue
            elif ioc_type == "url":
                host = re.sub(r"^[a-z]+://", "", value, flags=re.I)
                host = host.split("/")[0].split("@")[-1].split(":")[0].lower()
                if not keep_noise and host in DEFAULT_NOISE_DOMAINS:
                    continue
            elif ioc_type == "ipv4":
                if _looks_like_version(text, s):
                    continue
                if not keep_private and _is_private_ip(value):
                    continue
            elif ioc_type == "ipv6":
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                if not keep_private and _is_private_ip(value):
                    continue
            elif ioc_type == "email":
                value = value.lower()
                if not keep_noise and value.rsplit("@", 1)[-1] in DEFAULT_NOISE_DOMAINS:
                    continue
            elif ioc_type == "cve":
                value = value.upper()
            elif ioc_type == "windows_path":
                if len(value) < 6:
                    continue
            elif ioc_type == "btc":
                if value.isalpha() or value.isdigit():  # base58-looking words, not wallets
                    continue

            if _allowed(value, allowlist):
                continue

            consumed.append((s, e))
            key = (ioc_type, value)
            if key in seen:
                seen[key]["count"] += 1
                continue
            rec = {"indicator": value, "type": ioc_type, "count": 1}
            if with_context:
                rec["context"] = _sentence(text, s, e)
            seen[key] = rec

    order = {t: i for i, (t, _) in enumerate(PATTERNS)}
    return sorted(seen.values(), key=lambda r: (order[r["type"]], r["indicator"]))


# --------------------------------------------------------------------------- output

def render(records: list[dict], fmt: str, *, do_defang: bool, source: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    shown = [dict(r, indicator=defang(r["indicator"], r["type"]) if do_defang else r["indicator"])
             for r in records]

    if fmt == "json":
        return json.dumps({"source": source, "extracted_at": now, "count": len(shown),
                           "indicators": shown}, indent=2)

    if fmt == "csv":
        buf = io.StringIO()
        fields = ["indicator", "type", "role", "confidence", "first_seen", "source"]
        if any("context" in r for r in shown):
            fields.append("context")
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in shown:
            row = {"role": "", "confidence": "", "first_seen": now[:10], "source": source}
            row.update(r)
            w.writerow(row)
        return buf.getvalue()

    if fmt == "list":
        lines: list[str] = []
        cur = None
        for r in shown:
            if r["type"] != cur:
                cur = r["type"]
                lines.append(f"# {cur}")
            lines.append(r["indicator"])
        return "\n".join(lines)

    if fmt == "md":
        has_ctx = any("context" in r for r in shown)
        hdr = "| Indicator | Type | Count | Role | Confidence |" + (" Context |" if has_ctx else "")
        sep = "|---|---|---|---|---|" + ("---|" if has_ctx else "")
        rows = [f"**Source:** {source}  \n**Extracted:** {now}  \n**Indicators:** {len(shown)}\n", hdr, sep]
        for r in shown:
            row = f"| `{r['indicator']}` | {r['type']} | {r['count']} |  |  |"
            if has_ctx:
                ctx = r.get("context", "").replace("|", "\\|")
                row += f" {ctx} |"
            rows.append(row)
        return "\n".join(rows)

    if fmt == "stix":
        objs = []
        for r in records:  # STIX must be refanged
            pat = _stix_pattern(r["type"], r["indicator"])
            if not pat:
                continue
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, r['type'] + ':' + r['indicator'])}",
                "created": now, "modified": now, "name": f"{r['type']}: {r['indicator']}",
                "pattern": pat, "pattern_type": "stix", "valid_from": now,
                "indicator_types": ["malicious-activity"],
                "external_references": [{"source_name": "extraction-source", "description": source}],
            })
        return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}, indent=2)

    raise ValueError(fmt)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="file path, or - for stdin")
    ap.add_argument("--format", choices=["json", "csv", "md", "list", "stix"], default="json")
    ap.add_argument("--types", help="comma-separated subset, e.g. ipv4,domain,sha256")
    ap.add_argument("--defang", action="store_true", help="defang network indicators in output")
    ap.add_argument("--context", action="store_true", help="include surrounding text for each hit")
    ap.add_argument("--keep-private", action="store_true", help="keep RFC1918/loopback/link-local IPs")
    ap.add_argument("--keep-noise", action="store_true", help="keep well-known vendor/reference domains")
    ap.add_argument("--allowlist", type=Path,
                    default=Path(__file__).resolve().parent.parent / "references" / "allowlist.txt",
                    help="file of glob patterns to drop (default: references/allowlist.txt)")
    ap.add_argument("--source", help="label for the source document (default: input filename)")
    args = ap.parse_args(argv)

    if args.input == "-":
        text = sys.stdin.read()
        source = args.source or "stdin"
    else:
        p = Path(args.input)
        if not p.is_file():
            print(f"error: {p} is not a file", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8", errors="replace")
        source = args.source or p.name

    types = {t.strip() for t in args.types.split(",")} if args.types else None
    known = {t for t, _ in PATTERNS}
    if types and not types <= known:
        print(f"error: unknown types {sorted(types - known)}; known: {sorted(known)}", file=sys.stderr)
        return 2

    records = extract(text, types=types, allowlist=_load_allowlist(args.allowlist),
                      keep_private=args.keep_private, keep_noise=args.keep_noise,
                      with_context=args.context)
    sys.stdout.write(render(records, args.format, do_defang=args.defang, source=source))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
