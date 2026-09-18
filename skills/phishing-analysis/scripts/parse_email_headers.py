#!/usr/bin/env python3
"""Parse a reported email (.eml, or raw headers on stdin) for phishing analysis.

Standard library only. Reads bytes, never fetches URLs, never renders HTML,
never runs attachments. Everything in the message is treated as untrusted data.

What it extracts:
  * Received chain in chronological order with parsed hosts, IPs, timestamps
    and the delay between hops (negative delays mean clock skew or forgery)
  * Authentication-Results / ARC-Authentication-Results / Received-SPF parsed
    into SPF, DKIM, DMARC, ARC and compauth results with their properties
  * Alignment: From vs Return-Path vs Reply-To vs Sender vs DKIM d= vs Message-ID
    domain, plus display-name tricks and lookalikes of your own domains
  * URLs from text and HTML parts (defanged by default), with anchor-text
    mismatches, form actions, decoded Safe Links / Proofpoint / Google wrappers
  * Attachments with type, size, MD5/SHA-256, magic-byte hint and risk flags
  * A findings list (observations, not a verdict) and lure-class hints

Usage:
    python parse_email_headers.py message.eml
    python parse_email_headers.py message.eml --format json
    python parse_email_headers.py message.eml --org-domain yourcompany.example
    cat headers.txt | python parse_email_headers.py - --format md
    python parse_email_headers.py message.eml --no-defang --format json
    python parse_email_headers.py message.eml --extract-dir ./attachments   # writes <sha256>.bin

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import hashlib
import html as htmlmod
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

MAX_INPUT_BYTES = 50 * 1024 * 1024
MAX_URLS = 500
MAX_PHONES = 25
MAX_TEXT_SCAN = 2 * 1024 * 1024  # bytes of body text scanned per part

# --------------------------------------------------------------------------- tables

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "mail.com", "zoho.com", "yandex.com",
    "yandex.ru", "mail.ru", "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "qq.com",
    "163.com", "126.com", "rediffmail.com", "web.de", "t-online.de", "orange.fr", "free.fr",
}

URL_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "buff.ly",
    "rb.gy", "tiny.cc", "shorturl.at", "goo.gl", "t.ly", "lnkd.in", "bl.ink", "shorte.st",
    "s.id", "v.gd", "qrco.de", "short.io",
}

DANGEROUS_EXT = {
    "exe", "scr", "pif", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "hta", "msi", "msp", "cpl", "dll", "lnk", "url", "reg", "inf", "chm", "iso", "img",
    "vhd", "vhdx", "one", "svg", "xll", "jar", "apk", "appx", "msix", "sct", "application",
}
MACRO_CAPABLE_EXT = {"doc", "dot", "xls", "xlt", "xlm", "ppt", "pot", "docm", "dotm", "xlsm",
                     "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm", "rtf"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "z"}
HTML_ATTACH_EXT = {"htm", "html", "shtml", "xhtml", "mht", "mhtml", "svg"}

MAGIC = [
    (b"MZ", 0, "pe-executable"),
    (b"\x7fELF", 0, "elf"),
    (b"PK\x03\x04", 0, "zip-container"),
    (b"%PDF", 0, "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole-cfb (doc/xls/ppt/msg/msi)"),
    (b"{\\rtf", 0, "rtf"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7zip"),
    (b"\x1f\x8b", 0, "gzip"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "lnk-shortcut"),
    (b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d", 0, "onenote"),
    (b"CD001", 0x8001, "iso-9660"),
    (b"\x89PNG", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF8", 0, "gif"),
    (b"#!", 0, "script-shebang"),
]

# lure keyword hints; matched case-insensitively against subject + text body
LURE_HINTS = {
    "credential-harvest": [r"\bverify (?:your )?(?:account|identity|email)", r"\bpassword\b", r"\bre-?authenticate",
                           r"\bsign[- ]in\b", r"\baccount (?:has been |will be )?(?:suspended|locked|limited|disabled)",
                           r"\bunusual (?:sign-?in|activity)", r"\bmailbox (?:is )?(?:full|storage)",
                           r"\bshared (?:a )?(?:file|document)\b", r"\bdocusign\b", r"\bvoicemail\b", r"\be-?fax\b",
                           r"\bencrypted message\b", r"\bsecure message\b"],
    "bec-invoice": [r"\binvoice\b", r"\bpayment\b", r"\bwire\b", r"\bbank(?:ing)? details?\b", r"\bremittance\b",
                    r"\bpurchase order\b", r"\bpast due\b", r"\boverdue\b", r"\bupdated? (?:our )?(?:account|bank)\b",
                    r"\bare you available\b", r"\bquick (?:task|favou?r|request)\b", r"\bgift ?cards?\b",
                    r"\bconfidential\b.{0,60}?\bacquisition\b"],
    "callback-toad": [r"\bcall (?:us|our|customer|support|the number)\b", r"\bsubscription\b.{0,60}?\brenew",
                      r"\bauto-?renew", r"\bcharged\b", r"\brefund\b", r"\bcancel(?:lation)?\b.{0,60}?\bcall\b",
                      r"\bcustomer (?:care|support) (?:number|line)\b", r"\bgeek squad\b", r"\bnorton\b", r"\bmcafee\b"],
    "mfa-push": [r"\bmfa\b", r"\bmulti-?factor\b", r"\bauthenticat(?:or|ion) (?:app|code|request)\b",
                 r"\bapprove (?:the|this) (?:sign-?in|request)\b", r"\bone-?time (?:code|passcode)\b", r"\botp\b"],
    "package-delivery": [r"\bpackage\b", r"\bparcel\b", r"\bdelivery (?:attempt|failed|fee)\b", r"\bshipment\b",
                         r"\btracking (?:number|id)\b", r"\bcustoms\b", r"\bredeliver"],
    "hr-payroll": [r"\bdirect deposit\b", r"\bpayroll\b", r"\bw-?2\b", r"\bpay ?(?:slip|stub|check)\b",
                   r"\bbenefits? enrollment\b", r"\bsalary (?:adjustment|increase|review)\b", r"\bbonus\b",
                   r"\bhandbook\b", r"\btermination\b"],
    "it-helpdesk": [r"\bhelp ?desk\b", r"\bit (?:department|support|team)\b", r"\bpassword (?:will )?expir",
                    r"\bupgrade your\b", r"\bmigrat(?:e|ion)\b", r"\bvpn\b"],
    "legal-threat": [r"\bsubpoena\b", r"\blawsuit\b", r"\bcopyright (?:infringement|violation)\b", r"\blegal action\b",
                     r"\bcourt\b", r"\bfine\b.*\bpay\b"],
    "extortion": [r"\bbitcoin\b", r"\bbtc\b", r"\bwebcam\b", r"\bcompromising\b", r"\bexpos(?:e|ed|ing)\b.{0,60}?\bcontacts\b"],
    "qr-code": [r"\bqr ?code\b", r"\bscan (?:the|this) (?:code|image)\b", r"\bscan with your (?:phone|camera)\b"],
}
URGENCY = [r"\burgent(?:ly)?\b", r"\bimmediately\b", r"\bwithin (?:24|48) hours\b", r"\btoday\b", r"\bfinal (?:notice|warning|reminder)\b",
           r"\baction required\b", r"\bexpires? (?:today|soon|in)\b", r"\bdo not ignore\b", r"\basap\b", r"\bright away\b"]

# --------------------------------------------------------------------------- regexes (bounded)

RE_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{7,45})\]")
RE_PAREN_IP = re.compile(r"\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)")
RE_BARE_IP = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
RE_FROM = re.compile(r"^\s*from\s+([^\s;()]{1,253})", re.I)
RE_BY = re.compile(r"\bby\s+([^\s;()]{1,253})", re.I)
RE_WITH = re.compile(r"\bwith\s+([A-Za-z0-9._-]{1,40})", re.I)
RE_ID = re.compile(r"\bid\s+([^\s;()]{1,120})", re.I)
RE_FOR = re.compile(r"\bfor\s+<?([^\s>;()]{1,254})>?", re.I)
RE_HELO = re.compile(r"^\s*from\s+[^\s;()]{1,253}\s+\(([^\s()\[\]]{1,253})", re.I)

RE_AUTH_METHOD = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]{0,20})\s*=\s*([A-Za-z]{1,20})")
RE_AUTH_PROP = re.compile(r"\b([a-z]+\.[a-z_]+|reason|action|policy)\s*=\s*(\"[^\"]{0,200}\"|[^\s;()]{1,254})", re.I)
RE_PAREN_COMMENT = re.compile(r"\(([^()]{0,300})\)")
RE_DKIM_TAG = re.compile(r"\b([a-z]{1,2})=([^;]{0,500})", re.I)

RE_URL_TEXT = re.compile(r"(?:https?|ftp)://[^\s<>\"'\)\]\}]{1,2048}", re.I)
RE_URL_WWW = re.compile(r"(?<![/\w.@])www\.[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,10}(?:/[^\s<>\"']{0,1024})?", re.I)
RE_HTML_ATTR = re.compile(r"\b(href|src|action|data|background|poster|formaction)\s*=\s*(?:\"([^\"]{1,2048})\"|'([^']{1,2048})'|([^\s>]{1,2048}))", re.I)
RE_ANCHOR = re.compile(r"<a\b[^>]{0,1000}?href\s*=\s*(?:\"([^\"]{1,2048})\"|'([^']{1,2048})'|([^\s>]{1,2048}))[^>]{0,1000}>(.{0,600}?)</a>", re.I | re.S)
RE_TAG = re.compile(r"<[^>]{0,500}>")
RE_PHONE = re.compile(r"(?<![\w/])\+?\(?\d{1,3}\)?[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")
RE_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{1500,}={0,2}")
RE_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
RE_DOMAIN_LIKE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)

HTML_FLAGS = [
    ("script_tag", re.compile(r"<script\b", re.I)),
    ("form_tag", re.compile(r"<form\b", re.I)),
    ("password_input", re.compile(r"type\s*=\s*[\"']?password", re.I)),
    ("iframe_tag", re.compile(r"<iframe\b", re.I)),
    ("meta_refresh", re.compile(r"http-equiv\s*=\s*[\"']?refresh", re.I)),
    ("javascript_uri", re.compile(r"javascript:", re.I)),
    ("data_uri", re.compile(r"\bdata:[a-z]+/[a-z0-9.+-]+;base64,", re.I)),
    ("blob_download_api", re.compile(r"\b(?:atob|Blob|msSaveOrOpenBlob|createObjectURL)\s*\(", re.I)),
    ("hidden_text", re.compile(r"(?:font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#?fff(?:fff)?\b)", re.I)),
    ("obfuscated_js", re.compile(r"\b(?:eval|unescape|String\.fromCharCode|document\.write)\s*\(", re.I)),
]

# --------------------------------------------------------------------------- helpers

CC_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or", "go", "mil", "ltd", "plc", "nhs"}


def org_domain(domain: str) -> str:
    """Approximate the registrable (organizational) domain without a PSL."""
    d = domain.lower().strip(".")
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    if parts[-2] in CC_SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def addr_domain(addr: str) -> str:
    return addr.rpartition("@")[2].lower().strip("<> ") if "@" in addr else ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10")]
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def ip_scope(value: str) -> str:
    """Explicit ranges rather than ipaddress.is_private, which newer Pythons extend to RFC 5737 doc ranges."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if any(ip in n for n in _PRIVATE_NETS):
        return "private"
    if any(ip in n for n in _DOC_NETS):
        return "documentation"
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "reserved"
    return "public"


def defang_url(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").replace(".", "[.]")
    scheme = parts.scheme.lower().replace("http", "hxxp") if parts.scheme else ""
    rest = url
    if parts.scheme:
        rest = url[len(parts.scheme) + 3:]
    netloc_end = rest.find("/")
    tail = rest[netloc_end:] if netloc_end != -1 else ""
    netloc = rest[:netloc_end] if netloc_end != -1 else rest
    if parts.hostname:
        netloc = netloc.replace(parts.hostname, host, 1)
    return f"{scheme}://{netloc}{tail}" if scheme else f"{netloc}{tail}".replace(".", "[.]", 1)


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def magic_hint(data: bytes) -> str:
    for sig, offset, label in MAGIC:
        if data[offset:offset + len(sig)] == sig:
            return label
    head = data[:512].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<script" in head:
        return "html"
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        return "xml/svg"
    return "unknown"


def levenshtein(a: str, b: str) -> int:
    if len(a) > 64 or len(b) > 64:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str, org_domains: list[str]) -> str | None:
    """Return the org domain this one resembles, if any (combosquat, typosquat, homoglyph, TLD swap)."""
    d = domain.lower()
    if not d or d in org_domains:
        return None
    dl = d.split(".")[0] if "." in d else d
    for o in org_domains:
        ol = o.split(".")[0]
        if d.endswith("." + o):
            return None  # legitimate subdomain
        if ol and (ol in d.replace(".", "-")):
            return o  # combosquat or TLD swap: 'yourcompany-billing.example', 'yourcompany.co'
        norm = dl.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w").replace("cl", "d")
        if norm == ol or levenshtein(dl, ol) <= max(1, len(ol) // 5):
            return o
    return None


def hdr(msg: EmailMessage, name: str) -> str:
    try:
        v = msg.get(name)
    except Exception:  # defective header per the policy
        v = None
    return str(v) if v is not None else ""


def hdr_all(msg: EmailMessage, name: str) -> list[str]:
    try:
        return [str(v) for v in msg.get_all(name, [])]
    except Exception:
        return []


def parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


# --------------------------------------------------------------------------- received chain

def parse_received(headers: list[str]) -> list[dict]:
    hops = []
    for raw in headers:
        line = re.sub(r"\s+", " ", raw).strip()
        body, _, date_part = line.rpartition(";")
        if not body:  # no date separator
            body, date_part = line, ""
        pre_by = re.split(r"\bby\b", body, maxsplit=1, flags=re.I)[0]
        ips = RE_BRACKET_IP.findall(pre_by) + RE_PAREN_IP.findall(pre_by)
        if not ips:
            ips = RE_BARE_IP.findall(pre_by)
        ip = next((i for i in ips if is_ip(i)), None)
        m_from, m_by, m_with, m_id, m_for, m_helo = (RE_FROM.search(body), RE_BY.search(body), RE_WITH.search(body),
                                                    RE_ID.search(body), RE_FOR.search(body), RE_HELO.search(body))
        helo = m_helo.group(1) if m_helo else None
        if helo and (helo.lower() == "unknown" or is_ip(helo.strip("[]"))):
            rdns = helo.lower()
            helo = None
        else:
            rdns = helo
        dt = parse_date(date_part)
        hops.append({
            "from_host": m_from.group(1) if m_from else None,
            "from_rdns": rdns,
            "from_ip": ip,
            "ip_scope": ip_scope(ip) if ip else None,
            "by_host": m_by.group(1) if m_by else None,
            "with": m_with.group(1) if m_with else None,
            "id": m_id.group(1) if m_id else None,
            "for": m_for.group(1) if m_for else None,
            "timestamp_utc": iso(dt),
            "_dt": dt,
            "raw": line[:600],
        })
    hops.reverse()  # header order is newest-first; present oldest-first
    prev_dt = None
    for n, hop in enumerate(hops, 1):
        hop["hop"] = n
        dt = hop.pop("_dt", None)
        hop["delay_seconds"] = int((dt - prev_dt).total_seconds()) if (dt and prev_dt) else None
        prev_dt = dt or prev_dt
    return hops


# --------------------------------------------------------------------------- authentication

def parse_auth_results(value: str, header_name: str) -> dict:
    text = re.sub(r"\s+", " ", value).strip()
    segments = [s.strip() for s in text.split(";") if s.strip()]
    authserv = segments[0] if segments else ""
    authserv_id = authserv.split(" ")[0] if authserv else ""
    results = []
    for seg in segments[1:]:
        comments = RE_PAREN_COMMENT.findall(seg)
        clean = RE_PAREN_COMMENT.sub(" ", seg)
        m = RE_AUTH_METHOD.search(clean)
        if not m:
            continue
        props = {k.lower(): v.strip("\"") for k, v in RE_AUTH_PROP.findall(clean[m.end():])}
        results.append({"method": m.group(1).lower(), "result": m.group(2).lower(), "properties": props,
                        "comment": "; ".join(c.strip() for c in comments)[:300] or None})
    return {"header": header_name, "authserv_id": authserv_id, "results": results}


def parse_received_spf(value: str) -> dict:
    text = re.sub(r"\s+", " ", value).strip()
    m = re.match(r"^([A-Za-z]+)", text)
    props = {k.lower(): v.strip("\"") for k, v in RE_AUTH_PROP.findall(text)}
    for key in ("client-ip", "envelope-from", "helo", "identity", "receiver"):
        mm = re.search(rf"\b{key}=([^\s;]{{1,254}})", text, re.I)
        if mm:
            props[key] = mm.group(1)
    return {"result": m.group(1).lower() if m else None, "properties": props, "raw": text[:400]}


def parse_dkim_signature(value: str) -> dict:
    text = re.sub(r"\s+", "", value)
    tags = {}
    for tag, val in RE_DKIM_TAG.findall(text):
        t = tag.lower()
        if t in {"v", "a", "d", "s", "c", "q", "t", "x", "h", "i", "l", "bh"}:
            tags[t] = val[:120]
    return tags


def summarize_auth(auth_headers: list[dict]) -> dict:
    """Pick the first result per method from the topmost (most recent) Authentication-Results."""
    summary: dict[str, dict] = {}
    for ah in auth_headers:
        if ah["header"] != "Authentication-Results":
            continue
        for r in ah["results"]:
            summary.setdefault(r["method"], {"result": r["result"], "properties": r["properties"],
                                             "authserv_id": ah["authserv_id"]})
    return summary


# --------------------------------------------------------------------------- body / urls

def decode_wrapped(url: str) -> tuple[str | None, str | None]:
    """Unwrap common corporate link rewriters. Returns (real_url, wrapper_name)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None, None
    host = (parts.hostname or "").lower()
    qs = parse_qs(parts.query, max_num_fields=50)
    if host.endswith("safelinks.protection.outlook.com") and qs.get("url"):
        return unquote(qs["url"][0])[:2048], "microsoft-safelinks"
    if host == "urldefense.proofpoint.com" and parts.path.startswith("/v2/url") and qs.get("u"):
        enc = qs["u"][0]
        return unquote(enc.replace("_", "/").replace("-", "%"))[:2048], "proofpoint-urldefense-v2"
    if host in {"urldefense.com", "urldefense.proofpoint.com"} and parts.path.startswith("/v3/"):
        m = re.match(r"^/v3/__(.{1,2048}?)__;", parts.path + ("?" + parts.query if parts.query else ""))
        if m:
            return m.group(1), "proofpoint-urldefense-v3 (partial: '*' marks encoded chars)"
    if host in {"www.google.com", "google.com"} and parts.path == "/url" and qs.get("q"):
        return qs["q"][0][:2048], "google-redirect"
    if host.endswith(".mimecast.com") and parts.path.startswith("/s/"):
        return None, "mimecast-protect (opaque; decode in the Mimecast console)"
    if host.endswith("linkprotect.cudasvc.com") and qs.get("a"):
        return unquote(qs["a"][0])[:2048], "barracuda-linkprotect"
    return None, None


def url_record(url: str, source: str, anchor_text: str | None = None) -> dict:
    url = htmlmod.unescape(url.strip()).strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = None
    host = (parts.hostname or "").lower() if parts else ""
    rec = {
        "url": url[:2048], "scheme": (parts.scheme.lower() if parts else ""), "host": host,
        "port": parts.port if parts and parts.port else None,
        "path": (parts.path or "")[:300] if parts else "", "source": source, "anchor_text": anchor_text,
        "flags": [], "decoded_url": None, "wrapper": None, "count": 1,
    }
    if not host and parts and parts.scheme in {"http", "https", "ftp"}:
        rec["flags"].append("unparseable")
    if host and is_ip(host):
        rec["flags"].append("ip_host")
    if parts and parts.username:
        rec["flags"].append("userinfo_in_url")  # http://bank.example@evil.example/
    if host in URL_SHORTENERS:
        rec["flags"].append("shortener")
    if rec["port"] and rec["port"] not in (80, 443):
        rec["flags"].append("unusual_port")
    if len(url) > 500:
        rec["flags"].append("very_long")
    if parts and RE_EMAIL_IN_TEXT.search(unquote(parts.query or "") + unquote(parts.fragment or "")):
        rec["flags"].append("email_in_url")  # pre-filled victim address
    if host.endswith((".ipfs.io", ".ipfs.dweb.link")) or "/ipfs/" in (parts.path if parts else ""):
        rec["flags"].append("ipfs")
    if re.search(r"\b(?:redirect|redir|url|goto|next|return|dest|target|rurl|link)=https?", parts.query if parts else "", re.I):
        rec["flags"].append("open_redirect_pattern")
    real, wrapper = decode_wrapped(url)
    if wrapper:
        rec["wrapper"] = wrapper
        rec["flags"] = [f for f in rec["flags"] if f not in {"open_redirect_pattern", "email_in_url", "very_long"}]
    if real:
        rec["decoded_url"] = real
        rhost = (urlsplit(real).hostname or "").lower()
        rec["decoded_host"] = rhost
    if anchor_text:
        at = RE_TAG.sub("", htmlmod.unescape(anchor_text)).strip()
        rec["anchor_text"] = at[:200]
        m = RE_URL_TEXT.search(at) or RE_DOMAIN_LIKE.search(at)
        if m:
            shown = m.group(0)
            shown_host = (urlsplit(shown if "://" in shown else "http://" + shown).hostname or "").lower()
            target_host = rec.get("decoded_host") or host
            if shown_host and target_host and org_domain(shown_host) != org_domain(target_host):
                rec["flags"].append("link_text_mismatch")
                rec["shown_host"] = shown_host
    return rec


def extract_urls_from_text(text: str, source: str) -> list[dict]:
    out = []
    for m in RE_URL_TEXT.finditer(text[:MAX_TEXT_SCAN]):
        out.append(url_record(m.group(0).rstrip(".,;:'\")]}>"), source))
        if len(out) >= MAX_URLS:
            break
    for m in RE_URL_WWW.finditer(text[:MAX_TEXT_SCAN]):
        out.append(url_record(m.group(0).rstrip(".,;:'\")]}>"), source))
        if len(out) >= MAX_URLS:
            break
    return out


def extract_urls_from_html(html_text: str) -> tuple[list[dict], list[str], str]:
    html_text = html_text[:MAX_TEXT_SCAN]
    out: list[dict] = []
    anchored: set[str] = set()
    for m in RE_ANCHOR.finditer(html_text):
        href = m.group(1) or m.group(2) or m.group(3) or ""
        if href.lower().startswith(("mailto:", "tel:", "#", "cid:")):
            continue
        anchored.add(href)
        out.append(url_record(href, "html-anchor", anchor_text=m.group(4)))
        if len(out) >= MAX_URLS:
            break
    for m in RE_HTML_ATTR.finditer(html_text):
        attr = m.group(1).lower()
        val = m.group(2) or m.group(3) or m.group(4) or ""
        low = val.lower()
        if val in anchored or low.startswith(("#", "cid:", "mailto:", "tel:")):
            continue
        if low.startswith(("data:", "javascript:")):
            rec = {"url": val[:120] + ("..." if len(val) > 120 else ""), "scheme": low.split(":")[0], "host": "",
                   "source": f"html-{attr}", "flags": [f"{low.split(':')[0]}_uri"], "count": 1, "anchor_text": None,
                   "decoded_url": None, "wrapper": None, "port": None, "path": ""}
            out.append(rec)
            continue
        if not re.match(r"^(?:https?|ftp)://|^www\.", low):
            continue
        src = "html-form-action" if attr in {"action", "formaction"} else f"html-{attr}"
        out.append(url_record(val, src))
        if len(out) >= MAX_URLS:
            break
    flags = [name for name, rx in HTML_FLAGS if rx.search(html_text)]
    if RE_BASE64_BLOB.search(html_text):
        flags.append("large_base64_blob")
    visible = htmlmod.unescape(RE_TAG.sub(" ", re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html_text)))
    visible = re.sub(r"\s+", " ", visible).strip()
    return out, flags, visible


def dedupe_urls(urls: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for u in urls:
        key = u["url"]
        if key in seen:
            seen[key]["count"] += 1
            for f in u["flags"]:
                if f not in seen[key]["flags"]:
                    seen[key]["flags"].append(f)
            if u.get("anchor_text") and not seen[key].get("anchor_text"):
                seen[key]["anchor_text"] = u["anchor_text"]
        else:
            seen[key] = u
    return list(seen.values())


# --------------------------------------------------------------------------- attachments

def ext_of(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def attachment_record(part: EmailMessage, extract_dir: Path | None) -> dict:
    name = part.get_filename() or ""
    try:
        data = part.get_payload(decode=True) or b""
    except Exception:
        data = b""
    ext = ext_of(name)
    flags = []
    parts = name.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "invoice"}:
        flags.append("double_extension")
    if ext in DANGEROUS_EXT:
        flags.append("dangerous_extension")
    if ext in MACRO_CAPABLE_EXT:
        flags.append("macro_capable_format")
    if ext in ARCHIVE_EXT:
        flags.append("archive (password may be in the body)")
    if ext in HTML_ATTACH_EXT:
        flags.append("html_attachment (HTML smuggling / local credential form)")
    magic = magic_hint(data)
    if magic == "pe-executable" and ext not in {"exe", "dll", "scr", "sys", "cpl", "ocx"}:
        flags.append("executable_disguised")
    if magic == "html" and ext not in HTML_ATTACH_EXT:
        flags.append("html_content_with_other_extension")
    if magic == "zip-container" and ext not in ARCHIVE_EXT | {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar", "apk", "xpi", "odt", "ods", "epub"}:
        flags.append("zip_content_with_other_extension")
    if magic == "unknown" and ext in {"pdf", "docx", "xlsx", "zip"}:
        flags.append("extension_magic_mismatch")
    disposition = str(part.get("Content-Disposition", "")).split(";")[0].strip().lower() or None
    cid = str(part.get("Content-ID", "")).strip("<> ") or None
    if cid and part.get_content_maintype() == "image" and len(data) > 3_000:
        flags.append("inline_image (check for QR code)")
    rec = {
        "filename": name or None, "content_type": part.get_content_type(), "disposition": disposition,
        "content_id": cid, "size": len(data), "md5": hashlib.md5(data).hexdigest() if data else None,
        "sha256": sha256_bytes(data) if data else None, "magic": magic, "flags": flags,
    }
    if (magic in {"html", "xml/svg"} or ext in HTML_ATTACH_EXT) and 0 < len(data) <= MAX_TEXT_SCAN:
        # HTML attachments are where smuggled payloads and local credential forms live; scan without rendering
        inner_urls, inner_flags, _ = extract_urls_from_html(data.decode("utf-8", errors="replace"))
        rec["urls"] = dedupe_urls(inner_urls)[:50]
        rec["html_flags"] = inner_flags
    if extract_dir is not None and data:
        extract_dir.mkdir(parents=True, exist_ok=True)
        target = extract_dir / f"{rec['sha256']}.bin"
        target.write_bytes(data)
        rec["extracted_to"] = str(target)
    return rec


# --------------------------------------------------------------------------- analysis

def analyze(raw: bytes, *, org_domains: list[str], defang: bool, extract_dir: Path | None) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if not isinstance(msg, EmailMessage):
        msg = EmailMessage(policy=policy.default)

    # -- addresses
    from_raw = hdr(msg, "From")
    from_name, from_addr = parseaddr(from_raw)
    from_addrs = [a for _, a in getaddresses([from_raw])] if from_raw else []
    sender_addr = parseaddr(hdr(msg, "Sender"))[1]
    reply_to = [a for _, a in getaddresses(hdr_all(msg, "Reply-To"))]
    return_path = parseaddr(hdr(msg, "Return-Path"))[1]
    to_addrs = [a for _, a in getaddresses(hdr_all(msg, "To"))]
    cc_addrs = [a for _, a in getaddresses(hdr_all(msg, "Cc"))]
    message_id = hdr(msg, "Message-ID").strip()
    mid_domain = message_id.strip("<>").rpartition("@")[2].lower() if "@" in message_id else ""

    # -- routing and auth
    received = parse_received(hdr_all(msg, "Received"))
    auth_headers = [parse_auth_results(v, "Authentication-Results") for v in hdr_all(msg, "Authentication-Results")]
    auth_headers += [parse_auth_results(v, "ARC-Authentication-Results") for v in hdr_all(msg, "ARC-Authentication-Results")]
    received_spf = [parse_received_spf(v) for v in hdr_all(msg, "Received-SPF")]
    dkim_sigs = [parse_dkim_signature(v) for v in hdr_all(msg, "DKIM-Signature")]
    auth = summarize_auth(auth_headers)
    if "spf" not in auth and received_spf and received_spf[0]["result"]:
        auth["spf"] = {"result": received_spf[0]["result"], "properties": received_spf[0]["properties"], "authserv_id": "Received-SPF"}
    if not return_path:
        return_path = (auth.get("spf", {}).get("properties", {}).get("smtp.mailfrom")
                       or (received_spf[0]["properties"].get("envelope-from") if received_spf else "") or "")
        return_path = return_path.strip("<>")

    from_domain = addr_domain(from_addr)
    rp_domain = addr_domain(return_path) if "@" in return_path else return_path.lower()
    reply_domains = sorted({addr_domain(a) for a in reply_to if a})
    dkim_domains = sorted({s.get("d", "").lower() for s in dkim_sigs if s.get("d")})
    dkim_d_from_auth = auth.get("dkim", {}).get("properties", {}).get("header.d", "").lower()
    if dkim_d_from_auth and dkim_d_from_auth not in dkim_domains:
        dkim_domains.append(dkim_d_from_auth)

    def aligned(a: str, b: str) -> str | None:
        if not a or not b:
            return None
        if a == b:
            return "strict"
        if org_domain(a) == org_domain(b):
            return "relaxed"
        return "none"

    alignment = {
        "from_domain": from_domain, "return_path_domain": rp_domain or None, "reply_to_domains": reply_domains,
        "sender_domain": addr_domain(sender_addr) or None, "dkim_domains": dkim_domains, "message_id_domain": mid_domain or None,
        "spf_alignment": aligned(from_domain, rp_domain),
        "dkim_alignment": max((aligned(from_domain, d) or "none" for d in dkim_domains), key=lambda x: {"strict": 2, "relaxed": 1, "none": 0}[x]) if dkim_domains else None,
        "reply_to_alignment": [aligned(from_domain, d) for d in reply_domains],
        "message_id_alignment": aligned(from_domain, mid_domain),
    }

    # -- body parts
    urls: list[dict] = []
    html_flags: list[str] = []
    text_body = ""
    html_visible = ""
    attachments: list[dict] = []
    part_summary: list[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        is_attach = part.is_attachment() or bool(part.get_filename()) or part.get("Content-ID") is not None
        if ctype in {"text/plain", "text/html"} and not (part.is_attachment() or part.get_filename()):
            try:
                content = part.get_content()
            except Exception:
                content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            if not isinstance(content, str):
                content = str(content)
            part_summary.append({"content_type": ctype, "chars": len(content), "charset": part.get_content_charset()})
            if ctype == "text/plain":
                text_body += content[:MAX_TEXT_SCAN] + "\n"
                urls += extract_urls_from_text(content, "text")
            else:
                u, f, visible = extract_urls_from_html(content)
                urls += u
                html_flags += [x for x in f if x not in html_flags]
                html_visible += visible[:MAX_TEXT_SCAN] + "\n"
                urls += [r for r in extract_urls_from_text(visible, "html-visible-text")
                         if not any(r["url"] == e["url"] for e in urls)]
        elif is_attach or ctype not in {"text/plain", "text/html"}:
            attachments.append(attachment_record(part, extract_dir))
    urls = dedupe_urls(urls)[:MAX_URLS]

    scan_text = (hdr(msg, "Subject") + "\n" + text_body + "\n" + html_visible)[:MAX_TEXT_SCAN]
    lure_hits = {}
    for cls, patterns in LURE_HINTS.items():
        hits = sorted({m.group(0).lower()[:40] for rx in patterns for m in [re.search(rx, scan_text, re.I)] if m})
        if hits:
            lure_hits[cls] = hits[:8]
    urgency_hits = sorted({m.group(0).lower() for rx in URGENCY for m in [re.search(rx, scan_text, re.I)] if m})
    phones = []
    for m in RE_PHONE.finditer(scan_text):
        digits = re.sub(r"\D", "", m.group(0))
        if 10 <= len(digits) <= 15 and m.group(0).strip() not in phones:
            phones.append(m.group(0).strip())
        if len(phones) >= MAX_PHONES:
            break
    body_emails = sorted({e.lower() for e in RE_EMAIL_IN_TEXT.findall(scan_text)})[:50]

    # -- misc headers
    date_hdr = parse_date(hdr(msg, "Date"))
    first_hop_ts = next((h["timestamp_utc"] for h in received if h["timestamp_utc"]), None)
    x_orig = hdr(msg, "X-Originating-IP") or hdr(msg, "X-Sender-IP") or hdr(msg, "X-Source-IP")
    x_orig_ip = next((i for i in RE_BRACKET_IP.findall(x_orig) + RE_BARE_IP.findall(x_orig) if is_ip(i)), None)
    forefront = hdr(msg, "X-Forefront-Antispam-Report")
    ff = {}
    if forefront:
        for k, v in re.findall(r"\b([A-Z]{2,6}):([^;]{0,120})", forefront):
            ff[k] = v.strip()
    other = {
        "subject": hdr(msg, "Subject") or None,
        "date": iso(date_hdr),
        "to": to_addrs, "cc": cc_addrs,
        "message_id": message_id or None,
        "in_reply_to": hdr(msg, "In-Reply-To").strip() or None,
        "references_count": len(hdr(msg, "References").split()) if hdr(msg, "References") else 0,
        "x_originating_ip": x_orig_ip,
        "x_mailer": hdr(msg, "X-Mailer") or hdr(msg, "User-Agent") or None,
        "x_priority": hdr(msg, "X-Priority") or hdr(msg, "Importance") or None,
        "list_unsubscribe": bool(hdr(msg, "List-Unsubscribe")),
        "precedence": hdr(msg, "Precedence") or None,
        "auto_submitted": hdr(msg, "Auto-Submitted") or None,
        "x_ms_exchange_authas": hdr(msg, "X-MS-Exchange-Organization-AuthAs") or None,
        "x_ms_exchange_scl": hdr(msg, "X-MS-Exchange-Organization-SCL") or None,
        "x_forefront_antispam": ff or None,
        "x_proofpoint_spam_details": hdr(msg, "X-Proofpoint-Spam-Details")[:300] or None,
        "x_mimecast_spam_score": hdr(msg, "X-Mimecast-Spam-Score") or None,
        "arc_seal_count": len(hdr_all(msg, "ARC-Seal")),
    }

    # -- findings
    findings: list[dict] = []

    def add(sev: str, text: str, detail: str | None = None) -> None:
        findings.append({"severity": sev, "finding": text, "detail": detail})

    spf = auth.get("spf", {}).get("result")
    dkim = auth.get("dkim", {}).get("result")
    dmarc = auth.get("dmarc", {}).get("result")
    comp = auth.get("compauth", {}).get("result")
    if not auth_headers:
        add("info", "No Authentication-Results header; message may be an internal/forwarded copy or headers were stripped")
    if spf in {"fail", "softfail", "permerror"}:
        add("high" if spf == "fail" else "medium", f"SPF {spf}", f"smtp.mailfrom={auth['spf']['properties'].get('smtp.mailfrom')}")
    elif spf in {"none", "neutral", "temperror"}:
        add("medium", f"SPF {spf}: sending domain publishes no usable SPF policy or evaluation failed")
    if dkim in {"fail", "permerror"}:
        add("high", f"DKIM {dkim}", f"header.d={dkim_d_from_auth or None}")
    elif dkim in {"none", None} and auth_headers:
        add("medium", "No DKIM signature verified", "unsigned mail from a modern sender is unusual")
    if dmarc == "fail":
        pol = auth["dmarc"]["properties"].get("action") or auth["dmarc"]["properties"].get("policy") or auth["dmarc"]["properties"].get("reason")
        add("high", "DMARC fail", f"header.from={auth['dmarc']['properties'].get('header.from')}; action/policy={pol}")
    elif dmarc in {"none", "bestguesspass", "permerror", "temperror"}:
        add("medium", f"DMARC {dmarc}: From domain has no enforced DMARC policy, so it is spoofable")
    if comp == "fail":
        add("high", "Microsoft composite authentication (compauth) fail", auth["compauth"]["properties"].get("reason"))
    if alignment["spf_alignment"] == "none":
        add("medium", "Return-Path domain does not align with From domain",
            f"From={from_domain}; Return-Path={rp_domain}. Legitimate for bulk mailers and forwarders; suspicious for personal/finance mail")
    if dkim_domains and alignment["dkim_alignment"] == "none":
        add("medium", "DKIM d= domain does not align with From domain", f"From={from_domain}; d={','.join(dkim_domains)}")
    for d, a in zip(reply_domains, alignment["reply_to_alignment"]):
        if a == "none":
            add("high", "Reply-To domain differs from From domain (classic BEC / conversation-redirect tell)",
                f"From={from_domain}; Reply-To={d}")
    if mid_domain and alignment["message_id_alignment"] == "none" and dkim_domains and mid_domain not in dkim_domains:
        add("info", "Message-ID domain differs from From and DKIM domains", f"Message-ID @{mid_domain}")
    if not message_id:
        add("medium", "Missing Message-ID header")
    if len(from_addrs) > 1:
        add("high", "Multiple addresses in From header", ", ".join(from_addrs))
    if from_name and (RE_EMAIL_IN_TEXT.search(from_name) or RE_DOMAIN_LIKE.search(from_name)):
        add("high", "Display name contains an email address or domain (display-name spoofing)", from_name[:200])
    if from_domain in FREEMAIL_DOMAINS and from_name and " " in from_name.strip():
        add("info", "Free webmail sender with a personal display name; check against the org directory for name impersonation",
            f"{from_name} <{from_addr}>")
    if org_domains:
        for label, dom in (("From", from_domain), ("Reply-To", reply_domains[0] if reply_domains else ""),
                           ("Return-Path", rp_domain)):
            hit = lookalike_of(dom, org_domains)
            if hit:
                add("high", f"{label} domain looks like a lookalike of {hit}", dom)
        if from_domain in org_domains and other["x_ms_exchange_authas"] and other["x_ms_exchange_authas"].lower() == "anonymous":
            add("high", "From is our own domain but Exchange marked the connection Anonymous (external spoof of internal sender)")
        if from_domain in org_domains and spf in {"fail", "softfail", "none"}:
            add("high", "Mail claiming to be from our own domain failed SPF")
    for hop in received:
        if hop["delay_seconds"] is not None and hop["delay_seconds"] < -60:
            add("info", f"Hop {hop['hop']} timestamp is earlier than the previous hop ({hop['delay_seconds']}s): clock skew or forged Received header")
        if hop["delay_seconds"] is not None and hop["delay_seconds"] > 3600:
            add("info", f"Hop {hop['hop']} delayed {hop['delay_seconds'] // 60} min (queueing, greylisting, or a stale relay)")
        if hop.get("with") and hop["with"].upper().endswith("A") and hop["with"].upper().startswith("ESMTP") and hop["ip_scope"] in {"public", "documentation"}:
            add("info", f"Hop {hop['hop']}: authenticated submission (ESMTPA) from {hop['from_ip']} to {hop['by_host']}; the relay's account may be compromised or attacker-owned")
    if date_hdr and first_hop_ts:
        try:
            diff = abs((datetime.strptime(first_hop_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - date_hdr).total_seconds())
            if diff > 86400:
                add("info", f"Date header differs from first Received timestamp by {int(diff // 3600)} h")
        except ValueError:
            pass
    for u in urls:
        for f in u["flags"]:
            sev = "high" if f in {"link_text_mismatch", "userinfo_in_url", "data_uri", "javascript_uri"} else "medium"
            add(sev, f"URL flag {f}", u["url"][:160])
        if u["source"] == "html-form-action":
            add("high", "HTML form posts to a remote URL (credential form in the email body)", u["url"][:160])
    for f in html_flags:
        sev = "high" if f in {"password_input", "form_tag", "blob_download_api", "obfuscated_js", "script_tag"} else "medium"
        add(sev, f"HTML body: {f}")
    for a in attachments:
        for f in a["flags"]:
            sev = "high" if f.startswith(("dangerous", "executable", "html_attachment", "double")) else "medium"
            if f.startswith("inline_image"):
                sev = "info"
            add(sev, f"Attachment {a['filename'] or a['content_type']}: {f}", a["sha256"])
        for f in a.get("html_flags", []):
            add("high" if f in {"password_input", "form_tag", "blob_download_api", "obfuscated_js", "script_tag"} else "medium",
                f"Attachment {a['filename'] or a['content_type']} HTML: {f}")
        for u in a.get("urls", []):
            if u["source"] == "html-form-action":
                add("high", f"Attachment {a['filename'] or a['content_type']} contains a form posting to a remote URL", u["url"][:160])
    if phones and ("callback-toad" in lure_hits or not urls):
        add("medium", "Phone number(s) in body with callback-style wording; possible TOAD lure", ", ".join(phones[:5]))
    if other["in_reply_to"] and (spf in {"fail", "none"} or alignment["spf_alignment"] == "none"):
        add("medium", "Looks like a reply to an existing thread but fails/lacks authentication: possible thread hijacking")
    if urgency_hits:
        add("info", "Urgency language", ", ".join(urgency_hits[:6]))

    order = {"high": 0, "medium": 1, "info": 2}
    findings.sort(key=lambda f: order[f["severity"]])

    if defang:
        for u in urls + [x for a in attachments for x in a.get("urls", [])]:
            u["url"] = defang_url(u["url"])
            if u.get("decoded_url"):
                u["decoded_url"] = defang_url(u["decoded_url"])
        for f in findings:
            if f["detail"] and re.match(r"^(?:https?|ftp)://", f["detail"], re.I):
                f["detail"] = defang_url(f["detail"])

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "input_bytes": len(raw),
        "headers": {
            "from": {"display_name": from_name or None, "address": from_addr or None, "domain": from_domain or None},
            "sender": sender_addr or None, "reply_to": reply_to, "return_path": return_path or None,
            **other,
        },
        "alignment": alignment,
        "authentication": {"summary": auth, "all_results": auth_headers, "received_spf": received_spf,
                           "dkim_signatures": dkim_sigs},
        "received_chain": received,
        "urls": urls,
        "html_flags": html_flags,
        "body": {"parts": part_summary, "text_preview": re.sub(r"\s+", " ", (text_body or html_visible)).strip()[:600],
                 "emails_in_body": body_emails, "phone_numbers": phones},
        "attachments": attachments,
        "lure_hints": {"classes": lure_hits, "urgency": urgency_hits},
        "findings": findings,
    }


# --------------------------------------------------------------------------- render

def render_md(r: dict, defang: bool) -> str:
    h = r["headers"]
    a = r["alignment"]
    auth = r["authentication"]["summary"]
    dd = defang_domain if defang else (lambda s: s)
    lines = [f"# Email header analysis", "",
             f"Generated {r['generated_at']} from {r['input_bytes']} bytes. URLs and domains are "
             f"{'defanged' if defang else 'NOT defanged'}. Message content is untrusted data.", "",
             "## Envelope and identities", "",
             "| Field | Value |", "|---|---|",
             f"| Subject | {h['subject'] or ''} |",
             f"| Date | {h['date'] or ''} |",
             f"| From | {h['from']['display_name'] or ''} <{dd(h['from']['address'] or '')}> |",
             f"| Sender | {dd(h['sender'] or '')} |",
             f"| Reply-To | {', '.join(dd(x) for x in h['reply_to']) or ''} |",
             f"| Return-Path | {dd(h['return_path'] or '')} |",
             f"| To / Cc | {len(h['to'])} / {len(h['cc'])} |",
             f"| Message-ID | {h['message_id'] or ''} |",
             f"| X-Originating-IP | {h['x_originating_ip'] or ''} |",
             f"| X-Mailer | {h['x_mailer'] or ''} |",
             f"| In-Reply-To | {h['in_reply_to'] or ''} |",
             f"| Exchange AuthAs / SCL | {h['x_ms_exchange_authas'] or ''} / {h['x_ms_exchange_scl'] or ''} |",
             f"| Forefront report | {', '.join(f'{k}:{v}' for k, v in (h['x_forefront_antispam'] or {}).items() if k in ('CIP', 'CTRY', 'SFV', 'CAT', 'SCL', 'PTR', 'DIR')) or ''} |",
             "", "## Authentication", "",
             "| Method | Result | Properties |", "|---|---|---|"]
    for method in ("spf", "dkim", "dmarc", "arc", "compauth"):
        if method in auth:
            props = "; ".join(f"{k}={v}" for k, v in auth[method]["properties"].items())
            lines.append(f"| {method.upper()} | **{auth[method]['result']}** | {props} |")
    if not auth:
        lines.append("| (none) | | No Authentication-Results header found |")
    lines += ["", "**Alignment**", "",
              f"- From domain: `{dd(a['from_domain'] or '')}`",
              f"- Return-Path domain: `{dd(a['return_path_domain'] or '')}` -> SPF alignment: {a['spf_alignment']}",
              f"- DKIM d=: {', '.join('`' + dd(x) + '`' for x in a['dkim_domains']) or 'none'} -> DKIM alignment: {a['dkim_alignment']}",
              f"- Reply-To domains: {', '.join('`' + dd(x) + '`' for x in a['reply_to_domains']) or 'none'} -> {a['reply_to_alignment']}",
              f"- Message-ID domain: `{dd(a['message_id_domain'] or '')}` -> {a['message_id_alignment']}",
              "", "## Received chain (oldest first)", "",
              "| # | Time (UTC) | Delay | From host | rDNS/HELO | IP | Scope | By | With |", "|---|---|---|---|---|---|---|---|---|"]
    for hop in r["received_chain"]:
        delay = "" if hop["delay_seconds"] is None else f"{hop['delay_seconds']}s"
        lines.append(f"| {hop['hop']} | {hop['timestamp_utc'] or ''} | {delay} | {dd(hop['from_host'] or '')} | "
                     f"{dd(hop['from_rdns'] or '')} | {hop['from_ip'] or ''} | {hop['ip_scope'] or ''} | {dd(hop['by_host'] or '')} | {hop['with'] or ''} |")
    lines += ["", "## URLs", ""]
    if r["urls"]:
        lines += ["| URL | Source | Anchor text | Flags | Decoded |", "|---|---|---|---|---|"]
        for u in r["urls"]:
            lines.append(f"| `{u['url'][:120]}` | {u['source']} | {(u.get('anchor_text') or '')[:60]} | "
                         f"{', '.join(u['flags'])} | {(u.get('decoded_url') or '')[:100]} |")
    else:
        lines.append("None found.")
    if r["html_flags"]:
        lines += ["", f"HTML flags: {', '.join(r['html_flags'])}"]
    lines += ["", "## Attachments", ""]
    if r["attachments"]:
        lines += ["| Filename | Type | Size | Magic | SHA-256 | Flags |", "|---|---|---|---|---|---|"]
        for at in r["attachments"]:
            lines.append(f"| {at['filename'] or ''} | {at['content_type']} | {at['size']} | {at['magic']} | "
                         f"`{at['sha256'] or ''}` | {', '.join(at['flags'])} |")
    else:
        lines.append("None.")
    b = r["body"]
    lines += ["", "## Body signals", "",
              f"- Lure hints: {json.dumps(r['lure_hints']['classes']) if r['lure_hints']['classes'] else 'none'}",
              f"- Urgency: {', '.join(r['lure_hints']['urgency']) or 'none'}",
              f"- Phone numbers: {', '.join(b['phone_numbers']) or 'none'}",
              f"- Emails in body: {', '.join(dd(x) for x in b['emails_in_body']) or 'none'}",
              f"- Text preview: {b['text_preview'][:300]}",
              "", "## Findings (observations, not a verdict)", ""]
    if r["findings"]:
        for f in r["findings"]:
            lines.append(f"- **{f['severity']}**: {f['finding']}" + (f" ({f['detail']})" if f["detail"] else ""))
    else:
        lines.append("- No automated findings. Absence of findings is not evidence of legitimacy.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help=".eml file path, or - for raw message/headers on stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--org-domain", action="append", default=[], metavar="DOMAIN",
                    help="your own domain(s); enables lookalike and internal-spoof checks (repeatable)")
    ap.add_argument("--no-defang", action="store_true", help="emit live URLs/domains (default: defanged)")
    ap.add_argument("--extract-dir", type=Path, help="write each attachment to DIR/<sha256>.bin (opt-in; no extension so nothing auto-opens)")
    args = ap.parse_args(argv)

    if args.input == "-":
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    else:
        p = Path(args.input)
        if not p.is_file():
            print(f"error: {p} is not a file", file=sys.stderr)
            return 2
        with p.open("rb") as fh:
            raw = fh.read(MAX_INPUT_BYTES + 1)
    if not raw.strip():
        print("error: empty input", file=sys.stderr)
        return 2
    if len(raw) > MAX_INPUT_BYTES:
        print(f"error: input exceeds {MAX_INPUT_BYTES} bytes", file=sys.stderr)
        return 2
    if args.extract_dir is not None:
        print(f"note: writing attachment bytes to {args.extract_dir} as <sha256>.bin; treat as hostile", file=sys.stderr)

    org_domains = [d.lower().strip() for d in args.org_domain if d.strip()]
    try:
        result = analyze(raw, org_domains=org_domains, defang=not args.no_defang, extract_dir=args.extract_dir)
    except Exception as exc:  # malformed input should be reported, not tracebacked
        print(f"error: could not parse message: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        sys.stdout.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(render_md(result, defang=not args.no_defang))
    return 0


if __name__ == "__main__":
    sys.exit(main())
