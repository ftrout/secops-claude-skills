#!/usr/bin/env python3
"""Lint Sigma rules without any third-party dependency.

Parses the subset of YAML that Sigma rules use (block mappings, block and flow
sequences, quoted/plain scalars, `|`/`>` block scalars, comments, `---`
document separators) with a small tolerant parser, then checks each rule
against the Sigma specification (v2.0, 2024) and common review findings:

  * title present and <= 256 characters
  * id present and a UUID
  * status is one of stable/test/experimental/deprecated/unsupported
  * description present and not a placeholder
  * logsource has at least one of category/product/service
  * detection has a condition, every identifier in the condition exists,
    every selection is referenced, and no selection is wildcard-only
  * field modifiers are known Sigma modifiers; `|re` values compile
  * level is one of informational/low/medium/high/critical
  * tags use the attack.tNNNN(.NNN) / attack.<tactic> / cve. / car. /
    detection. / tlp. namespaces, lower-case
  * date / modified use YYYY-MM-DD (YYYY/MM/DD accepted with a note)
  * falsepositives present and non-empty
  * author and references present (warning only)

Usage:
    python sigma_lint.py rule.yml
    python sigma_lint.py rules/ --format json
    cat rule.yml | python sigma_lint.py -
    python sigma_lint.py rules/ --strict        # warnings fail the run

Exit codes: 0 all rules pass, 1 at least one rule has errors (or warnings
with --strict), 2 input could not be read or parsed.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2_000_000
MAX_LINES = 20_000

# --------------------------------------------------------------------------- yaml subset


class YamlError(ValueError):
    pass


@dataclass
class _Line:
    indent: int
    text: str  # stripped of leading whitespace, comments NOT removed
    no: int


_KEY_RE = re.compile(r"""^(?P<key>"[^"]{0,200}"|'[^']{0,200}'|[^\s"'#\-\[\{][^:#]{0,200}?)\s*:(?:\s+(?P<val>.*))?$""")
_INT_RE = re.compile(r"^-?\d{1,18}$")
_FLOAT_RE = re.compile(r"^-?\d{1,18}\.\d{1,18}$")


def _strip_comment(s: str) -> str:
    """Remove a trailing ` # comment` that is outside quotes."""
    in_s = in_d = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _unquote_double(s: str) -> str:
    out: list[str] = []
    i = 1
    esc = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0"}
    while i < len(s) - 1:
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) - 1:
            nxt = s[i + 1]
            out.append(esc.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "":
        return None
    if s[0] == '"':
        if len(s) >= 2 and s[-1] == '"':
            return _unquote_double(s)
        return s.strip('"')
    if s[0] == "'":
        if len(s) >= 2 and s[-1] == "'":
            return s[1:-1].replace("''", "'")
        return s.strip("'")
    if s in ("~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(s):
        return int(s)
    if _FLOAT_RE.match(s):
        return float(s)
    return s


def _split_flow(body: str) -> list[str]:
    """Split the inside of `[a, 'b, c', d]` on top-level commas."""
    items: list[str] = []
    cur: list[str] = []
    in_s = in_d = False
    depth = 0
    for ch in body:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                items.append("".join(cur))
                cur = []
                continue
        cur.append(ch)
    if "".join(cur).strip():
        items.append("".join(cur))
    return [i.strip() for i in items if i.strip()]


def _flow(value: str) -> Any:
    v = value.strip()
    if v.startswith("[") and v.endswith("]"):
        return [_flow(i) for i in _split_flow(v[1:-1])]
    if v.startswith("{") and v.endswith("}"):
        out: dict[str, Any] = {}
        for item in _split_flow(v[1:-1]):
            k, _, val = item.partition(":")
            out[str(_scalar(k))] = _flow(val)
        return out
    return _scalar(v)


class _Parser:
    def __init__(self, text: str):
        raw = text.splitlines()
        if len(raw) > MAX_LINES:
            raise YamlError(f"more than {MAX_LINES} lines")
        self.raw = raw
        self.lines: list[_Line] = []
        for no, ln in enumerate(raw, 1):
            if ln.strip() == "" or ln.lstrip().startswith("#"):
                continue
            stripped = ln.lstrip(" ")
            self.lines.append(_Line(len(ln) - len(stripped), stripped.rstrip("\r"), no))
        self.i = 0

    # -- helpers
    def _peek(self) -> _Line | None:
        return self.lines[self.i] if self.i < len(self.lines) else None

    def parse(self) -> Any:
        if not self.lines:
            return None
        val = self._node(self.lines[0].indent)
        if self.i < len(self.lines):
            ln = self.lines[self.i]
            raise YamlError(f"line {ln.no}: unexpected content {ln.text[:40]!r}")
        return val

    def _node(self, indent: int) -> Any:
        ln = self._peek()
        if ln is None:
            return None
        if ln.text == "-" or ln.text.startswith("- "):
            return self._sequence(indent)
        m = _KEY_RE.match(_strip_comment(ln.text))
        if m and not ln.text.startswith(("[", "{")):
            return self._mapping(indent)
        # bare scalar (possibly multi-line)
        parts = [_strip_comment(ln.text)]
        self.i += 1
        while (nxt := self._peek()) is not None and nxt.indent >= indent and not nxt.text.startswith("- "):
            if _KEY_RE.match(_strip_comment(nxt.text)):
                break
            parts.append(_strip_comment(nxt.text))
            self.i += 1
        return _scalar(" ".join(parts)) if len(parts) == 1 else " ".join(parts)

    def _block_scalar(self, header: str, parent_indent: int) -> str:
        style = header[0]
        chomp = "clip"
        if "-" in header[1:]:
            chomp = "strip"
        elif "+" in header[1:]:
            chomp = "keep"
        # consume raw lines (including blanks and '#' lines) with indent > parent
        cur = self._peek()
        start_no = cur.no if cur else len(self.raw) + 1
        # raw line index of first candidate line: the line after the header line
        idx = self._header_raw_idx
        collected: list[str] = []
        content_indent: int | None = None
        while idx < len(self.raw):
            ln = self.raw[idx]
            if ln.strip() == "":
                collected.append("")
                idx += 1
                continue
            ind = len(ln) - len(ln.lstrip(" "))
            if ind <= parent_indent:
                break
            if content_indent is None:
                content_indent = ind
            collected.append(ln[content_indent:] if ind >= content_indent else ln.lstrip(" "))
            idx += 1
        # re-sync token stream: skip logical lines whose raw number < idx+1
        while (nxt := self._peek()) is not None and nxt.no <= idx:
            self.i += 1
        del start_no
        while collected and collected[-1] == "":
            collected.pop()
        if style == ">":
            out: list[str] = []
            buf: list[str] = []
            for c in collected:
                if c == "":
                    out.append(" ".join(buf))
                    buf = []
                else:
                    buf.append(c.strip())
            out.append(" ".join(buf))
            text = "\n".join(out)
        else:
            text = "\n".join(collected)
        if chomp == "strip":
            return text.rstrip("\n")
        return text + "\n" if text else ""

    def _value_after_key(self, val: str | None, indent: int) -> Any:
        if val is None or val.strip() == "":
            nxt = self._peek()
            if nxt is None:
                return None
            if nxt.indent > indent:
                return self._node(nxt.indent)
            if nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                return self._sequence(indent)  # YAML allows a list at the key's own indent
            return None
        v = val.strip()
        if v[0] in "|>" and re.fullmatch(r"[|>][+-]?\d?|[|>]\d?[+-]?", v):
            return self._block_scalar(v, indent)
        if v[0] in "[{":
            return _flow(v)
        if v[0] in "\"'" and (len(v) == 1 or v[-1] != v[0]):
            # multi-line quoted scalar
            parts = [v]
            while (nxt := self._peek()) is not None and nxt.indent > indent:
                parts.append(nxt.text)
                self.i += 1
                if nxt.text.rstrip().endswith(v[0]):
                    break
            return _scalar(" ".join(parts))
        # plain scalar with possible continuation lines
        parts = [v]
        while (nxt := self._peek()) is not None and nxt.indent > indent and not nxt.text.startswith("- "):
            if _KEY_RE.match(_strip_comment(nxt.text)):
                break
            parts.append(_strip_comment(nxt.text))
            self.i += 1
        return _scalar(" ".join(parts))

    def _mapping(self, indent: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while (ln := self._peek()) is not None:
            if ln.indent < indent:
                break
            if ln.indent > indent:
                raise YamlError(f"line {ln.no}: unexpected indentation")
            if ln.text == "-" or ln.text.startswith("- "):
                break
            m = _KEY_RE.match(_strip_comment(ln.text))
            if not m:
                raise YamlError(f"line {ln.no}: expected `key: value`, got {ln.text[:40]!r}")
            key = str(_scalar(m.group("key")))
            self.i += 1
            self._header_raw_idx = ln.no  # raw index of the line after this one
            out[key] = self._value_after_key(m.group("val"), indent)
        return out

    def _sequence(self, indent: int) -> list[Any]:
        out: list[Any] = []
        while (ln := self._peek()) is not None:
            if ln.indent != indent or not (ln.text == "-" or ln.text.startswith("- ")):
                break
            item = ln.text[1:].lstrip(" ")
            if item == "" or item.startswith("#"):
                self.i += 1
                nxt = self._peek()
                out.append(self._node(nxt.indent) if nxt and nxt.indent > indent else None)
                continue
            offset = len(ln.text) - len(item)
            m = _KEY_RE.match(_strip_comment(item))
            if m and not item.startswith(("[", "{")):
                # inline mapping (`- key: value`): rewrite the line as if it were indented under the dash
                self.lines[self.i] = _Line(indent + offset, item, ln.no)
                out.append(self._mapping(indent + offset))
                continue
            self.i += 1
            self._header_raw_idx = ln.no
            out.append(self._value_after_key(item, indent))
        return out


def parse_yaml(text: str) -> Any:
    return _Parser(text).parse()


def split_documents(text: str) -> list[str]:
    docs: list[str] = []
    cur: list[str] = []
    for ln in text.splitlines():
        if ln.strip() == "---":
            docs.append("\n".join(cur))
            cur = []
        else:
            cur.append(ln)
    docs.append("\n".join(cur))
    return [d for d in docs if d.strip()]


# --------------------------------------------------------------------------- sigma vocab

STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TACTICS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
}
MODIFIERS = {
    "contains", "all", "startswith", "endswith", "exists", "cased", "re", "i", "m", "s",
    "cidr", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash",
    "gt", "gte", "lt", "lte", "minute", "hour", "day", "week", "month", "year",
    "fieldref", "expand",
}
KNOWN_TOP_KEYS = {
    "title", "id", "name", "related", "taxonomy", "status", "description", "license",
    "author", "references", "date", "modified", "logsource", "detection", "fields",
    "falsepositives", "level", "tags", "scope",
}
KNOWN_CATEGORIES = {
    "process_creation", "file_event", "file_change", "file_delete", "file_rename",
    "file_access", "file_executable_detected", "network_connection", "dns_query",
    "registry_event", "registry_add", "registry_set", "registry_delete", "image_load",
    "driver_load", "create_remote_thread", "process_access", "pipe_created", "wmi_event",
    "ps_script", "ps_module", "ps_classic_start", "ps_classic_provider_start",
    "raw_access_thread", "process_tampering", "process_termination", "sysmon_error",
    "sysmon_status", "create_stream_hash", "clipboard_capture", "dns", "proxy",
    "webserver", "firewall", "antivirus", "database", "application",
}
KNOWN_PRODUCTS = {
    "windows", "linux", "macos", "aws", "azure", "gcp", "m365", "okta", "github",
    "cisco", "zeek", "juniper", "paloalto", "fortios", "sql", "python", "django",
    "ruby_on_rails", "rpc_firewall", "spring", "velocity", "nodejs", "kubernetes",
    "opencanary", "modsecurity", "onelogin", "google_workspace", "bitbucket", "huawei",
    "jvm", "qualys", "sqlite", "sap", "netwrix", "apache", "nginx", "office", "rpc",
    "netflow", "syslog", "webserver", "ssh", "ldap", "dns", "smb",
}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DATE_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATE_SLASH_RE = re.compile(r"^\d{4}/\d{2}/\d{2}$")
TECHNIQUE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$")
GROUP_SW_RE = re.compile(r"^[gs]\d{4}$")
CVE_TAG_RE = re.compile(r"^\d{4}-\d{4,7}$")
CAR_TAG_RE = re.compile(r"^\d{4}-\d{2}-\d{3}$")
TLP_VALUES = {"clear", "white", "green", "amber", "amber_strict", "red"}
DETECTION_TAGS = {"dfir", "emerging_threats", "threat_hunting"}
IDENT_RE = re.compile(r"[A-Za-z0-9_*?.-]+")
WILDCARD_ONLY_RE = re.compile(r"^[*?]*$")
PLACEHOLDER_DESC = re.compile(r"^(todo|tbd|n/?a|description|detects\.?|-|\.)$", re.I)


# --------------------------------------------------------------------------- checks


@dataclass
class Finding:
    level: str  # error | warning | info
    check: str
    message: str


@dataclass
class RuleResult:
    source: str
    title: str = ""
    findings: list[Finding] = field(default_factory=list)

    def error(self, check: str, msg: str) -> None:
        self.findings.append(Finding("error", check, msg))

    def warn(self, check: str, msg: str) -> None:
        self.findings.append(Finding("warning", check, msg))

    def info(self, check: str, msg: str) -> None:
        self.findings.append(Finding("info", check, msg))

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.level == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.level == "warning")


def _is_wildcard_only(v: Any) -> bool:
    return isinstance(v, str) and WILDCARD_ONLY_RE.match(v) is not None


def _iter_values(v: Any):
    if isinstance(v, list):
        for x in v:
            yield from _iter_values(x)
    elif isinstance(v, dict):
        for x in v.values():
            yield from _iter_values(x)
    else:
        yield v


def _condition_identifiers(cond: str) -> list[str]:
    """Return selection identifiers referenced by a condition string."""
    cleaned = re.sub(r"\b(?:\d+|all)\s+of\b", " ", cond)
    cleaned = re.sub(r"\b(?:and|or|not|them)\b", " ", cleaned)
    cleaned = cleaned.replace("(", " ").replace(")", " ")
    return [t for t in IDENT_RE.findall(cleaned) if not t.isdigit()]


def _check_selection(res: RuleResult, name: str, sel: Any) -> None:
    if sel is None:
        res.error("detection", f"selection `{name}` is empty")
        return
    values = list(_iter_values(sel))
    if not values:
        res.error("detection", f"selection `{name}` has no values")
        return
    wc = [v for v in values if _is_wildcard_only(v)]
    if wc and len(wc) == len(values):
        res.error("detection", f"selection `{name}` is wildcard-only ({wc[0]!r}); it matches every event")
    elif wc:
        res.warn("detection", f"selection `{name}` contains a wildcard-only value {wc[0]!r}; use `|exists: true` if you mean 'field present'")
    if isinstance(sel, dict):
        for key, val in sel.items():
            parts = str(key).split("|")
            mods = parts[1:]
            for m in mods:
                if m not in MODIFIERS:
                    res.warn("modifier", f"unknown modifier `{m}` on `{key}` in `{name}`")
            if "all" in mods and not isinstance(val, list):
                res.warn("modifier", f"`|all` on `{key}` in `{name}` has a single value; `all` only matters for lists")
            if "re" in mods:
                for pat in (val if isinstance(val, list) else [val]):
                    if isinstance(pat, str):
                        if len(pat) > 2000:
                            res.warn("modifier", f"regex on `{key}` is very long")
                            continue
                        try:
                            re.compile(pat)
                        except re.error as exc:
                            res.error("modifier", f"regex on `{key}` in `{name}` does not compile: {exc}")
            if isinstance(val, list) and not val:
                res.error("detection", f"`{key}` in `{name}` is an empty list")
    elif isinstance(sel, list):
        for item in sel:
            if isinstance(item, dict):
                _check_selection(res, name, item)


def check_rule(rule: Any, source: str) -> RuleResult:
    res = RuleResult(source=source)
    if not isinstance(rule, dict):
        res.error("structure", "rule is not a mapping")
        return res

    for key in rule:
        if key not in KNOWN_TOP_KEYS:
            res.warn("structure", f"unknown top-level key `{key}`")

    # title
    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        res.error("title", "missing title")
    else:
        res.title = title.strip()
        if len(title) > 256:
            res.error("title", f"title is {len(title)} chars (max 256)")
        elif len(title) > 120:
            res.warn("title", "title longer than 120 chars; keep it scannable")

    # id
    rid = rule.get("id")
    if rid is None:
        res.error("id", "missing id (UUID v4)")
    elif not isinstance(rid, str) or not UUID_RE.match(rid):
        res.error("id", f"id {rid!r} is not a UUID")

    # status
    status = rule.get("status")
    if status is None:
        res.error("status", "missing status")
    elif status not in STATUSES:
        res.error("status", f"status {status!r} not in {sorted(STATUSES)}")
    elif status == "deprecated":
        res.info("status", "rule is deprecated; make sure a `related` entry points at its replacement")

    # description
    desc = rule.get("description")
    if not isinstance(desc, str) or not desc.strip():
        res.error("description", "missing description")
    elif len(desc.strip()) < 20 or PLACEHOLDER_DESC.match(desc.strip()):
        res.error("description", "description is a placeholder or too short to explain what the rule detects and why")

    # logsource
    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        res.error("logsource", "missing logsource mapping")
    else:
        if not any(k in ls for k in ("category", "product", "service")):
            res.error("logsource", "logsource needs at least one of category/product/service")
        for k in ls:
            if k not in {"category", "product", "service", "definition"}:
                res.warn("logsource", f"unexpected logsource key `{k}`")
        cat = ls.get("category")
        if cat is not None and cat not in KNOWN_CATEGORIES:
            res.warn("logsource", f"category {cat!r} is not in the common Sigma taxonomy; make sure your pipeline maps it")
        prod = ls.get("product")
        if prod is not None and prod not in KNOWN_PRODUCTS:
            res.warn("logsource", f"product {prod!r} is not in the common Sigma taxonomy; make sure your pipeline maps it")

    # detection
    det = rule.get("detection")
    if not isinstance(det, dict):
        res.error("detection", "missing detection mapping")
    else:
        cond = det.get("condition")
        selections = {k: v for k, v in det.items() if k != "condition"}
        if cond is None:
            res.error("detection", "detection has no condition")
        elif isinstance(cond, list):
            res.warn("detection", "condition is a list; multiple conditions are deprecated, combine with `or`")
            cond = " or ".join(f"({c})" for c in cond if isinstance(c, str))
        if not selections:
            res.error("detection", "detection has no selections")
        if isinstance(cond, str):
            if "|" in cond:
                res.warn("detection", "condition uses `|` aggregation, which is deprecated in Sigma v2; use a correlation rule")
            refs = _condition_identifiers(cond.split("|", 1)[0])
            used: set[str] = set()
            if re.search(r"\bthem\b", cond):
                used.update(selections)
            for ident in refs:
                if "*" in ident or "?" in ident:
                    hits = fnmatch.filter(selections.keys(), ident)
                    if not hits:
                        res.error("detection", f"condition pattern `{ident}` matches no selection")
                    used.update(hits)
                elif ident in selections:
                    used.add(ident)
                else:
                    res.error("detection", f"condition references `{ident}` which is not defined")
            for name in selections:
                if name not in used:
                    res.warn("detection", f"selection `{name}` is defined but not used in the condition")
            if re.search(r"\bnot\b", cond) and not re.search(r"\b(?:filter|exclusion|excl)", cond):
                res.info("detection", "condition uses `not`; conventional naming is `filter_*` for exclusions")
        for name, sel in selections.items():
            _check_selection(res, str(name), sel)

    # level
    level = rule.get("level")
    if level is None:
        res.error("level", "missing level")
    elif level not in LEVELS:
        res.error("level", f"level {level!r} not in {sorted(LEVELS)}")

    # tags
    tags = rule.get("tags")
    if tags is None:
        res.warn("tags", "no tags; add attack.<tactic> and attack.tNNNN so coverage can be measured")
    elif not isinstance(tags, list):
        res.error("tags", "tags must be a list")
    else:
        has_tech = has_tactic = False
        for t in tags:
            if not isinstance(t, str):
                res.error("tags", f"tag {t!r} is not a string")
                continue
            if t != t.lower():
                res.error("tags", f"tag `{t}` must be lower-case (e.g. attack.t1059.001)")
                continue
            ns, _, rest = t.partition(".")
            if ns == "attack":
                if TECHNIQUE_RE.match(rest):
                    has_tech = True
                elif rest in TACTICS:
                    has_tactic = True
                elif GROUP_SW_RE.match(rest):
                    pass
                else:
                    res.error("tags", f"tag `{t}` is not attack.tNNNN(.NNN), attack.<tactic>, attack.gNNNN or attack.sNNNN")
            elif ns == "cve":
                if not CVE_TAG_RE.match(rest):
                    res.error("tags", f"tag `{t}` should look like cve.2021-44228")
            elif ns == "car":
                if not CAR_TAG_RE.match(rest):
                    res.error("tags", f"tag `{t}` should look like car.2016-04-005")
            elif ns == "tlp":
                if rest not in TLP_VALUES:
                    res.error("tags", f"tag `{t}` has unknown TLP level")
            elif ns == "detection":
                if rest not in DETECTION_TAGS:
                    res.warn("tags", f"tag `{t}` is not one of detection.{'/'.join(sorted(DETECTION_TAGS))}")
            elif ns in {"stp", "d3fend"}:
                pass
            else:
                res.warn("tags", f"tag `{t}` uses an unknown namespace")
        if not has_tech:
            res.warn("tags", "no attack.tNNNN technique tag")
        if not has_tactic:
            res.warn("tags", "no attack.<tactic> tag")

    # dates
    for key in ("date", "modified"):
        val = rule.get(key)
        if val is None:
            if key == "date":
                res.warn("date", "no date; add the creation date (YYYY-MM-DD)")
            continue
        sval = str(val)
        if DATE_ISO_RE.match(sval):
            pass
        elif DATE_SLASH_RE.match(sval):
            res.info("date", f"{key} uses YYYY/MM/DD; Sigma v2 prefers ISO 8601 YYYY-MM-DD")
        else:
            res.error("date", f"{key} {sval!r} is not YYYY-MM-DD")

    # falsepositives
    fps = rule.get("falsepositives")
    if fps is None:
        res.error("falsepositives", "missing falsepositives; list the benign activity that will trip this rule (or `Unlikely`)")
    elif isinstance(fps, list):
        if not [f for f in fps if isinstance(f, str) and f.strip()]:
            res.error("falsepositives", "falsepositives list is empty")
    elif isinstance(fps, str):
        res.warn("falsepositives", "falsepositives should be a list")
    else:
        res.error("falsepositives", "falsepositives must be a list of strings")

    # author / references
    if not rule.get("author"):
        res.warn("author", "no author")
    refs = rule.get("references")
    if not refs:
        res.warn("references", "no references; link the report, blog, or ticket that motivated the rule")
    elif not isinstance(refs, list):
        res.warn("references", "references should be a list")

    return res


# --------------------------------------------------------------------------- io


def _read_text(path_arg: str) -> tuple[str, str]:
    if path_arg == "-":
        return sys.stdin.read()[:MAX_FILE_BYTES], "stdin"
    p = Path(path_arg)
    data = p.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        raise YamlError(f"{p}: file larger than {MAX_FILE_BYTES} bytes")
    return data.decode("utf-8", errors="replace"), str(p)


def _collect_paths(inputs: list[str]) -> list[str]:
    out: list[str] = []
    for item in inputs:
        if item == "-":
            out.append("-")
            continue
        p = Path(item)
        if p.is_dir():
            out.extend(str(f) for f in sorted(p.rglob("*")) if f.suffix.lower() in {".yml", ".yaml"} and f.is_file())
        elif p.is_file():
            out.append(str(p))
        else:
            raise FileNotFoundError(item)
    return out


def lint_paths(paths: list[str]) -> tuple[list[RuleResult], list[str]]:
    results: list[RuleResult] = []
    fatal: list[str] = []
    for path in paths:
        try:
            text, label = _read_text(path)
        except (OSError, YamlError) as exc:
            fatal.append(f"{path}: {exc}")
            continue
        docs = split_documents(text)
        if not docs:
            fatal.append(f"{label}: empty file")
            continue
        for n, doc in enumerate(docs, 1):
            src = label if len(docs) == 1 else f"{label}#{n}"
            try:
                rule = parse_yaml(doc)
            except (YamlError, RecursionError) as exc:
                fatal.append(f"{src}: YAML parse error: {exc}")
                continue
            results.append(check_rule(rule, src))
    return results, fatal


# --------------------------------------------------------------------------- render


def render_text(results: list[RuleResult], fatal: list[str], show_info: bool) -> str:
    lines: list[str] = []
    for f in fatal:
        lines.append(f"FATAL  {f}")
    for r in results:
        status = "PASS" if r.errors == 0 else "FAIL"
        lines.append(f"{status}   {r.source}  ({r.title or 'untitled'}): {r.errors} error(s), {r.warnings} warning(s)")
        for fd in r.findings:
            if fd.level == "info" and not show_info:
                continue
            lines.append(f"       {fd.level.upper():7} [{fd.check}] {fd.message}")
    total_err = sum(r.errors for r in results)
    total_warn = sum(r.warnings for r in results)
    lines.append(f"\n{len(results)} rule(s) checked, {total_err} error(s), {total_warn} warning(s), {len(fatal)} unreadable")
    return "\n".join(lines)


def render_md(results: list[RuleResult], fatal: list[str], show_info: bool) -> str:
    lines = ["| Rule | Status | Level | Check | Message |", "|---|---|---|---|---|"]
    for f in fatal:
        msg = f.replace("|", "\\|")
        lines.append(f"| {f.split(':', 1)[0]} | FATAL | error | parse | {msg} |")
    for r in results:
        status = "PASS" if r.errors == 0 else "FAIL"
        shown = [fd for fd in r.findings if show_info or fd.level != "info"]
        if not shown:
            lines.append(f"| {r.source} | {status} |  |  | clean |")
        for fd in shown:
            msg = fd.message.replace("|", "\\|")
            lines.append(f"| {r.source} | {status} | {fd.level} | {fd.check} | {msg} |")
    return "\n".join(lines)


def render_json(results: list[RuleResult], fatal: list[str], show_info: bool) -> str:
    return json.dumps({
        "unreadable": fatal,
        "rules": [{
            "source": r.source, "title": r.title, "passed": r.errors == 0,
            "errors": r.errors, "warnings": r.warnings,
            "findings": [fd.__dict__ for fd in r.findings if show_info or fd.level != "info"],
        } for r in results],
    }, indent=2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="rule files, directories (recursed for *.yml/*.yaml), or - for stdin")
    ap.add_argument("--format", choices=["text", "json", "md"], default="text")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    ap.add_argument("--no-info", action="store_true", help="hide informational notes")
    args = ap.parse_args(argv)

    try:
        paths = _collect_paths(args.inputs)
    except FileNotFoundError as exc:
        print(f"error: {exc} does not exist", file=sys.stderr)
        return 2
    if not paths:
        print("error: no .yml/.yaml files found", file=sys.stderr)
        return 2

    results, fatal = lint_paths(paths)
    renderer = {"text": render_text, "json": render_json, "md": render_md}[args.format]
    sys.stdout.write(renderer(results, fatal, show_info=not args.no_info) + "\n")

    if fatal and not results:
        return 2
    failed = any(r.errors for r in results) or (args.strict and any(r.warnings for r in results))
    return 1 if failed or fatal else 0


if __name__ == "__main__":
    sys.exit(main())
