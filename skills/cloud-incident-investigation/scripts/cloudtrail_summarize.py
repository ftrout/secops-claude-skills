#!/usr/bin/env python3
"""Summarize AWS CloudTrail records for an investigation.

Reads CloudTrail JSON in any of the shapes you actually get handed:
  * the native ``{"Records": [...]}`` object that S3 delivery writes
  * a bare JSON array of event records
  * JSON Lines (one record per line, e.g. exported from Athena or a SIEM)
  * ``.json.gz`` files, and directories of any mix of the above (recursive)

It then answers the first questions an investigator asks: who did what, from
where, how often, what failed, and which of the events are the ones that
typically matter (key creation, logging tampering, policy changes, role
chaining, console logins without MFA, secret reads, ...).

Standard library only. Read-only. Never touches the network.

Usage:
    python cloudtrail_summarize.py events.json
    python cloudtrail_summarize.py ./trail-export/ --format json
    cat events.jsonl | python cloudtrail_summarize.py - --format md --top 15
    python cloudtrail_summarize.py events.json --identity "arn:aws:iam::123456789012:user/alice"
    python cloudtrail_summarize.py events.json --from 2026-09-01T00:00:00Z --to 2026-09-02T00:00:00Z
    python cloudtrail_summarize.py events.json --high-risk my_list.txt      # one eventName per line
    python cloudtrail_summarize.py events.json --extra-risk GetObject,ListBuckets

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

# --------------------------------------------------------------------------- defaults

# Event names that are worth a human look in almost every investigation. Grouped by
# why they matter so the report can say so. Teams extend or replace this with
# --high-risk / --extra-risk (see references/environment.md).
DEFAULT_HIGH_RISK: dict[str, str] = {
    # credential / identity creation and escalation
    "CreateAccessKey": "new long-lived credential",
    "CreateLoginProfile": "console password set on a user",
    "UpdateLoginProfile": "console password changed",
    "CreateUser": "new IAM principal",
    "AttachUserPolicy": "privilege change",
    "AttachRolePolicy": "privilege change",
    "AttachGroupPolicy": "privilege change",
    "PutUserPolicy": "inline privilege change",
    "PutRolePolicy": "inline privilege change",
    "PutGroupPolicy": "inline privilege change",
    "CreatePolicyVersion": "managed policy rewritten",
    "SetDefaultPolicyVersion": "policy version swap (classic escalation)",
    "UpdateAssumeRolePolicy": "role trust policy changed",
    "AddUserToGroup": "group membership change",
    "DeactivateMFADevice": "MFA removed",
    "DeleteVirtualMFADevice": "MFA removed",
    "CreateSAMLProvider": "federation trust added",
    "UpdateSAMLProvider": "federation trust changed",
    "CreateOpenIDConnectProvider": "federation trust added",
    # logging and detection tampering
    "StopLogging": "CloudTrail disabled",
    "DeleteTrail": "CloudTrail deleted",
    "UpdateTrail": "CloudTrail reconfigured",
    "PutEventSelectors": "CloudTrail data events changed",
    "DeleteFlowLogs": "VPC flow logs removed",
    "DeleteLogGroup": "CloudWatch logs removed",
    "DeleteLogStream": "CloudWatch logs removed",
    "DisableAlarmActions": "alarm silenced",
    "DeleteAlarms": "alarm removed",
    "DeleteDetector": "GuardDuty disabled",
    "UpdateDetector": "GuardDuty reconfigured",
    "DeleteMembers": "GuardDuty members removed",
    "DisassociateFromMasterAccount": "GuardDuty delegation broken",
    "StopConfigurationRecorder": "AWS Config disabled",
    "DeleteConfigurationRecorder": "AWS Config removed",
    "DisableSecurityHub": "Security Hub disabled",
    "DeleteRule": "EventBridge rule removed",
    "DisableRule": "EventBridge rule disabled",
    # data exposure and exfiltration set-up
    "PutBucketPolicy": "bucket policy changed",
    "PutBucketAcl": "bucket ACL changed",
    "DeleteBucketPolicy": "bucket policy removed",
    "PutBucketPublicAccessBlock": "public access block changed",
    "DeletePublicAccessBlock": "public access block removed",
    "PutBucketVersioning": "versioning changed (ransom prep)",
    "PutBucketLifecycle": "lifecycle changed (ransom prep)",
    "PutBucketLifecycleConfiguration": "lifecycle changed (ransom prep)",
    "ModifySnapshotAttribute": "snapshot shared",
    "ModifyImageAttribute": "AMI shared",
    "ModifyDBSnapshotAttribute": "RDS snapshot shared",
    "ModifyDBClusterSnapshotAttribute": "RDS snapshot shared",
    "CreateSnapshot": "snapshot created (possible staging)",
    "CopySnapshot": "snapshot copied (possible exfil)",
    "GetSecretValue": "secret read",
    "BatchGetSecretValue": "bulk secret read",
    "GetParameter": "SSM parameter read",
    "GetParameters": "SSM parameter read",
    "GetParametersByPath": "SSM parameter enumeration",
    "Decrypt": "KMS decrypt",
    "ScheduleKeyDeletion": "KMS key deletion scheduled",
    "DisableKey": "KMS key disabled",
    "PutKeyPolicy": "KMS key policy changed",
    # execution and persistence
    "RunInstances": "compute launched",
    "SendCommand": "SSM command executed on instance",
    "StartSession": "SSM session opened",
    "ModifyInstanceAttribute": "instance user data / attributes changed",
    "CreateFunction20150331": "Lambda created",
    "UpdateFunctionCode20150331v2": "Lambda code changed",
    "UpdateFunctionConfiguration20150331v2": "Lambda config changed",
    "AuthorizeSecurityGroupIngress": "inbound rule opened",
    "AuthorizeSecurityGroupEgress": "outbound rule opened",
    "CreateKeyPair": "SSH key pair created",
    "ImportKeyPair": "SSH key pair imported",
    "CreateNetworkAclEntry": "NACL changed",
    "ReplaceNetworkAclEntry": "NACL changed",
    # account and org
    "LeaveOrganization": "account left org (SCP bypass)",
    "DetachPolicy": "SCP / org policy detached",
    "UpdateAccountPasswordPolicy": "password policy weakened?",
    "PutAccountPublicAccessBlock": "account-wide public access block changed",
    # sign-in
    "ConsoleLogin": "console sign-in",
    "GetFederationToken": "federation token minted",
    "GetSessionToken": "temporary creds minted",
    "AssumeRoleWithSAML": "federated role assumption",
    "AssumeRoleWithWebIdentity": "web identity role assumption",
}

# Read-only enumeration that is noisy on its own but meaningful in bursts from
# one identity (a recon phase looks like this).
RECON_EVENTS = {
    "ListBuckets", "ListUsers", "ListRoles", "ListAccessKeys", "ListAttachedUserPolicies",
    "ListAttachedRolePolicies", "GetAccountAuthorizationDetails", "DescribeInstances",
    "DescribeSecurityGroups", "DescribeSnapshots", "ListSecrets", "DescribeParameters",
    "ListFunctions20150331", "ListKeys", "ListAliases", "GetCallerIdentity", "DescribeTrails",
    "GetBucketPolicy", "GetBucketAcl", "ListTables", "DescribeDBInstances", "ListStacks",
}

MAX_RECORDS_DEFAULT = 2_000_000
MAX_LINE_BYTES = 2_000_000  # a single CloudTrail record larger than this is not a record

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?$")


# --------------------------------------------------------------------------- input

def _iter_json_text(text: str, label: str) -> Iterator[dict]:
    """Yield records from a JSON document or JSON Lines text."""
    stripped = text.lstrip()
    if not stripped:
        return
    if stripped[0] in "{[":
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("Records"), list):
            for rec in doc["Records"]:
                if isinstance(rec, dict):
                    yield rec
            return
        if isinstance(doc, list):
            for rec in doc:
                if isinstance(rec, dict):
                    yield rec
            return
        if isinstance(doc, dict) and "eventName" in doc:
            yield doc
            return
    # Fall through to JSON Lines. Each line must be its own object.
    bad = 0
    for line in io.StringIO(text):
        line = line.strip()
        if not line or len(line) > MAX_LINE_BYTES:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(rec, dict):
            # Some exports wrap the record: {"Records":[...]} per line, or {"_source": {...}}
            if isinstance(rec.get("Records"), list):
                for r in rec["Records"]:
                    if isinstance(r, dict):
                        yield r
            elif isinstance(rec.get("_source"), dict):
                yield rec["_source"]
            else:
                yield rec
    if bad:
        print(f"warning: {label}: skipped {bad} unparseable line(s)", file=sys.stderr)


def _read_path(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as fh:
            return fh.read().decode("utf-8", errors="replace")
    return path.read_text(encoding="utf-8", errors="replace")


def iter_records(inputs: list[str]) -> Iterator[dict]:
    for item in inputs:
        if item == "-":
            yield from _iter_json_text(sys.stdin.read(), "stdin")
            continue
        p = Path(item)
        if p.is_dir():
            files = sorted(f for f in p.rglob("*") if f.is_file()
                           and (f.suffix in {".json", ".jsonl", ".ndjson"} or f.name.endswith(".json.gz")
                                or f.name.endswith(".jsonl.gz")))
            for f in files:
                yield from _iter_json_text(_read_path(f), str(f))
        elif p.is_file():
            yield from _iter_json_text(_read_path(p), str(p))
        else:
            raise FileNotFoundError(item)


# --------------------------------------------------------------------------- normalize

def parse_time(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str) or not _ISO_RE.match(value):
        return None
    v = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def identity_label(rec: dict) -> tuple[str, str]:
    """Return (label, type) for the calling identity.

    For AssumedRole sessions the ARN already contains role name and session name,
    which is what you want to pivot on. For everything else prefer the ARN, then
    userName, then principalId.
    """
    ui = rec.get("userIdentity") or {}
    if not isinstance(ui, dict):
        return ("<unknown>", "Unknown")
    itype = str(ui.get("type") or "Unknown")
    arn = ui.get("arn")
    if arn:
        return (str(arn), itype)
    name = ui.get("userName") or ui.get("principalId") or ui.get("invokedBy") or ui.get("accountId")
    if itype == "AWSService":
        name = ui.get("invokedBy") or name
    return (str(name or "<unknown>"), itype)


def mfa_flag(rec: dict) -> str:
    """'yes' / 'no' / '' depending on what the record tells us."""
    add = rec.get("additionalEventData") or {}
    if isinstance(add, dict) and "MFAUsed" in add:
        return "yes" if str(add.get("MFAUsed")).lower() == "yes" else "no"
    ui = rec.get("userIdentity") or {}
    attrs = ((ui.get("sessionContext") or {}).get("attributes") or {}) if isinstance(ui, dict) else {}
    if isinstance(attrs, dict) and "mfaAuthenticated" in attrs:
        return "yes" if str(attrs.get("mfaAuthenticated")).lower() == "true" else "no"
    return ""


def session_issuer(rec: dict) -> str | None:
    ui = rec.get("userIdentity") or {}
    if not isinstance(ui, dict):
        return None
    issuer = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
    if isinstance(issuer, dict) and issuer.get("arn"):
        return str(issuer["arn"])
    return None


def _short(value: object, width: int = 80) -> str:
    s = str(value) if value is not None else ""
    s = s.replace("\n", " ").replace("|", "\\|")
    return s if len(s) <= width else s[: width - 3] + "..."


# --------------------------------------------------------------------------- summarize

def summarize(records: Iterable[dict], *, high_risk: dict[str, str], top: int,
              since: datetime | None, until: datetime | None, identity_filter: str | None,
              ip_filter: str | None, max_records: int) -> dict:
    by_identity: Counter[str] = Counter()
    identity_type: dict[str, str] = {}
    identity_first: dict[str, datetime] = {}
    identity_last: dict[str, datetime] = {}
    identity_ips: dict[str, Counter[str]] = defaultdict(Counter)
    identity_errors: Counter[str] = Counter()
    identity_recon: Counter[str] = Counter()
    identity_events: dict[str, Counter[str]] = defaultdict(Counter)
    by_event: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    by_ip: Counter[str] = Counter()
    ip_identities: dict[str, set[str]] = defaultdict(set)
    by_error: Counter[str] = Counter()
    by_agent: Counter[str] = Counter()
    by_region: Counter[str] = Counter()
    by_account: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    error_examples: dict[str, Counter[str]] = defaultdict(Counter)
    hits: list[dict] = []
    console_logins: list[dict] = []
    assume_roles: list[dict] = []
    role_chains: Counter[tuple[str, str]] = Counter()
    secret_reads: Counter[str] = Counter()
    first: datetime | None = None
    last: datetime | None = None
    total = 0
    skipped_time = 0

    for rec in records:
        if total >= max_records:
            print(f"warning: stopped after {max_records} records (--max-records)", file=sys.stderr)
            break
        ts = parse_time(rec.get("eventTime"))
        if since and (ts is None or ts < since):
            skipped_time += 1
            continue
        if until and (ts is None or ts > until):
            skipped_time += 1
            continue
        ident, itype = identity_label(rec)
        ip = str(rec.get("sourceIPAddress") or "")
        if identity_filter and identity_filter.lower() not in ident.lower():
            continue
        if ip_filter and ip_filter != ip:
            continue
        total += 1

        event = str(rec.get("eventName") or "")
        source = str(rec.get("eventSource") or "")
        err = rec.get("errorCode")
        agent = str(rec.get("userAgent") or "")
        region = str(rec.get("awsRegion") or "")
        account = str(rec.get("recipientAccountId") or (rec.get("userIdentity") or {}).get("accountId") or "")

        if ts:
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            if ident not in identity_first or ts < identity_first[ident]:
                identity_first[ident] = ts
            if ident not in identity_last or ts > identity_last[ident]:
                identity_last[ident] = ts

        by_identity[ident] += 1
        identity_type[ident] = itype
        identity_ips[ident][ip] += 1
        identity_events[ident][event] += 1
        by_event[event] += 1
        by_source[source] += 1
        by_ip[ip] += 1
        ip_identities[ip].add(ident)
        by_agent[agent] += 1
        by_region[region] += 1
        by_account[account] += 1
        by_type[itype] += 1
        if err:
            by_error[str(err)] += 1
            identity_errors[ident] += 1
            error_examples[str(err)][event] += 1
        if event in RECON_EVENTS:
            identity_recon[ident] += 1

        ts_s = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else str(rec.get("eventTime") or "")

        if event == "ConsoleLogin":
            resp = rec.get("responseElements") or {}
            outcome = resp.get("ConsoleLogin") if isinstance(resp, dict) else None
            console_logins.append({
                "time": ts_s, "identity": ident, "ip": ip, "mfa": mfa_flag(rec),
                "outcome": str(outcome or err or ""), "user_agent": agent,
            })
        if event in {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}:
            params = rec.get("requestParameters") or {}
            target = params.get("roleArn") if isinstance(params, dict) else None
            assume_roles.append({
                "time": ts_s, "caller": ident, "caller_type": itype, "target_role": str(target or ""),
                "ip": ip, "error": str(err or ""),
            })
            if target and itype == "AssumedRole":
                role_chains[(ident.split("/")[1] if "/" in ident else ident, str(target))] += 1
        if event in {"GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters",
                     "GetParametersByPath", "Decrypt"}:
            secret_reads[ident] += 1

        if event in high_risk:
            params = rec.get("requestParameters")
            hits.append({
                "time": ts_s, "event": event, "why": high_risk[event], "identity": ident,
                "identity_type": itype, "ip": ip, "error": str(err or ""), "region": region,
                "mfa": mfa_flag(rec) if event == "ConsoleLogin" else "",
                "params": _short(json.dumps(params, sort_keys=True) if params else "", 160),
            })

    hits.sort(key=lambda h: h["time"])

    def _top(counter: Counter, n: int) -> list[dict]:
        return [{"value": k, "count": v} for k, v in counter.most_common(n)]

    identities = []
    for ident, count in by_identity.most_common():
        identities.append({
            "identity": ident, "type": identity_type[ident], "events": count,
            "errors": identity_errors[ident], "recon_events": identity_recon[ident],
            "secret_reads": secret_reads[ident],
            "distinct_ips": len(identity_ips[ident]),
            "top_ips": [ip for ip, _ in identity_ips[ident].most_common(3)],
            "first_seen": identity_first[ident].strftime("%Y-%m-%dT%H:%M:%SZ") if ident in identity_first else "",
            "last_seen": identity_last[ident].strftime("%Y-%m-%dT%H:%M:%SZ") if ident in identity_last else "",
            "top_events": [e for e, _ in identity_events[ident].most_common(5)],
        })

    ips = []
    for ip, count in by_ip.most_common(top):
        ips.append({"ip": ip, "events": count, "distinct_identities": len(ip_identities[ip])})

    errors = []
    for code, count in by_error.most_common(top):
        errors.append({"error": code, "count": count,
                       "top_events": [e for e, _ in error_examples[code].most_common(3)]})

    return {
        "records": total,
        "skipped_outside_window": skipped_time,
        "first_event": first.strftime("%Y-%m-%dT%H:%M:%SZ") if first else "",
        "last_event": last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else "",
        "accounts": _top(by_account, top),
        "regions": _top(by_region, top),
        "identity_types": _top(by_type, top),
        "identities": identities,
        "events": _top(by_event, top),
        "event_sources": _top(by_source, top),
        "source_ips": ips,
        "errors": errors,
        "user_agents": _top(by_agent, top),
        "console_logins": console_logins,
        "assume_role_events": assume_roles,
        "role_chains": [{"from_role": a, "to_role": b, "count": c} for (a, b), c in role_chains.most_common()],
        "high_risk_hits": hits,
        "high_risk_event_counts": _top(Counter(h["event"] for h in hits), 100),
    }


# --------------------------------------------------------------------------- render

def render_md(s: dict, top: int) -> str:
    out: list[str] = []
    out.append("# CloudTrail summary")
    out.append("")
    out.append(f"- Records analysed: **{s['records']}**"
               + (f" (skipped {s['skipped_outside_window']} outside time window)" if s["skipped_outside_window"] else ""))
    out.append(f"- Time span (UTC): {s['first_event'] or '?'} to {s['last_event'] or '?'}")
    out.append("- Accounts: " + ", ".join(f"{a['value'] or '?'} ({a['count']})" for a in s["accounts"]))
    out.append("- Regions: " + ", ".join(f"{r['value'] or '?'} ({r['count']})" for r in s["regions"]))
    out.append("- Identity types: " + ", ".join(f"{t['value']} ({t['count']})" for t in s["identity_types"]))
    out.append("")

    out.append(f"## High-risk events ({len(s['high_risk_hits'])})")
    out.append("")
    if s["high_risk_hits"]:
        out.append("| Time (UTC) | Event | Why it matters | Identity | Source IP | Error | Params |")
        out.append("|---|---|---|---|---|---|---|")
        for h in s["high_risk_hits"][: top * 4]:
            mfa = f" (MFA: {h['mfa']})" if h["mfa"] else ""
            out.append(f"| {h['time']} | `{h['event']}` | {h['why']}{mfa} | `{_short(h['identity'], 70)}` "
                       f"| {h['ip']} | {h['error']} | {_short(h['params'], 100)} |")
        if len(s["high_risk_hits"]) > top * 4:
            out.append(f"| ... | {len(s['high_risk_hits']) - top * 4} more; use --format json | | | | | |")
    else:
        out.append("_None of the configured high-risk event names appeared._")
    out.append("")

    out.append("## Identities")
    out.append("")
    out.append("| Identity | Type | Events | Errors | Recon | Secret reads | IPs | First seen | Last seen | Top events |")
    out.append("|---|---|---|---|---|---|---|---|---|---|")
    for i in s["identities"][:top]:
        out.append(f"| `{_short(i['identity'], 70)}` | {i['type']} | {i['events']} | {i['errors']} | {i['recon_events']} "
                   f"| {i['secret_reads']} | {i['distinct_ips']} ({', '.join(i['top_ips'])}) | {i['first_seen']} "
                   f"| {i['last_seen']} | {', '.join(i['top_events'])} |")
    out.append("")

    if s["console_logins"]:
        out.append(f"## Console logins ({len(s['console_logins'])})")
        out.append("")
        out.append("| Time (UTC) | Identity | Source IP | MFA | Outcome | User agent |")
        out.append("|---|---|---|---|---|---|")
        for c in s["console_logins"][: top * 2]:
            out.append(f"| {c['time']} | `{_short(c['identity'], 60)}` | {c['ip']} | {c['mfa'] or '?'} "
                       f"| {c['outcome']} | {_short(c['user_agent'], 50)} |")
        out.append("")

    if s["assume_role_events"]:
        out.append(f"## Role assumptions ({len(s['assume_role_events'])})")
        out.append("")
        out.append("| Time (UTC) | Caller | Caller type | Target role | Source IP | Error |")
        out.append("|---|---|---|---|---|---|")
        for a in s["assume_role_events"][: top * 2]:
            out.append(f"| {a['time']} | `{_short(a['caller'], 60)}` | {a['caller_type']} | `{_short(a['target_role'], 60)}` "
                       f"| {a['ip']} | {a['error']} |")
        if s["role_chains"]:
            out.append("")
            out.append("Role chains (an assumed-role session assuming another role):")
            for rc in s["role_chains"]:
                out.append(f"- `{rc['from_role']}` -> `{rc['to_role']}` ({rc['count']}x)")
        out.append("")

    out.append("## Event names")
    out.append("")
    out.append("| Event | Count |")
    out.append("|---|---|")
    for e in s["events"]:
        out.append(f"| `{e['value']}` | {e['count']} |")
    out.append("")

    out.append("## Source IPs")
    out.append("")
    out.append("| Source IP | Events | Distinct identities |")
    out.append("|---|---|---|")
    for ip in s["source_ips"]:
        out.append(f"| {ip['ip']} | {ip['events']} | {ip['distinct_identities']} |")
    out.append("")

    out.append("## Errors")
    out.append("")
    if s["errors"]:
        out.append("| Error code | Count | Top events |")
        out.append("|---|---|---|")
        for e in s["errors"]:
            out.append(f"| {e['error']} | {e['count']} | {', '.join(e['top_events'])} |")
    else:
        out.append("_No errors._")
    out.append("")

    out.append("## User agents")
    out.append("")
    out.append("| User agent | Count |")
    out.append("|---|---|")
    for a in s["user_agents"]:
        out.append(f"| {_short(a['value'], 90)} | {a['count']} |")
    out.append("")

    out.append("## Event sources")
    out.append("")
    out.append("| Source | Count |")
    out.append("|---|---|")
    for e in s["event_sources"]:
        out.append(f"| {e['value']} | {e['count']} |")
    return "\n".join(out)


# --------------------------------------------------------------------------- cli

def _load_risk_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, why = line.partition(",")
        result[name.strip()] = why.strip() or "listed in high-risk file"
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="file(s), directory(ies), or - for stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--top", type=int, default=20, help="rows per table (default 20)")
    ap.add_argument("--from", dest="since", help="only events at/after this ISO 8601 UTC time")
    ap.add_argument("--to", dest="until", help="only events at/before this ISO 8601 UTC time")
    ap.add_argument("--identity", help="only events whose identity label contains this substring")
    ap.add_argument("--ip", help="only events from this exact sourceIPAddress")
    ap.add_argument("--high-risk", type=Path,
                    help="file of eventName[,reason] lines that REPLACES the built-in high-risk list")
    ap.add_argument("--extra-risk", help="comma-separated eventNames to ADD to the high-risk list")
    ap.add_argument("--max-records", type=int, default=MAX_RECORDS_DEFAULT,
                    help=f"stop after this many records (default {MAX_RECORDS_DEFAULT})")
    args = ap.parse_args(argv)

    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None
    if (args.since and since is None) or (args.until and until is None):
        print("error: --from/--to must be ISO 8601, e.g. 2026-09-01T00:00:00Z", file=sys.stderr)
        return 2
    if args.top < 1:
        print("error: --top must be >= 1", file=sys.stderr)
        return 2

    high_risk = dict(DEFAULT_HIGH_RISK)
    if args.high_risk:
        if not args.high_risk.is_file():
            print(f"error: {args.high_risk} is not a file", file=sys.stderr)
            return 2
        high_risk = _load_risk_file(args.high_risk)
    if args.extra_risk:
        for name in args.extra_risk.split(","):
            if name.strip():
                high_risk.setdefault(name.strip(), "added via --extra-risk")

    try:
        summary = summarize(iter_records(args.inputs), high_risk=high_risk, top=args.top,
                            since=since, until=until, identity_filter=args.identity, ip_filter=args.ip,
                            max_records=args.max_records)
    except FileNotFoundError as exc:
        print(f"error: {exc} does not exist", file=sys.stderr)
        return 2
    except (OSError, gzip.BadGzipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if summary["records"] == 0:
        print("warning: no CloudTrail records found in input", file=sys.stderr)

    if args.format == "json":
        sys.stdout.write(json.dumps(summary, indent=2))
    else:
        sys.stdout.write(render_md(summary, args.top))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
