#!/usr/bin/env python3
"""Analyze a CSV of sign-in events for account-compromise patterns.

Works on exports from Entra ID (SigninLogs), Okta (System Log), Google Workspace
(Login audit), or any SIEM, as long as the CSV has columns for user, timestamp, IP,
country, result, and optionally MFA state, user agent, app, and client app. Column
names are auto-detected from common export headers and can be overridden with
``--col``.

Per user it computes:
  * distinct IPs, countries, and user agents; countries and user agents that are
    NEW relative to a baseline period (first N days of that user's history)
  * impossible travel: consecutive successful sign-ins from different countries
    faster than a speed threshold (using a built-in country-centroid table), or
    simply within N hours when a country is not in the table
  * MFA failure bursts (MFA fatigue / push bombing) and whether a success followed
  * failed-then-success from an IP that had never succeeded for that user before
    (password spray / stuffing that landed)
  * legacy-authentication successes (IMAP/POP/SMTP/other basic-auth clients)
  * a simple risk score so the worst users float to the top

Standard library only. Read-only. No network access.

Usage:
    python signin_analyzer.py signins.csv
    python signin_analyzer.py signins.csv --format json
    cat export.csv | python signin_analyzer.py - --format md --top 10
    python signin_analyzer.py signins.csv --user alice@yourcompany.example
    python signin_analyzer.py signins.csv --col user=UserPrincipalName --col ip="IP address" \\
        --col timestamp="Date (UTC)" --col country=Location --col result=Status
    python signin_analyzer.py signins.csv --travel-hours 3 --max-kmh 800 --mfa-burst 4 --mfa-window 10

Exit code 0 on success, 2 on bad input.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_ROWS = 5_000_000
MAX_FIELD_LEN = 4096

# --------------------------------------------------------------------------- columns

# Logical column -> candidate header names, checked case-insensitively, in order.
COLUMN_ALIASES: dict[str, list[str]] = {
    "user": ["user", "userprincipalname", "user principal name", "upn", "username", "user name",
             "actor.alternateid", "actor_alternateid", "actor", "email", "principal", "account",
             "targetusername", "identity", "user_id", "userid", "user id"],
    "timestamp": ["timestamp", "time", "createddatetime", "date (utc)", "date", "published",
                  "timegenerated", "eventtime", "event_time", "_time", "datetime", "time (utc)"],
    "ip": ["ip", "ipaddress", "ip address", "ip_address", "client.ipaddress", "client_ipaddress",
           "sourceip", "source ip", "src_ip", "callerip", "clientip", "remote_ip", "ip addr"],
    "country": ["country", "location", "countryorregion", "country_or_region",
                "client.geographicalcontext.country", "client_geographicalcontext_country",
                "geo_country", "country code", "country_code", "src_country"],
    "result": ["result", "status", "resulttype", "result type", "outcome.result", "outcome_result",
               "outcome", "success", "sign-in status", "status.errorcode", "errorcode", "error code",
               "action", "eventtype", "event type", "event_type"],
    "mfa": ["mfa", "mfa result", "mfa_result", "mfaresult", "authenticationrequirement",
            "authentication requirement", "mfadetail", "multi-factor authentication result",
            "multifactor", "mfa auth method", "authentication method", "factor",
            "outcome.reason", "outcome_reason", "resultdescription", "result description"],
    "user_agent": ["user_agent", "useragent", "user agent", "client.useragent.rawuseragent",
                   "client_useragent_rawuseragent", "ua", "http_user_agent", "browser",
                   "client.useragent.browser", "device"],
    "app": ["app", "application", "appdisplayname", "app display name", "resourcedisplayname",
            "resource display name", "target", "target.displayname", "app_name", "resource"],
    "client_app": ["client_app", "clientappused", "client app used", "client app", "client_app_used",
                   "protocol", "authentication protocol", "auth_protocol", "clientapp"],
}

SUCCESS_VALUES = {"success", "succeeded", "0", "true", "ok", "allow", "allowed", "pass", "passed",
                  "login_success", "user.session.start", "sign-in success", "successful", "1"}
FAILURE_HINT_RE = re.compile(r"fail|denied|deny|block|error|invalid|locked|interrupt|expired|"
                             r"unauthori[sz]ed|reject|timeout|challenge", re.I)

# Entra ResultType codes that mean "MFA was challenged and not satisfied". 500121 is the
# push denied / timed out code; 50074 and 50076 are "MFA required" interrupts, which show
# up as failures when the user never completes the challenge.
MFA_FAIL_CODES = {"500121", "50074", "50076", "50158", "50072", "50079"}
MFA_FAIL_TEXT_RE = re.compile(r"mfa|multi.?factor|strong auth|push|otp|verification|"
                              r"authenticator|second factor|2sv|two.?step", re.I)
MFA_SATISFIED_RE = re.compile(r"multifactorauthentication|mfa.*(success|satisfied|complet|verified)|"
                              r"auth_via_mfa|(success|satisfied|complet|verified).*mfa|^yes$|^true$|^mfa$", re.I)

LEGACY_RE = re.compile(r"\b(imap4?|pop3?|smtp|authenticated smtp|other clients|"
                       r"exchange activesync|activesync|mapi over http|outlook anywhere|"
                       r"offline address book|exchange web services|ews|autodiscover|"
                       r"reporting web services|bav2ropc)\b", re.I)

# --------------------------------------------------------------------------- countries

# Approximate centroids (lat, lon) for common countries, ISO 3166-1 alpha-2. Accuracy of a few
# hundred km is fine: the check is "could a person have flown this far in this time".
CENTROIDS: dict[str, tuple[float, float]] = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "MX": (23.6, -102.6), "BR": (-14.2, -51.9),
    "AR": (-38.4, -63.6), "CL": (-35.7, -71.5), "CO": (4.6, -74.3), "PE": (-9.2, -75.0),
    "GB": (54.0, -2.5), "IE": (53.4, -8.2), "FR": (46.2, 2.2), "DE": (51.2, 10.4),
    "NL": (52.1, 5.3), "BE": (50.5, 4.5), "LU": (49.8, 6.1), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "ES": (40.5, -3.7), "PT": (39.4, -8.2), "IT": (41.9, 12.6), "GR": (39.1, 21.8),
    "SE": (60.1, 18.6), "NO": (60.5, 8.5), "DK": (56.3, 9.5), "FI": (61.9, 25.7), "IS": (64.9, -19.0),
    "PL": (51.9, 19.1), "CZ": (49.8, 15.5), "SK": (48.7, 19.7), "HU": (47.2, 19.5),
    "RO": (45.9, 25.0), "BG": (42.7, 25.5), "UA": (48.4, 31.2), "BY": (53.7, 27.9), "RU": (61.5, 105.3),
    "TR": (39.0, 35.2), "IL": (31.0, 34.9), "SA": (23.9, 45.1), "AE": (23.4, 53.8), "QA": (25.4, 51.2),
    "IR": (32.4, 53.7), "IQ": (33.2, 43.7), "EG": (26.8, 30.8), "MA": (31.8, -7.1), "NG": (9.1, 8.7),
    "KE": (-0.02, 37.9), "ZA": (-30.6, 22.9), "GH": (7.9, -1.0), "ET": (9.1, 40.5),
    "IN": (20.6, 79.0), "PK": (30.4, 69.3), "BD": (23.7, 90.4), "LK": (7.9, 80.8), "NP": (28.4, 84.1),
    "CN": (35.9, 104.2), "HK": (22.4, 114.1), "TW": (23.7, 121.0), "JP": (36.2, 138.3), "KR": (35.9, 127.8),
    "KP": (40.3, 127.5), "MN": (46.9, 103.8), "VN": (14.1, 108.3), "TH": (15.9, 100.9), "MY": (4.2, 101.9),
    "SG": (1.35, 103.8), "ID": (-0.8, 113.9), "PH": (12.9, 121.8), "KH": (12.6, 105.0),
    "AU": (-25.3, 133.8), "NZ": (-40.9, 174.9),
    "KZ": (48.0, 66.9), "UZ": (41.4, 64.6), "GE": (42.3, 43.4), "AM": (40.1, 45.0), "AZ": (40.1, 47.6),
    "RS": (44.0, 21.0), "HR": (45.1, 15.2), "SI": (46.2, 15.0), "BA": (43.9, 17.7), "LT": (55.2, 23.9),
    "LV": (56.9, 24.6), "EE": (58.6, 25.0), "MD": (47.4, 28.4), "CY": (35.1, 33.4), "MT": (35.9, 14.4),
    "PA": (8.5, -80.8), "CR": (9.7, -83.8), "DO": (18.7, -70.2), "CU": (21.5, -77.8), "VE": (6.4, -66.6),
    "EC": (-1.8, -78.2), "BO": (-16.3, -63.6), "UY": (-32.5, -55.8), "PY": (-23.4, -58.4),
}

COUNTRY_NAMES: dict[str, str] = {
    "united states": "US", "usa": "US", "united states of america": "US", "canada": "CA", "mexico": "MX",
    "brazil": "BR", "argentina": "AR", "chile": "CL", "colombia": "CO", "peru": "PE",
    "united kingdom": "GB", "uk": "GB", "great britain": "GB", "england": "GB", "ireland": "IE",
    "france": "FR", "germany": "DE", "netherlands": "NL", "belgium": "BE", "luxembourg": "LU",
    "switzerland": "CH", "austria": "AT", "spain": "ES", "portugal": "PT", "italy": "IT", "greece": "GR",
    "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI", "iceland": "IS", "poland": "PL",
    "czechia": "CZ", "czech republic": "CZ", "slovakia": "SK", "hungary": "HU", "romania": "RO",
    "bulgaria": "BG", "ukraine": "UA", "belarus": "BY", "russia": "RU", "russian federation": "RU",
    "turkey": "TR", "türkiye": "TR", "israel": "IL", "saudi arabia": "SA", "united arab emirates": "AE",
    "qatar": "QA", "iran": "IR", "iraq": "IQ", "egypt": "EG", "morocco": "MA", "nigeria": "NG",
    "kenya": "KE", "south africa": "ZA", "ghana": "GH", "ethiopia": "ET", "india": "IN", "pakistan": "PK",
    "bangladesh": "BD", "sri lanka": "LK", "nepal": "NP", "china": "CN", "hong kong": "HK", "taiwan": "TW",
    "japan": "JP", "south korea": "KR", "korea": "KR", "republic of korea": "KR", "north korea": "KP",
    "mongolia": "MN", "vietnam": "VN", "viet nam": "VN", "thailand": "TH", "malaysia": "MY",
    "singapore": "SG", "indonesia": "ID", "philippines": "PH", "cambodia": "KH", "australia": "AU",
    "new zealand": "NZ", "kazakhstan": "KZ", "uzbekistan": "UZ", "georgia": "GE", "armenia": "AM",
    "azerbaijan": "AZ", "serbia": "RS", "croatia": "HR", "slovenia": "SI", "bosnia and herzegovina": "BA",
    "lithuania": "LT", "latvia": "LV", "estonia": "EE", "moldova": "MD", "cyprus": "CY", "malta": "MT",
    "panama": "PA", "costa rica": "CR", "dominican republic": "DO", "cuba": "CU", "venezuela": "VE",
    "ecuador": "EC", "bolivia": "BO", "uruguay": "UY", "paraguay": "PY",
}


def normalize_country(value: str) -> str:
    """Return an ISO alpha-2 code where possible, else the cleaned original string."""
    v = (value or "").strip()
    if not v:
        return ""
    # Entra "Location" exports look like "Seattle, Washington, US": take the last part.
    if "," in v:
        v = v.rsplit(",", 1)[-1].strip()
    low = v.lower()
    if len(v) == 2 and v.upper() in CENTROIDS:
        return v.upper()
    if low in COUNTRY_NAMES:
        return COUNTRY_NAMES[low]
    return v.upper() if len(v) == 2 else v


def distance_km(a: str, b: str) -> float | None:
    if a not in CENTROIDS or b not in CENTROIDS:
        return None
    lat1, lon1 = map(math.radians, CENTROIDS[a])
    lat2, lon2 = map(math.radians, CENTROIDS[b])
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 2 * 6371.0 * math.asin(math.sqrt(h))


# --------------------------------------------------------------------------- timestamps

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%b %d %Y %H:%M:%S", "%d %b %Y %H:%M:%S",
]
_EPOCH_RE = re.compile(r"^\d{10}(?:\d{3})?(?:\.\d+)?$")


def parse_time(value: str) -> datetime | None:
    v = (value or "").strip()
    if not v or len(v) > 64:
        return None
    if _EPOCH_RE.match(v):
        num = float(v)
        if num > 1e11:
            num /= 1000.0
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    v = v.replace("Z", "+00:00")
    # Trim sub-microsecond precision (Entra exports 7 digits).
    v = re.sub(r"(\.\d{6})\d+", r"\1", v)
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    return None


def fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


# --------------------------------------------------------------------------- model

@dataclass
class Event:
    user: str
    ts: datetime
    ip: str
    country: str
    success: bool
    result_raw: str
    mfa_raw: str
    mfa_failed: bool
    mfa_satisfied: bool
    user_agent: str
    app: str
    client_app: str
    legacy: bool


@dataclass
class UserReport:
    user: str
    events: int = 0
    successes: int = 0
    failures: int = 0
    ips: Counter = field(default_factory=Counter)
    countries: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    apps: Counter = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    new_countries: list[dict] = field(default_factory=list)
    new_user_agents: list[dict] = field(default_factory=list)
    impossible_travel: list[dict] = field(default_factory=list)
    mfa_bursts: list[dict] = field(default_factory=list)
    fail_then_success: list[dict] = field(default_factory=list)
    legacy_success: list[dict] = field(default_factory=list)
    score: int = 0
    reasons: list[str] = field(default_factory=list)


def classify_result(raw: str, mfa_raw: str) -> tuple[bool, bool, bool]:
    """Return (success, mfa_failed, mfa_satisfied)."""
    r = (raw or "").strip()
    rl = r.lower()
    m = (mfa_raw or "").strip()
    success = rl in SUCCESS_VALUES or (bool(rl) and not FAILURE_HINT_RE.search(rl)
                                       and rl not in {"failure", "failed", "false", "no"}
                                       and not rl.isdigit())
    if rl.isdigit():
        success = rl == "0"
    if rl in {"failure", "failed", "false", "no", "denied", "blocked", "fail"}:
        success = False
    mfa_failed = (not success) and (r in MFA_FAIL_CODES or bool(MFA_FAIL_TEXT_RE.search(m))
                                    or bool(re.search(r"500121|mfa|strong auth", rl)))
    mfa_satisfied = success and bool(MFA_SATISFIED_RE.search(m))
    return success, mfa_failed, mfa_satisfied


def resolve_columns(header: list[str], overrides: dict[str, str]) -> dict[str, str | None]:
    lower = {h.lower().strip(): h for h in header}
    resolved: dict[str, str | None] = {}
    for logical, aliases in COLUMN_ALIASES.items():
        if logical in overrides:
            if overrides[logical] not in header:
                raise ValueError(f"column {overrides[logical]!r} for {logical} not in header {header}")
            resolved[logical] = overrides[logical]
            continue
        resolved[logical] = next((lower[a] for a in aliases if a in lower), None)
    return resolved


def read_events(text: str, overrides: dict[str, str]) -> tuple[list[Event], dict[str, str | None], int]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("empty input or no header row")
    cols = resolve_columns([f.strip() for f in reader.fieldnames], overrides)
    reader.fieldnames = [f.strip() for f in reader.fieldnames]
    for required in ("user", "timestamp"):
        if not cols[required]:
            raise ValueError(f"could not find a {required} column; use --col {required}=<header>. "
                             f"Header: {reader.fieldnames}")

    def get(row: dict, key: str) -> str:
        col = cols.get(key)
        val = row.get(col, "") if col else ""
        val = (val or "").strip()
        return val[:MAX_FIELD_LEN]

    events: list[Event] = []
    skipped = 0
    for n, row in enumerate(reader):
        if n >= MAX_ROWS:
            print(f"warning: stopped after {MAX_ROWS} rows", file=sys.stderr)
            break
        ts = parse_time(get(row, "timestamp"))
        user = get(row, "user").lower()
        if not ts or not user:
            skipped += 1
            continue
        result_raw = get(row, "result")
        mfa_raw = get(row, "mfa")
        success, mfa_failed, mfa_satisfied = classify_result(result_raw, mfa_raw)
        client_app = get(row, "client_app")
        ua = get(row, "user_agent")
        legacy = bool(LEGACY_RE.search(client_app)) or bool(re.search(r"BAV2ROPC", ua))
        events.append(Event(
            user=user, ts=ts, ip=get(row, "ip"), country=normalize_country(get(row, "country")),
            success=success, result_raw=result_raw, mfa_raw=mfa_raw, mfa_failed=mfa_failed,
            mfa_satisfied=mfa_satisfied, user_agent=ua, app=get(row, "app"),
            client_app=client_app, legacy=legacy,
        ))
    events.sort(key=lambda e: (e.ts, e.user))
    return events, cols, skipped


# --------------------------------------------------------------------------- analysis

def analyze(events: list[Event], *, baseline_days: float, travel_hours: float, max_kmh: float,
            mfa_burst: int, mfa_window_min: float, fts_window_min: float,
            fts_min_failures: int = 2) -> list[UserReport]:
    by_user: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_user[e.user].append(e)

    reports: list[UserReport] = []
    for user, evs in by_user.items():
        r = UserReport(user=user)
        r.events = len(evs)
        r.first_seen = evs[0].ts
        r.last_seen = evs[-1].ts
        baseline_end = evs[0].ts + timedelta(days=baseline_days)
        seen_countries: set[str] = set()
        seen_uas: set[str] = set()
        success_ips: set[str] = set()
        last_success: Event | None = None
        recent_fail_ips: list[tuple[datetime, str]] = []  # (ts, ip) of failures
        mfa_fail_times: list[datetime] = []
        burst_open: dict | None = None

        for e in evs:
            r.ips[e.ip] += 1
            if e.country:
                r.countries[e.country] += 1
            if e.user_agent:
                r.user_agents[e.user_agent] += 1
            if e.app:
                r.apps[e.app] += 1
            in_baseline = e.ts <= baseline_end

            if e.success:
                r.successes += 1
                # new country / user agent (only successes count; failures from anywhere are noise)
                if e.country and e.country not in seen_countries and not in_baseline:
                    r.new_countries.append({"time": fmt_time(e.ts), "country": e.country, "ip": e.ip,
                                            "app": e.app, "mfa": e.mfa_raw})
                if e.user_agent and e.user_agent not in seen_uas and not in_baseline:
                    r.new_user_agents.append({"time": fmt_time(e.ts), "user_agent": e.user_agent[:160],
                                              "ip": e.ip, "country": e.country})
                # impossible travel vs previous success
                if last_success and e.country and last_success.country and e.country != last_success.country:
                    hours = (e.ts - last_success.ts).total_seconds() / 3600.0
                    km = distance_km(last_success.country, e.country)
                    flagged = False
                    detail = ""
                    if km is not None and hours > 0:
                        kmh = km / hours
                        flagged = kmh > max_kmh
                        detail = f"{km:.0f} km in {hours:.1f} h = {kmh:.0f} km/h"
                    elif km is not None and hours == 0:
                        flagged = True
                        detail = f"{km:.0f} km in 0 h"
                    else:
                        flagged = hours < travel_hours
                        detail = f"country change in {hours:.1f} h (no centroid for one side)"
                    if flagged:
                        r.impossible_travel.append({
                            "from_time": fmt_time(last_success.ts), "from_country": last_success.country,
                            "from_ip": last_success.ip, "to_time": fmt_time(e.ts), "to_country": e.country,
                            "to_ip": e.ip, "detail": detail, "to_mfa": e.mfa_raw, "to_app": e.app,
                        })
                # failed-then-success from an IP with no prior success
                if e.ip and e.ip not in success_ips:
                    cutoff = e.ts - timedelta(minutes=fts_window_min)
                    prior_fails = [t for t, ip in recent_fail_ips if ip == e.ip and t >= cutoff]
                    if len(prior_fails) >= fts_min_failures:
                        r.fail_then_success.append({
                            "time": fmt_time(e.ts), "ip": e.ip, "country": e.country,
                            "failures_before": len(prior_fails), "first_failure": fmt_time(min(prior_fails)),
                            "mfa": e.mfa_raw, "app": e.app, "user_agent": e.user_agent[:120],
                        })
                # MFA burst followed by success
                if (burst_open and not burst_open["followed_by_success"]
                        and (e.ts - burst_open["_last"]).total_seconds() <= mfa_window_min * 60 * 3):
                    burst_open["followed_by_success"] = fmt_time(e.ts)
                    burst_open["success_ip"] = e.ip
                    burst_open["success_mfa"] = e.mfa_raw
                if e.legacy:
                    r.legacy_success.append({"time": fmt_time(e.ts), "ip": e.ip, "country": e.country,
                                             "client_app": e.client_app or e.user_agent[:80]})
                seen_countries.add(e.country) if e.country else None
                seen_uas.add(e.user_agent) if e.user_agent else None
                success_ips.add(e.ip)
                last_success = e
            else:
                r.failures += 1
                recent_fail_ips.append((e.ts, e.ip))
                if len(recent_fail_ips) > 10_000:
                    recent_fail_ips = recent_fail_ips[-5_000:]
                if e.mfa_failed:
                    mfa_fail_times.append(e.ts)
                    window_start = e.ts - timedelta(minutes=mfa_window_min)
                    mfa_fail_times = [t for t in mfa_fail_times if t >= window_start]
                    if len(mfa_fail_times) >= mfa_burst:
                        if burst_open and (e.ts - burst_open["_last"]).total_seconds() <= mfa_window_min * 60:
                            burst_open["count"] += 1
                            burst_open["end"] = fmt_time(e.ts)
                            burst_open["_last"] = e.ts
                        else:
                            burst_open = {"start": fmt_time(mfa_fail_times[0]), "end": fmt_time(e.ts),
                                          "count": len(mfa_fail_times), "ip": e.ip, "country": e.country,
                                          "app": e.app, "followed_by_success": "", "success_ip": "",
                                          "success_mfa": "", "_last": e.ts}
                            r.mfa_bursts.append(burst_open)
                    elif burst_open and (e.ts - burst_open["_last"]).total_seconds() <= mfa_window_min * 60:
                        burst_open["count"] += 1
                        burst_open["end"] = fmt_time(e.ts)
                        burst_open["_last"] = e.ts
            # also track baseline observations for failures so a country seen only in
            # failures is still "known" for the purposes of noise reduction? No: failures
            # from anywhere are spray noise; only successes establish the baseline.

        for b in r.mfa_bursts:
            b.pop("_last", None)

        # scoring
        if r.impossible_travel:
            r.score += 3 * len(r.impossible_travel)
            r.reasons.append(f"impossible travel x{len(r.impossible_travel)}")
        if r.mfa_bursts:
            pts = sum(4 if b["followed_by_success"] else 2 for b in r.mfa_bursts)
            r.score += pts
            r.reasons.append(f"MFA failure burst x{len(r.mfa_bursts)}"
                             + (" then success" if any(b["followed_by_success"] for b in r.mfa_bursts) else ""))
        if r.fail_then_success:
            r.score += 3 * len(r.fail_then_success)
            r.reasons.append(f"failed-then-success from new IP x{len(r.fail_then_success)}")
        if r.new_countries:
            r.score += 2 * len(r.new_countries)
            r.reasons.append("new country: " + ", ".join(sorted({c['country'] for c in r.new_countries})))
        if r.legacy_success:
            r.score += 2
            r.reasons.append(f"legacy auth success x{len(r.legacy_success)}")
        if r.new_user_agents:
            r.score += min(len(r.new_user_agents), 3)
            r.reasons.append(f"new user agent x{len(r.new_user_agents)}")
        reports.append(r)

    reports.sort(key=lambda x: (-x.score, -x.failures, x.user))
    return reports


# --------------------------------------------------------------------------- render

def to_dict(r: UserReport) -> dict:
    return {
        "user": r.user, "score": r.score, "reasons": r.reasons, "events": r.events,
        "successes": r.successes, "failures": r.failures,
        "first_seen": fmt_time(r.first_seen), "last_seen": fmt_time(r.last_seen),
        "distinct_ips": len(r.ips), "top_ips": [ip for ip, _ in r.ips.most_common(5)],
        "countries": dict(r.countries), "distinct_user_agents": len(r.user_agents),
        "apps": [a for a, _ in r.apps.most_common(5)],
        "new_countries": r.new_countries, "new_user_agents": r.new_user_agents,
        "impossible_travel": r.impossible_travel, "mfa_bursts": r.mfa_bursts,
        "fail_then_success": r.fail_then_success, "legacy_success": r.legacy_success,
    }


def _esc(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_md(reports: list[UserReport], meta: dict, top: int) -> str:
    out = ["# Sign-in analysis", ""]
    out.append(f"- Events: **{meta['events']}** across {len(reports)} users"
               + (f" ({meta['skipped']} rows skipped: bad timestamp or empty user)" if meta["skipped"] else ""))
    out.append(f"- Window (UTC): {meta['first']} to {meta['last']}")
    out.append("- Columns used: " + ", ".join(f"{k}={v}" for k, v in meta["columns"].items() if v))
    missing = [k for k, v in meta["columns"].items() if not v]
    if missing:
        out.append("- Columns not found (checks depending on them are skipped): " + ", ".join(missing))
    out.append(f"- Thresholds: baseline {meta['baseline_days']} d, travel > {meta['max_kmh']} km/h or country change "
               f"< {meta['travel_hours']} h, MFA burst >= {meta['mfa_burst']} in {meta['mfa_window_min']} min, "
               f"fail-then-success >= {meta['fts_min_failures']} failures in {meta['fts_window_min']} min")
    out.append("")
    out.append("## Users by risk")
    out.append("")
    out.append("| User | Score | Events | OK | Fail | IPs | Countries | UAs | First seen | Last seen | Reasons |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for r in reports[:top]:
        out.append(f"| {_esc(r.user)} | {r.score} | {r.events} | {r.successes} | {r.failures} | {len(r.ips)} "
                   f"| {', '.join(sorted(r.countries)) or '?'} | {len(r.user_agents)} | {fmt_time(r.first_seen)} "
                   f"| {fmt_time(r.last_seen)} | {_esc('; '.join(r.reasons))} |")
    out.append("")

    flagged = [r for r in reports if r.score > 0][:top]
    if not flagged:
        out.append("_No user met any detection threshold. That is a statement about these thresholds and this "
                   "data, not a clean bill of health._")
        return "\n".join(out)

    out.append("## Findings")
    for r in flagged:
        out.append("")
        out.append(f"### {r.user} (score {r.score})")
        for t in r.impossible_travel:
            out.append(f"- **Impossible travel:** {t['from_country']} ({t['from_ip']}) at {t['from_time']} -> "
                       f"{t['to_country']} ({t['to_ip']}) at {t['to_time']}; {t['detail']}; "
                       f"app={_esc(t['to_app']) or '?'}; mfa={_esc(t['to_mfa']) or '?'}")
        for b in r.mfa_bursts:
            tail = (f"; **success at {b['followed_by_success']}** from {b['success_ip']} (mfa={_esc(b['success_mfa'])})"
                    if b["followed_by_success"] else "; no success followed")
            out.append(f"- **MFA failure burst:** {b['count']} MFA failures {b['start']} to {b['end']} from {b['ip']} "
                       f"({b['country'] or '?'}), app={_esc(b['app']) or '?'}{tail}")
        for f in r.fail_then_success:
            out.append(f"- **Failed-then-success from new IP:** {f['failures_before']} failure(s) from {f['ip']} "
                       f"({f['country'] or '?'}) since {f['first_failure']}, then success at {f['time']}; "
                       f"app={_esc(f['app']) or '?'}; mfa={_esc(f['mfa']) or '?'}; ua={_esc(f['user_agent']) or '?'}")
        for c in r.new_countries:
            out.append(f"- **New country:** {c['country']} from {c['ip']} at {c['time']}; app={_esc(c['app']) or '?'}; "
                       f"mfa={_esc(c['mfa']) or '?'}")
        for l in r.legacy_success:
            out.append(f"- **Legacy auth success:** {_esc(l['client_app'])} from {l['ip']} ({l['country'] or '?'}) at {l['time']}")
        for u in r.new_user_agents:
            out.append(f"- **New user agent:** `{_esc(u['user_agent'])}` from {u['ip']} ({u['country'] or '?'}) at {u['time']}")
    return "\n".join(out)


# --------------------------------------------------------------------------- cli

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="CSV file path, or - for stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--col", action="append", default=[], metavar="LOGICAL=HEADER",
                    help="map a logical column (user, timestamp, ip, country, result, mfa, user_agent, app, "
                         "client_app) to a CSV header; repeatable")
    ap.add_argument("--user", help="only analyze this user (substring match, case-insensitive)")
    ap.add_argument("--from", dest="since", help="ignore events before this time (ISO 8601)")
    ap.add_argument("--to", dest="until", help="ignore events after this time (ISO 8601)")
    ap.add_argument("--top", type=int, default=25, help="users to show (default 25)")
    ap.add_argument("--baseline-days", type=float, default=7.0,
                    help="first N days of each user's history are the baseline for 'new' country / UA (default 7)")
    ap.add_argument("--travel-hours", type=float, default=2.0,
                    help="flag a country change faster than this when no centroid is known (default 2)")
    ap.add_argument("--max-kmh", type=float, default=900.0,
                    help="flag travel faster than this between successful sign-ins (default 900)")
    ap.add_argument("--mfa-burst", type=int, default=5, help="MFA failures to call a burst (default 5)")
    ap.add_argument("--mfa-window", type=float, default=10.0, help="minutes for the MFA burst window (default 10)")
    ap.add_argument("--fts-window", type=float, default=60.0,
                    help="minutes to look back for failures before a success from a new IP (default 60)")
    ap.add_argument("--fts-min-failures", type=int, default=2,
                    help="failures from the new IP needed before its success is flagged (default 2; "
                         "1 catches typos and is noisy)")
    args = ap.parse_args(argv)

    overrides: dict[str, str] = {}
    for item in args.col:
        k, sep, v = item.partition("=")
        if not sep or k not in COLUMN_ALIASES:
            print(f"error: --col must be LOGICAL=HEADER with LOGICAL in {sorted(COLUMN_ALIASES)}", file=sys.stderr)
            return 2
        overrides[k] = v

    if args.input == "-":
        text = sys.stdin.read()
    else:
        p = Path(args.input)
        if not p.is_file():
            print(f"error: {p} is not a file", file=sys.stderr)
            return 2
        text = p.read_text(encoding="utf-8-sig", errors="replace")

    try:
        events, cols, skipped = read_events(text, overrides)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None
    if (args.since and not since) or (args.until and not until):
        print("error: --from/--to must be ISO 8601", file=sys.stderr)
        return 2
    if since:
        events = [e for e in events if e.ts >= since]
    if until:
        events = [e for e in events if e.ts <= until]
    if args.user:
        events = [e for e in events if args.user.lower() in e.user]
    if not events:
        print("error: no usable events after parsing/filtering", file=sys.stderr)
        return 2

    reports = analyze(events, baseline_days=args.baseline_days, travel_hours=args.travel_hours,
                      max_kmh=args.max_kmh, mfa_burst=args.mfa_burst, mfa_window_min=args.mfa_window,
                      fts_window_min=args.fts_window, fts_min_failures=args.fts_min_failures)
    meta = {
        "events": len(events), "skipped": skipped, "first": fmt_time(events[0].ts), "last": fmt_time(events[-1].ts),
        "columns": cols, "baseline_days": args.baseline_days, "travel_hours": args.travel_hours,
        "max_kmh": args.max_kmh, "mfa_burst": args.mfa_burst, "mfa_window_min": args.mfa_window,
        "fts_window_min": args.fts_window, "fts_min_failures": args.fts_min_failures,
    }
    if args.format == "json":
        sys.stdout.write(json.dumps({"meta": meta, "users": [to_dict(r) for r in reports[:args.top]]}, indent=2))
    else:
        sys.stdout.write(render_md(reports, meta, args.top))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
