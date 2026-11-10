#!/usr/bin/env python3
"""
fetch-threatfox.py — pull abuse.ch's ThreatFox recent-IOCs feed and emit one
CEF-over-syslog line per IOC, for a k3s CronJob that forwards into NetWitness.

Runs in python:3-alpine. Standard library only.

Unlike URLhaus/Feodo (plain CSV downloads), ThreatFox requires a free
Auth-Key (POST https://threatfox-api.abuse.ch/api/v1/, header "Auth-Key:
<key>" — confirmed empirically: no header -> HTTP 401, wrong-but-present
header -> HTTP 403 with query_status="unknown_auth_key"). Get one free at
https://auth.abuse.ch/ ; it is read only from the THREATFOX_AUTH_KEY
environment variable, never hardcoded or logged.

ThreatFox mixes several IOC types in one feed (domain, url, ip:port,
md5_hash, sha256_hash, ...). Only domain/url/ip:port are forwarded here —
same ip/domain scope as the other two feeds. Everything else is counted
under skipped_unsupported_type and dropped, same "skip, don't crash"
pattern as fetch-urlhaus.py's skipped_ipv6 bucket.

As with URLhaus, --lookback-hours applies a second, local filter on top of
the API's own --days window, so an hourly CronJob with a 1h buffer doesn't
need to trust the API's day-granularity alone. See APPLY.md.
"""
import argparse
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"
SYSLOG_HOST = "192.168.33.43"
SYSLOG_PORT = 514

# ThreatFox's own "days" window for the get_iocs query (API min 1, max 7).
DAYS_BACK = 1

# Local filter on top of DAYS_BACK, same role as fetch-urlhaus.py's
# LOOKBACK_HOURS: sized for an hourly CronJob (1h cadence + 1h buffer).
LOOKBACK_HOURS = 2

SUPPORTED_IOC_TYPES = {"domain", "url", "ip:port"}
SKIP_REASONS = ("skipped_old", "skipped_unsupported_type", "skipped_unparseable")


def syslog_timestamp(dt: datetime) -> str:
    """BSD syslog timestamp, e.g. 'Oct  3 07:00:00' (single-digit day padded with a space)."""
    day = dt.strftime("%d")
    if day[0] == "0":
        day = " " + day[1:]
    return f"{dt.strftime('%b')} {day} {dt.strftime('%H:%M:%S')}"


def escape_cef_header(value) -> str:
    """CEF header fields: escape backslash, then pipe (the field separator)."""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("|", "\\|")
    return s


def escape_cef_extension(value) -> str:
    """CEF extension values: escape backslash, then '=', then newlines."""
    s = str(value)
    s = s.replace("\\", "\\\\")
    s = s.replace("=", "\\=")
    s = s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")
    return s


def parse_first_seen(raw: str) -> datetime:
    """Parse ThreatFox's 'YYYY-MM-DD HH:MM:SS UTC' first_seen into aware UTC datetime."""
    s = (raw or "").strip()
    if s.upper().endswith("UTC"):
        s = s[:-3].strip()
    dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def within_lookback(seen: datetime, now: datetime, lookback_hours: int) -> bool:
    return (now - seen) <= timedelta(hours=lookback_hours)


def classify_host(url: str):
    """
    Split a URL into a (kind, value, port) tuple, or None if the host is
    IPv6 or the URL can't be parsed at all. Duplicated from
    fetch-urlhaus.py per this project's convention (one script per feed,
    no shared-module dependency to keep each ConfigMap self-contained).

    kind is "ip" (IPv4 only) or "domain" (lowercased hostname).
    port is the explicit port, else 443 for https, else 80.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        if not hostname:
            return None
        port = parsed.port  # raises ValueError on a malformed port
    except ValueError:
        return None

    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        addr = None

    if addr is not None:
        if addr.version == 6:
            return None
        kind, value = "ip", str(addr)
    else:
        kind, value = "domain", hostname.lower()

    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return kind, value, port


def classify_ioc(ioc_type: str, ioc: str):
    """
    Map a ThreatFox (ioc_type, ioc) pair to a (kind, value, port) tuple, or
    None if the type is unsupported or the value can't be parsed.

    ioc_type == "domain": ioc is a bare hostname, no port info.
    ioc_type == "url": ioc is a full URL; reuse classify_host (drops IPv6).
    ioc_type == "ip:port": ioc is "1.2.3.4:8080" (IPv4 only observed; an
      IPv6 literal here would contain multiple colons and fail the rsplit
      parse below, which is treated the same as any other unparseable IOC).
    """
    t = (ioc_type or "").strip().lower()
    ioc = (ioc or "").strip()

    if t == "domain":
        if not ioc:
            return None
        return "domain", ioc.lower(), None

    if t == "url":
        return classify_host(ioc)

    if t == "ip:port":
        if ioc.count(":") != 1:
            return None
        ip_part, _, port_part = ioc.partition(":")
        try:
            port = int(port_part)
        except ValueError:
            return None
        try:
            addr = ipaddress.ip_address(ip_part)
        except ValueError:
            return None
        if addr.version == 6:
            return None
        return "ip", str(addr), port

    return None


def normalize_field(raw) -> str:
    """Empty, None, or the literal string 'none' (any case) -> 'none' sentinel."""
    s = (raw or "").strip() if isinstance(raw, str) else ("" if raw is None else str(raw))
    if not s or s.lower() == "none":
        return "none"
    return s


def normalize_tags(tags) -> str:
    """ThreatFox tags are a JSON array (or null). Comma-join; 'none' if empty/null."""
    if not tags:
        return "none"
    cleaned = [str(t).strip().replace(" ", "_") for t in tags if str(t).strip()]
    return ",".join(cleaned) if cleaned else "none"


def build_line(ioc_obj: dict, now: datetime, lookback_hours: int):
    """
    Returns (line, None) if the IOC should be sent, or (None, reason) if it
    should be skipped. reason is one of SKIP_REASONS.

    Emits CEF:
      CEF:0|abuse.ch|ThreatFox|1.0|{threat_type}|ThreatFox {id}|5|dst=<ip> ... | dhost=<domain> ...

    "cs1Label=malware cs1=..." is omitted when malware_printable is
    empty/none. "cs2Label=confidence cs2=..." is omitted when
    confidence_level is missing. "cs3Label=tags cs3=..." is omitted when
    tags is empty/null. No extension value is ever the literal string
    "none" (same rule as fetch-urlhaus.py/fetch-feodo.py).

    ThreatFox has no field that maps cleanly onto the "outcome=" status
    field the other two feeds use (URLhaus's online/offline, Feodo's
    c2_status) — there is no per-IOC up/down state in this feed, so
    "outcome=" is not emitted here at all, not even conditionally.
    """
    try:
        seen = parse_first_seen(ioc_obj.get("first_seen", ""))
    except ValueError:
        return None, "skipped_unparseable"
    if not within_lookback(seen, now, lookback_hours):
        return None, "skipped_old"

    host = classify_ioc(ioc_obj.get("ioc_type", ""), ioc_obj.get("ioc", ""))
    if host is None:
        return None, "skipped_unsupported_type"
    kind, value, port = host

    iid = (str(ioc_obj.get("id") or "")).strip()
    threat_type = normalize_field(ioc_obj.get("threat_type"))
    malware = normalize_field(ioc_obj.get("malware_printable"))
    confidence = ioc_obj.get("confidence_level")
    tags = normalize_tags(ioc_obj.get("tags"))

    ts = syslog_timestamp(now)
    signature_id = escape_cef_header(threat_type)
    name = escape_cef_header(f"ThreatFox {iid}")

    host_field = (
        f"dst={escape_cef_extension(value)}" if kind == "ip"
        else f"dhost={escape_cef_extension(value)}"
    )
    ext_parts = [host_field]
    if port is not None:
        ext_parts.append(f"dpt={escape_cef_extension(port)}")
    if malware != "none":
        ext_parts.append("cs1Label=malware")
        ext_parts.append(f"cs1={escape_cef_extension(malware)}")
    if confidence is not None and str(confidence).strip() != "":
        ext_parts.append("cs2Label=confidence")
        ext_parts.append(f"cs2={escape_cef_extension(confidence)}")
    if tags != "none":
        ext_parts.append("cs3Label=tags")
        ext_parts.append(f"cs3={escape_cef_extension(tags)}")
    extension = " ".join(ext_parts)

    line = (
        f"<134>{ts} k3s-node0 CEF:0|abuse.ch|ThreatFox|1.0|{signature_id}|{name}|5|{extension}"
    )
    return line, None


def fetch_iocs(days: int, auth_key: str) -> list:
    """POST get_iocs to the ThreatFox API. Raises on anything but query_status == 'ok'."""
    body = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    req = urllib.request.Request(
        FEED_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Auth-Key": auth_key,
            "User-Agent": "threat-feed-fix/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))

    status = payload.get("query_status", "")
    if status != "ok":
        raise RuntimeError(f"ThreatFox API returned query_status={status!r}")
    return payload.get("data") or []


def send_udp(lines: list) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sock.sendto(line.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
    finally:
        sock.close()


def run(iocs: list, now: datetime, lookback_hours: int):
    """Pure driver: IOC dicts in, (lines, counts) out. No I/O."""
    lines = []
    counts = {"sent": 0, "skipped_old": 0, "skipped_unsupported_type": 0, "skipped_unparseable": 0}
    for ioc_obj in iocs:
        line, reason = build_line(ioc_obj, now, lookback_hours)
        if line:
            lines.append(line)
            counts["sent"] += 1
        else:
            counts[reason] += 1
    return lines, counts


def _read_dotenv_key(key: str, env_path: str) -> str:
    """Minimal stdlib KEY=VALUE .env reader, used only as a fallback when
    THREATFOX_AUTH_KEY isn't already in the environment. Backed by a
    1Password-managed local Environment file (a FIFO, not a plaintext file
    at rest) when wired up via the 1Password MCP server -- see README.
    Missing file / unreadable / key absent all just fall through to the
    existing "not set" error in main(), so this never masks a real problem.
    """
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                if name.strip() == key:
                    return value.strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fetch ThreatFox recent IOCs, emit CEF syslog lines.")
    parser.add_argument(
        "--days", type=int, default=DAYS_BACK,
        help=f"ThreatFox API 'days' window, 1-7 (default: {DAYS_BACK}).",
    )
    parser.add_argument(
        "--lookback-hours", type=int, default=LOOKBACK_HOURS,
        help=f"Only forward IOCs first seen within this many hours (default: {LOOKBACK_HOURS}).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print lines and a summary; send nothing over the network.",
    )
    args = parser.parse_args(argv)

    auth_key = os.environ.get("THREATFOX_AUTH_KEY", "").strip()
    if not auth_key:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        auth_key = _read_dotenv_key("THREATFOX_AUTH_KEY", env_path).strip()
    if not auth_key:
        print(
            "error: THREATFOX_AUTH_KEY is not set. Get a free key at "
            "https://auth.abuse.ch/ and export it as THREATFOX_AUTH_KEY, or "
            "wire up the 1Password-managed .env (see README).",
            file=sys.stderr,
        )
        sys.exit(1)

    now = datetime.now(timezone.utc)
    try:
        iocs = fetch_iocs(args.days, auth_key)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        try:
            query_status = json.loads(body).get("query_status", "")
        except json.JSONDecodeError:
            query_status = ""
        detail = f"query_status={query_status!r}" if query_status else f"body={body!r}"
        print(
            f"error: ThreatFox API request failed: HTTP {exc.code} {exc.reason} ({detail})",
            file=sys.stderr,
        )
        sys.exit(1)
    except (RuntimeError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"error: ThreatFox API request failed: {exc}", file=sys.stderr)
        sys.exit(1)

    lines, counts = run(iocs, now, args.lookback_hours)

    summary = (
        f"sent={counts['sent']} skipped_old={counts['skipped_old']} "
        f"skipped_unsupported_type={counts['skipped_unsupported_type']} "
        f"skipped_unparseable={counts['skipped_unparseable']}"
    )

    if args.dry_run:
        for line in lines:
            print(line)
        print(f"\nsummary: {summary}")
        return

    send_udp(lines)
    print(f"summary: {summary}")


if __name__ == "__main__":
    main()
