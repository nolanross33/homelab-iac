#!/usr/bin/env python3
"""
fetch-urlhaus.py — pull the URLhaus "recent" CSV feed and emit one CEF-over-
syslog line per row, for a k3s CronJob that forwards into NetWitness.

Runs in python:3-alpine. Standard library only.

History:
  - Original behavior resent the entire feed every run (~34k events/hour,
    nearly all duplicates).
  - A custom urlhausfeed NetWitness parser was tried and never extracted
    fields correctly (table-map name mismatch); that approach is retired.
  - Current behavior: emit CEF so NetWitness's stock CEF parser handles
    the event, and only forward rows added within LOOKBACK_HOURS so a
    short lookback (sized to the CronJob's own schedule) prevents the
    original resend-everything duplicate flood. See APPLY.md for the
    chosen schedule/lookback pairing.
"""
import argparse
import csv
import io
import ipaddress
import socket
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
SYSLOG_HOST = "192.168.1.43"
SYSLOG_PORT = 514

# Only forward rows whose date_added is within this many hours of "now".
# Overridable with --lookback-hours. Sized for an hourly CronJob schedule
# (1h cadence + 1h buffer for a missed run) -- see APPLY.md.
LOOKBACK_HOURS = 2

# Real CSV column order for the csv_recent feed (comment lines start with '#').
CSV_FIELDS = ["id", "date_added", "url", "status", "last_online", "threat", "tags", "reference"]

SKIP_REASONS = ("skipped_old", "skipped_ipv6")


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


def parse_date_added(raw: str) -> datetime:
    """Parse the feed's date_added column into an aware UTC datetime."""
    s = (raw or "").strip()
    if s.upper().endswith("UTC"):
        s = s[:-3].strip()
    dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def within_lookback(added: datetime, now: datetime, lookback_hours: int) -> bool:
    return (now - added) <= timedelta(hours=lookback_hours)


def classify_host(url: str):
    """
    Split a URL into a (kind, value, port) tuple, or None if the host is
    IPv6 or the URL can't be parsed at all.

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


def normalize_tags(raw: str) -> str:
    """Spaces -> underscores. Empty or the feed's literal 'None' -> 'none'."""
    s = (raw or "").strip()
    if not s or s.lower() == "none":
        return "none"
    return s.replace(" ", "_")


def build_line(row: dict, now: datetime, lookback_hours: int):
    """
    Returns (line, None) if the row should be sent, or (None, reason) if it
    should be skipped. reason is one of SKIP_REASONS.

    Emits CEF:
      CEF:0|abuse.ch|URLhaus|1.0|{threat}|URLhaus {id}|5|dst=<ip> ... | dhost=<domain> ...
    dst= is used for an IPv4-hosted URL, dhost= for a hostname-hosted one.

    "cs1Label=malware cs1=..." is omitted entirely when tags are empty/none,
    and "outcome=..." is omitted entirely when status is empty/none — no
    extension value is ever the literal string "none".

    NOTE: a URL that fails to parse at all (junk) is bucketed under
    "skipped_ipv6" along with real IPv6 hosts — both mean "no ip/domain
    could be extracted" and the CLI summary only tracks that one bucket,
    per spec.
    """
    try:
        added = parse_date_added(row.get("date_added", ""))
    except ValueError:
        return None, "skipped_old"
    if not within_lookback(added, now, lookback_hours):
        return None, "skipped_old"

    host = classify_host(row.get("url", ""))
    if host is None:
        return None, "skipped_ipv6"
    kind, value, port = host

    rid = (row.get("id") or "").strip()
    threat = (row.get("threat") or "").strip() or "none"
    status = (row.get("status") or "").strip()
    tags = normalize_tags(row.get("tags", ""))  # "none" sentinel means "nothing to report"

    ts = syslog_timestamp(now)
    signature_id = escape_cef_header(threat)
    name = escape_cef_header(f"URLhaus {rid}")

    host_field = (
        f"dst={escape_cef_extension(value)}" if kind == "ip"
        else f"dhost={escape_cef_extension(value)}"
    )
    ext_parts = [host_field, f"dpt={escape_cef_extension(port)}"]
    if tags != "none":
        ext_parts.append("cs1Label=malware")
        ext_parts.append(f"cs1={escape_cef_extension(tags)}")
    if status and status.lower() != "none":
        ext_parts.append(f"outcome={escape_cef_extension(status)}")
    extension = " ".join(ext_parts)

    line = (
        f"<134>{ts} k3s-node0 CEF:0|abuse.ch|URLhaus|1.0|{signature_id}|{name}|5|{extension}"
    )
    return line, None


def read_rows(csv_text: str) -> list:
    """Strip '#' comment lines and parse the remainder as the known column layout."""
    cleaned = "\n".join(l for l in csv_text.splitlines() if not l.startswith("#"))
    return list(csv.DictReader(io.StringIO(cleaned), fieldnames=CSV_FIELDS))


def fetch_csv_text() -> str:
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "threat-feed-fix/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def send_udp(lines: list) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            sock.sendto(line.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
    finally:
        sock.close()


def run(rows: list, now: datetime, lookback_hours: int):
    """Pure driver: rows in, (lines, counts) out. No I/O."""
    lines = []
    counts = {"sent": 0, "skipped_old": 0, "skipped_ipv6": 0}
    for row in rows:
        line, reason = build_line(row, now, lookback_hours)
        if line:
            lines.append(line)
            counts["sent"] += 1
        else:
            counts[reason] += 1
    return lines, counts


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fetch URLhaus recent feed, emit CEF syslog lines.")
    parser.add_argument(
        "--lookback-hours", type=int, default=LOOKBACK_HOURS,
        help=f"Only forward rows added within this many hours (default: {LOOKBACK_HOURS}).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print lines and a summary; send nothing over the network.",
    )
    args = parser.parse_args(argv)

    now = datetime.now(timezone.utc)
    rows = read_rows(fetch_csv_text())
    lines, counts = run(rows, now, args.lookback_hours)

    if args.dry_run:
        for line in lines:
            print(line)
        print(
            f"\nsummary: sent={counts['sent']} "
            f"skipped_old={counts['skipped_old']} skipped_ipv6={counts['skipped_ipv6']}"
        )
        return

    send_udp(lines)
    print(
        f"summary: sent={counts['sent']} "
        f"skipped_old={counts['skipped_old']} skipped_ipv6={counts['skipped_ipv6']}"
    )


if __name__ == "__main__":
    main()
