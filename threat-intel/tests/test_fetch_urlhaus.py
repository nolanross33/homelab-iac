"""
Tests for fetch-urlhaus.py. Fixtures only — no network calls, no socket sends.

Real data: the two "REAL ROW" fixtures below (id/url/threat/tags/status) come
from the task's real sample data. Every other field on those rows
(date_added, last_online, reference) is made up to exercise the lookback
window and is marked SYNTHETIC. All other rows in this file are entirely
SYNTHETIC test data.
"""
from datetime import datetime, timedelta, timezone


NOW = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)  # SYNTHETIC: fixed clock for deterministic tests


def row(id_, date_added, url, status="online", last_online="SYNTHETIC",
        threat="malware_download", tags="", reference="SYNTHETIC"):
    return {
        "id": id_, "date_added": date_added, "url": url, "status": status,
        "last_online": last_online, "threat": threat, "tags": tags, "reference": reference,
    }


# ---------------------------------------------------------------------------
# classify_host: URL splitting
# ---------------------------------------------------------------------------

class TestClassifyHost:
    def test_ipv4_with_port(self, urlhaus_mod):
        # REAL: id=3949637 url=http://219.157.238.6:35642/i
        assert urlhaus_mod.classify_host("http://219.157.238.6:35642/i") == ("ip", "219.157.238.6", 35642)

    def test_ipv4_without_port_defaults_http_80(self, urlhaus_mod):
        # REAL: id=3949639 url=http://176.65.139.160/arm6
        assert urlhaus_mod.classify_host("http://176.65.139.160/arm6") == ("ip", "176.65.139.160", 80)

    def test_https_hostname_defaults_443(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.classify_host("https://evil-example.com/payload") == ("domain", "evil-example.com", 443)

    def test_hostname_with_explicit_port(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.classify_host("http://evil-example.com:8080/x") == ("domain", "evil-example.com", 8080)

    def test_uppercase_hostname_is_lowered(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.classify_host("http://EVIL-EXAMPLE.COM/x") == ("domain", "evil-example.com", 80)

    def test_ipv6_is_skipped(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.classify_host("http://[2001:db8::1]/x") is None

    def test_junk_url_is_skipped(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.classify_host("not-a-url-at-all") is None
        assert urlhaus_mod.classify_host("") is None
        assert urlhaus_mod.classify_host("http://:::bad") is None


# ---------------------------------------------------------------------------
# tags normalization
# ---------------------------------------------------------------------------

class TestNormalizeTags:
    def test_empty_becomes_none(self, urlhaus_mod):
        assert urlhaus_mod.normalize_tags("") == "none"

    def test_literal_none_becomes_none(self, urlhaus_mod):
        # REAL: id=3949637 tags=None
        assert urlhaus_mod.normalize_tags("None") == "none"

    def test_spaces_become_underscores(self, urlhaus_mod):
        # SYNTHETIC
        assert urlhaus_mod.normalize_tags("elf botnet mirai") == "elf_botnet_mirai"

    def test_comma_tags_untouched(self, urlhaus_mod):
        # REAL: id=3949639 tags=176-65-139-160,elf,ua-wget
        assert urlhaus_mod.normalize_tags("176-65-139-160,elf,ua-wget") == "176-65-139-160,elf,ua-wget"


# ---------------------------------------------------------------------------
# lookback window
# ---------------------------------------------------------------------------

class TestLookback:
    def test_within_window_is_sent(self, urlhaus_mod):
        added = NOW - timedelta(hours=1)  # SYNTHETIC
        assert urlhaus_mod.within_lookback(added, NOW, 26) is True

    def test_outside_window_is_skipped(self, urlhaus_mod):
        added = NOW - timedelta(hours=27)  # SYNTHETIC
        assert urlhaus_mod.within_lookback(added, NOW, 26) is False

    def test_exactly_at_boundary_is_sent(self, urlhaus_mod):
        added = NOW - timedelta(hours=26)  # SYNTHETIC
        assert urlhaus_mod.within_lookback(added, NOW, 26) is True

    def test_default_lookback_matches_hourly_schedule(self, urlhaus_mod):
        # Default LOOKBACK_HOURS is sized for the recommended hourly CronJob
        # cadence (1h cadence + 1h buffer for a missed run) -- see APPLY.md.
        assert urlhaus_mod.LOOKBACK_HOURS == 2


# ---------------------------------------------------------------------------
# CEF escaping
# ---------------------------------------------------------------------------

class TestCefEscaping:
    def test_header_escapes_backslash_then_pipe(self, urlhaus_mod):
        # SYNTHETIC: a Name containing both a literal backslash and a pipe
        assert urlhaus_mod.escape_cef_header("a|b\\c") == "a\\|b\\\\c"

    def test_header_plain_value_untouched(self, urlhaus_mod):
        assert urlhaus_mod.escape_cef_header("URLhaus 3949637") == "URLhaus 3949637"

    def test_extension_escapes_backslash_then_equals_then_newline(self, urlhaus_mod):
        # SYNTHETIC: an extension value containing '=', '\', and a newline
        assert urlhaus_mod.escape_cef_extension("a=b\\c\nd") == "a\\=b\\\\c\\nd"

    def test_extension_plain_value_untouched(self, urlhaus_mod):
        assert urlhaus_mod.escape_cef_extension("219.157.238.6") == "219.157.238.6"


# ---------------------------------------------------------------------------
# build_line: end-to-end per-row behavior, using the real fixture rows
# ---------------------------------------------------------------------------

class TestBuildLine:
    def test_real_row_ipv4(self, urlhaus_mod):
        # REAL: id=3949637 url=http://219.157.238.6:35642/i threat=malware_download tags=None status=online
        r = row(
            id_="3949637",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),  # SYNTHETIC timestamp
            url="http://219.157.238.6:35642/i",
            threat="malware_download",
            tags="None",
            status="online",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        # NOTE: the syslog timestamp reflects "now" (send time), not date_added.
        # tags=None -> cs1Label/cs1 omitted entirely (never emitted as literal "none").
        assert line == (
            "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|URLhaus|1.0|malware_download|URLhaus 3949637|5|"
            "dst=219.157.238.6 dpt=35642 outcome=online"
        )

    def test_real_row_ipv4_host(self, urlhaus_mod):
        # REAL: id=3949639 url=http://176.65.139.160/arm6 threat=malware_download
        #       tags=176-65-139-160,elf,ua-wget status=online
        r = row(
            id_="3949639",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),  # SYNTHETIC timestamp
            url="http://176.65.139.160/arm6",
            threat="malware_download",
            tags="176-65-139-160,elf,ua-wget",
            status="online",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        assert line == (
            "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|URLhaus|1.0|malware_download|URLhaus 3949639|5|"
            "dst=176.65.139.160 dpt=80 cs1Label=malware cs1=176-65-139-160,elf,ua-wget outcome=online"
        )

    def test_hostname_row_emits_dhost_field(self, urlhaus_mod):
        # SYNTHETIC row exercising the dhost= output format
        r = row(
            id_="9999901",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            url="https://evil-example.com/payload",
            threat="malware_download",
            tags="",
            status="online",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        # tags="" -> cs1Label/cs1 omitted entirely.
        assert line == (
            "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|URLhaus|1.0|malware_download|URLhaus 9999901|5|"
            "dhost=evil-example.com dpt=443 outcome=online"
        )

    def test_row_with_pipe_in_threat_is_escaped_in_header(self, urlhaus_mod):
        # SYNTHETIC: a threat value containing a pipe, to prove header escaping
        # actually runs end-to-end (not just unit-tested in isolation).
        r = row(
            id_="9999906",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            url="http://198.51.100.20/x",
            threat="mal|ware",
            tags="",
            status="online",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        assert "|mal\\|ware|" in line
        # 5 template separators (CEF:0|vendor|product|version|sig|name) plus
        # the one escaped-but-still-present pipe inside the signature value.
        prefix, extension = line.split("|5|", 1)
        assert prefix.count("|") == 6
        # tags="" -> cs1Label/cs1 omitted; status="online" -> outcome kept.
        assert extension == "dst=198.51.100.20 dpt=80 outcome=online"

    def test_old_row_is_skipped(self, urlhaus_mod):
        # SYNTHETIC
        r = row(
            id_="9999902",
            date_added=(NOW - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S"),
            url="http://198.51.100.9/x",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert line is None
        assert reason == "skipped_old"

    def test_ipv6_row_is_skipped(self, urlhaus_mod):
        # SYNTHETIC
        r = row(
            id_="9999903",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            url="http://[2001:db8::1]/x",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert line is None
        assert reason == "skipped_ipv6"


class TestOptionalExtensionFields:
    """cs1Label/cs1 and outcome are omitted entirely when empty/none -- never emitted as literal "none"."""

    def test_tags_and_status_both_empty_omits_both_pairs(self, urlhaus_mod):
        # SYNTHETIC
        r = row(
            id_="9999907",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            url="http://198.51.100.21/y",
            tags="",
            status="",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        assert line == (
            "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|URLhaus|1.0|malware_download|URLhaus 9999907|5|"
            "dst=198.51.100.21 dpt=80"
        )
        assert "none" not in line.lower()

    def test_status_literal_none_is_omitted(self, urlhaus_mod):
        # SYNTHETIC: the feed's literal "None" sentinel in the status column too
        r = row(
            id_="9999908",
            date_added=(NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
            url="http://198.51.100.22/z",
            tags="",
            status="None",
        )
        line, reason = urlhaus_mod.build_line(r, NOW, 2)
        assert reason is None
        assert "outcome=" not in line
        assert "cs1" not in line
        assert "none" not in line.lower()


# ---------------------------------------------------------------------------
# run(): aggregate counts, including both real rows together
# ---------------------------------------------------------------------------

class TestRun:
    def test_summary_counts(self, urlhaus_mod):
        fresh_ts = (NOW - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        old_ts = (NOW - timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")  # SYNTHETIC
        rows = [
            # REAL rows, SYNTHETIC timestamps
            row("3949637", fresh_ts, "http://219.157.238.6:35642/i", tags="None"),
            row("3949639", fresh_ts, "http://176.65.139.160/arm6", tags="176-65-139-160,elf,ua-wget"),
            # SYNTHETIC: old row, dropped
            row("9999904", old_ts, "http://198.51.100.9/x"),
            # SYNTHETIC: ipv6 row, dropped
            row("9999905", fresh_ts, "http://[2001:db8::1]/x"),
        ]
        lines, counts = urlhaus_mod.run(rows, NOW, 2)
        assert counts == {"sent": 2, "skipped_old": 1, "skipped_ipv6": 1}
        assert len(lines) == 2
        assert all(line.startswith("<134>") and "CEF:0|abuse.ch|URLhaus|1.0|" in line for line in lines)
        # First row's tags=None must never surface as a literal "none" value.
        assert all("none" not in line.lower() for line in lines)


# ---------------------------------------------------------------------------
# read_rows: comment stripping + fixed column order (no header in the feed)
# ---------------------------------------------------------------------------

class TestReadRows:
    def test_comment_lines_are_skipped(self, urlhaus_mod):
        # SYNTHETIC CSV text, shaped like the real feed (commented header, no real header row)
        csv_text = (
            "# https://urlhaus.abuse.ch/downloads/csv_recent/\n"
            "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link\n"
            '3949637,"2024-05-01 11:00:00",http://219.157.238.6:35642/i,online,'
            '"2024-05-01 11:05:00",malware_download,None,SYNTHETIC-REFERENCE\n'
        )
        rows = urlhaus_mod.read_rows(csv_text)
        assert len(rows) == 1
        assert rows[0]["id"] == "3949637"
        assert rows[0]["url"] == "http://219.157.238.6:35642/i"
        assert rows[0]["tags"] == "None"
