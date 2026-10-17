"""
Tests for fetch-feodo.py. Fixtures only — no network calls, no socket sends.
All rows in this file are SYNTHETIC (the task gave no real feodotracker sample rows).
"""
from datetime import datetime, timezone

NOW = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)  # SYNTHETIC: fixed clock


def test_build_line_basic(feodo_mod):
    # SYNTHETIC
    r = {"first_seen_utc": "2024-05-01 10:00:00", "dst_ip": "198.51.100.7",
         "dst_port": "443", "c2_status": "online", "last_online": "2024-05-01 11:00:00",
         "malware": "Heodo"}
    line = feodo_mod.build_line(r, NOW)
    assert line == (
        "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|Feodo|1.0|C2|Feodo C2 Server|5|"
        "dst=198.51.100.7 dpt=443 cs1Label=malware cs1=Heodo outcome=online"
    )


def test_build_line_missing_fields_omits_optional_pairs(feodo_mod):
    # SYNTHETIC: no malware, no c2_status -> cs1Label/cs1 and outcome both
    # omitted entirely, never emitted as literal "none".
    r = {"dst_ip": "198.51.100.8", "dst_port": "8080"}
    line = feodo_mod.build_line(r, NOW)
    assert line == (
        "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|Feodo|1.0|C2|Feodo C2 Server|5|"
        "dst=198.51.100.8 dpt=8080"
    )
    assert "none" not in line.lower()


def test_build_line_literal_none_values_are_omitted(feodo_mod):
    # SYNTHETIC: the feed's literal "None" sentinel in malware/status columns
    r = {"dst_ip": "198.51.100.13", "dst_port": "8080", "malware": "None", "c2_status": "none"}
    line = feodo_mod.build_line(r, NOW)
    assert "cs1" not in line
    assert "outcome=" not in line
    assert "none" not in line.lower()


def test_read_rows_real_header_not_commented(feodo_mod):
    # SYNTHETIC CSV text, shaped per the task's documented header
    csv_text = (
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
        '"2024-05-01 10:00:00","198.51.100.7","443","online","2024-05-01 11:00:00","Heodo"\n'
    )
    rows = feodo_mod.read_rows(csv_text)
    assert len(rows) == 1
    assert rows[0]["dst_ip"] == "198.51.100.7"
    assert rows[0]["malware"] == "Heodo"


def test_read_rows_skips_leading_comment_lines(feodo_mod):
    # SYNTHETIC: some abuse.ch feeds prepend '#' metadata lines before the real header
    csv_text = (
        "# Feodo Tracker IP Blocklist\n"
        "# Last updated: 2024-05-01\n"
        '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
        '"2024-05-01 10:00:00","198.51.100.9","8080","offline","2024-05-01 11:00:00","Dridex"\n'
    )
    rows = feodo_mod.read_rows(csv_text)
    assert len(rows) == 1
    assert rows[0]["dst_ip"] == "198.51.100.9"
    assert rows[0]["malware"] == "Dridex"


def test_run_builds_one_line_per_row(feodo_mod):
    # SYNTHETIC
    rows = [
        {"dst_ip": "198.51.100.7", "dst_port": "443", "c2_status": "online", "malware": "Heodo"},
        {"dst_ip": "198.51.100.8", "dst_port": "8080", "c2_status": "offline", "malware": "Dridex"},
    ]
    lines = feodo_mod.run(rows, NOW)
    assert len(lines) == 2
    assert "dst=198.51.100.7" in lines[0]
    assert "dst=198.51.100.8" in lines[1]
    assert all(line.startswith("<134>") and "CEF:0|abuse.ch|Feodo|1.0|C2|" in line for line in lines)


# ---------------------------------------------------------------------------
# CEF escaping (same helpers as fetch-urlhaus.py, duplicated per script)
# ---------------------------------------------------------------------------

class TestCefEscaping:
    def test_header_escapes_backslash_then_pipe(self, feodo_mod):
        # SYNTHETIC
        assert feodo_mod.escape_cef_header("a|b\\c") == "a\\|b\\\\c"

    def test_extension_escapes_backslash_then_equals_then_newline(self, feodo_mod):
        # SYNTHETIC
        assert feodo_mod.escape_cef_extension("a=b\\c\nd") == "a\\=b\\\\c\\nd"

    def test_malware_value_with_equals_is_escaped_end_to_end(self, feodo_mod):
        # SYNTHETIC: malware name containing '=' to prove extension escaping
        # actually runs in build_line, not just in isolation.
        r = {"dst_ip": "198.51.100.12", "dst_port": "443", "c2_status": "online", "malware": "Foo=Bar"}
        line = feodo_mod.build_line(r, NOW)
        assert "cs1=Foo\\=Bar" in line
