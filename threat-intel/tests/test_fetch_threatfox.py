"""
Tests for fetch-threatfox.py. Fixtures only — no network calls, no socket sends.

REAL: the id=41 IOC object in TestBuildLine.test_build_line_domain_real_sample
is abuse.ch's own documented example response from https://threatfox.abuse.ch/api/.
Every other row in this file is SYNTHETIC.
"""
from datetime import datetime, timezone


NOW = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)  # SYNTHETIC: fixed clock for deterministic tests


# ---------------------------------------------------------------------------
# classify_host: URL splitting (duplicated from fetch-urlhaus.py)
# ---------------------------------------------------------------------------

class TestClassifyHost:
    def test_https_hostname_defaults_443(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_host("https://evil-example.com/payload") == ("domain", "evil-example.com", 443)

    def test_ipv6_is_skipped(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_host("http://[2001:db8::1]/x") is None


# ---------------------------------------------------------------------------
# classify_ioc: ThreatFox (ioc_type, ioc) -> (kind, value, port)
# ---------------------------------------------------------------------------

class TestClassifyIoc:
    def test_domain(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("domain", "Evil-Example.COM") == ("domain", "evil-example.com", None)

    def test_domain_empty_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("domain", "") is None

    def test_url_defers_to_classify_host(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("url", "http://evil-example.com:8080/x") == ("domain", "evil-example.com", 8080)

    def test_ip_port(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("ip:port", "203.0.113.5:4444") == ("ip", "203.0.113.5", 4444)

    def test_ip_port_malformed_port_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("ip:port", "203.0.113.5:notaport") is None

    def test_ip_port_missing_colon_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("ip:port", "203.0.113.5") is None

    def test_ip_port_ipv6_is_none(self, threatfox_mod):
        # SYNTHETIC: an IPv6 literal would contain multiple colons and fail
        # the single-colon partition this function relies on.
        assert threatfox_mod.classify_ioc("ip:port", "2001:db8::1:443") is None

    def test_unsupported_type_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.classify_ioc("md5_hash", "d41d8cd98f00b204e9800998ecf8427e") is None
        assert threatfox_mod.classify_ioc("sha256_hash", "abc123") is None


# ---------------------------------------------------------------------------
# normalize_field / normalize_tags
# ---------------------------------------------------------------------------

class TestNormalizeField:
    def test_none_and_empty_and_literal_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.normalize_field(None) == "none"
        assert threatfox_mod.normalize_field("") == "none"
        assert threatfox_mod.normalize_field("None") == "none"
        assert threatfox_mod.normalize_field("  ") == "none"

    def test_real_value_passes_through(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.normalize_field("botnet_cc") == "botnet_cc"


class TestNormalizeTags:
    def test_none_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.normalize_tags(None) == "none"

    def test_empty_list_is_none(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.normalize_tags([]) == "none"

    def test_joins_and_replaces_spaces(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.normalize_tags(["exe", "test case"]) == "exe,test_case"


# ---------------------------------------------------------------------------
# CEF escaping (same helpers as fetch-urlhaus.py/fetch-feodo.py, duplicated)
# ---------------------------------------------------------------------------

class TestCefEscaping:
    def test_header_escapes_backslash_then_pipe(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.escape_cef_header("a|b\\c") == "a\\|b\\\\c"

    def test_extension_escapes_backslash_then_equals_then_newline(self, threatfox_mod):
        # SYNTHETIC
        assert threatfox_mod.escape_cef_extension("a=b\\c\nd") == "a\\=b\\\\c\\nd"


# ---------------------------------------------------------------------------
# build_line
# ---------------------------------------------------------------------------

class TestBuildLine:
    def test_build_line_domain_real_sample(self, threatfox_mod):
        # REAL: abuse.ch's own documented sample IOC from https://threatfox.abuse.ch/api/
        ioc = {
            "id": "41",
            "ioc": "gaga.com",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
            "ioc_type": "domain",
            "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
            "malware": "win.dridex",
            "malware_printable": "Dridex",
            "malware_alias": None,
            "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex",
            "confidence_level": 50,
            "first_seen": "2020-12-08 13:36:27 UTC",
            "last_seen": None,
            "reporter": "abuse_ch",
            "reference": "https://twitter.com/JAMESWT_MHT/status/1336229725082177536",
            "tags": ["exe", "test"],
        }
        now = datetime(2020, 12, 8, 14, 0, 0, tzinfo=timezone.utc)  # REAL timestamp's own day, synthetic clock offset
        line, reason = threatfox_mod.build_line(ioc, now, lookback_hours=2)
        assert reason is None
        assert line == (
            "<134>Dec  8 14:00:00 k3s-node0 CEF:0|abuse.ch|ThreatFox|1.0|botnet_cc|ThreatFox 41|5|"
            "dhost=gaga.com cs1Label=malware cs1=Dridex cs2Label=confidence cs2=50 "
            "cs3Label=tags cs3=exe,test"
        )
        assert "none" not in line.lower()

    def test_build_line_ip_port_missing_optional_fields(self, threatfox_mod):
        # SYNTHETIC: no malware, no confidence, no tags -> all three optional
        # groups omitted entirely, never emitted as literal "none".
        ioc = {
            "id": "99", "ioc": "203.0.113.5:4444", "ioc_type": "ip:port",
            "threat_type": "payload_delivery", "malware_printable": None,
            "confidence_level": None, "tags": None,
            "first_seen": "2024-05-01 11:00:00 UTC",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert reason is None
        assert line == (
            "<134>May  1 12:00:00 k3s-node0 CEF:0|abuse.ch|ThreatFox|1.0|payload_delivery|ThreatFox 99|5|"
            "dst=203.0.113.5 dpt=4444"
        )
        assert "none" not in line.lower()

    def test_build_line_url_type(self, threatfox_mod):
        # SYNTHETIC
        ioc = {
            "id": "100", "ioc": "http://evil-example.com:8080/x", "ioc_type": "url",
            "threat_type": "payload_delivery", "malware_printable": "AgentTesla",
            "confidence_level": 75, "tags": None,
            "first_seen": "2024-05-01 11:30:00 UTC",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert reason is None
        assert "dhost=evil-example.com" in line
        assert "dpt=8080" in line
        assert "cs1=AgentTesla" in line
        assert "cs2=75" in line

    def test_build_line_old_is_skipped(self, threatfox_mod):
        # SYNTHETIC: first_seen well outside the lookback window
        ioc = {
            "id": "101", "ioc": "stale.example.com", "ioc_type": "domain",
            "threat_type": "botnet_cc", "first_seen": "2024-04-01 00:00:00 UTC",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert line is None
        assert reason == "skipped_old"

    def test_build_line_unsupported_type_is_skipped(self, threatfox_mod):
        # SYNTHETIC
        ioc = {
            "id": "102", "ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash",
            "threat_type": "payload_delivery", "first_seen": "2024-05-01 11:50:00 UTC",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert line is None
        assert reason == "skipped_unsupported_type"

    def test_build_line_unparseable_first_seen_is_skipped(self, threatfox_mod):
        # SYNTHETIC
        ioc = {
            "id": "103", "ioc": "evil.example.com", "ioc_type": "domain",
            "threat_type": "botnet_cc", "first_seen": "not-a-date",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert line is None
        assert reason == "skipped_unparseable"

    def test_outcome_field_is_never_emitted(self, threatfox_mod):
        # SYNTHETIC: ThreatFox has no per-IOC status field analogous to
        # URLhaus's status / Feodo's c2_status, so "outcome=" should never
        # appear in a ThreatFox CEF line.
        ioc = {
            "id": "104", "ioc": "203.0.113.9:80", "ioc_type": "ip:port",
            "threat_type": "botnet_cc", "malware_printable": "Mirai",
            "confidence_level": 90, "tags": ["elf"],
            "first_seen": "2024-05-01 11:45:00 UTC",
        }
        line, reason = threatfox_mod.build_line(ioc, NOW, lookback_hours=2)
        assert reason is None
        assert "outcome=" not in line


# ---------------------------------------------------------------------------
# run: pure driver, counts
# ---------------------------------------------------------------------------

class TestRun:
    def test_run_counts_sent_and_skipped(self, threatfox_mod):
        # SYNTHETIC
        iocs = [
            {"id": "1", "ioc": "a.example.com", "ioc_type": "domain",
             "threat_type": "botnet_cc", "first_seen": "2024-05-01 11:00:00 UTC"},
            {"id": "2", "ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash",
             "threat_type": "payload_delivery", "first_seen": "2024-05-01 11:00:00 UTC"},
            {"id": "3", "ioc": "b.example.com", "ioc_type": "domain",
             "threat_type": "botnet_cc", "first_seen": "2024-04-01 00:00:00 UTC"},
            {"id": "4", "ioc": "c.example.com", "ioc_type": "domain",
             "threat_type": "botnet_cc", "first_seen": "garbage"},
        ]
        lines, counts = threatfox_mod.run(iocs, NOW, lookback_hours=2)
        assert len(lines) == 1
        assert counts == {
            "sent": 1, "skipped_old": 1,
            "skipped_unsupported_type": 1, "skipped_unparseable": 1,
        }


# ---------------------------------------------------------------------------
# _read_dotenv_key: fallback .env reader for THREATFOX_AUTH_KEY
# ---------------------------------------------------------------------------

class TestReadDotenvKey:
    def test_reads_matching_key(self, threatfox_mod, tmp_path):
        # SYNTHETIC
        env_file = tmp_path / ".env"
        env_file.write_text("THREATFOX_AUTH_KEY=fake-key-value\nOTHER=ignored\n")
        assert threatfox_mod._read_dotenv_key("THREATFOX_AUTH_KEY", str(env_file)) == "fake-key-value"

    def test_strips_quotes_and_whitespace(self, threatfox_mod, tmp_path):
        # SYNTHETIC
        env_file = tmp_path / ".env"
        env_file.write_text('THREATFOX_AUTH_KEY = "fake-key-value"  \n')
        assert threatfox_mod._read_dotenv_key("THREATFOX_AUTH_KEY", str(env_file)) == "fake-key-value"

    def test_ignores_comments_and_blank_lines(self, threatfox_mod, tmp_path):
        # SYNTHETIC
        env_file = tmp_path / ".env"
        env_file.write_text("# comment\n\nTHREATFOX_AUTH_KEY=fake-key-value\n")
        assert threatfox_mod._read_dotenv_key("THREATFOX_AUTH_KEY", str(env_file)) == "fake-key-value"

    def test_missing_key_returns_empty(self, threatfox_mod, tmp_path):
        # SYNTHETIC
        env_file = tmp_path / ".env"
        env_file.write_text("UNRELATED=value\n")
        assert threatfox_mod._read_dotenv_key("THREATFOX_AUTH_KEY", str(env_file)) == ""

    def test_missing_file_returns_empty(self, threatfox_mod, tmp_path):
        assert threatfox_mod._read_dotenv_key("THREATFOX_AUTH_KEY", str(tmp_path / "nope.env")) == ""
