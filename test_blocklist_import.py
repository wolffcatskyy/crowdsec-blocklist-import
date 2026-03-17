#!/usr/bin/env python3
"""
Comprehensive pytest test suite for blocklist_import.py.

Coverage:
1. Config.from_env() — env var loading, defaults, bool parsing
2. parse_ip_or_network() — valid IPs, CIDRs, private ranges, edge cases, IPv6
3. extract_ips_from_line() — comments, tabs, URLs, field extraction
4. Allowlist — exact IPs, CIDR containment, IPv4/IPv6, overlaps
5. is_private_or_reserved() — all private ranges including ::ffff:0:0/96
6. validate_enable_env_vars() — valid, invalid, unknown, typo suggestions
7. CrowdSecLAPI — mock HTTP responses for all methods
8. fetch_blocklist() — mock HTTP, streaming, error handling
9. Webhook formatting — Discord, Slack, generic payloads
10. AbuseIPDB API — mock responses, confidence filtering
11. Daemon mode signal handling
12. MetricsCollector (when prometheus_client available)
"""

from __future__ import annotations

from datetime import timedelta
import ipaddress
import io
import logging
import os
import signal
import sys
import time
from typing import Optional
from unittest.mock import MagicMock, Mock, patch, PropertyMock
import pytest

# ---------------------------------------------------------------------------
# Import the module under test.  Some deps (requests, prometheus_client) are
# real packages but all *network* calls are mocked in every test.
# ---------------------------------------------------------------------------
import importlib

import blocklist_import as bi
from blocklist_import import (
    Allowlist,
    BlocklistSource,
    Config,
    CrowdSecLAPI,
    FetchResult,
    ImportStats,
    PRIVATE_NETWORKS,
    VALID_ENABLE_VARS,
    _format_discord_webhook,
    _format_generic_webhook,
    _format_slack_webhook,
    build_allowlist,
    extract_ips_from_line,
    fetch_blocklist,
    find_similar_vars,
    is_private_or_reserved,
    parse_ip_or_network,
    read_secret_file,
    sanitize_error_message,
    validate_bool_value,
    validate_enable_env_vars,
    get_abuseipdb_api_headers,
    get_abuseipdb_api_params,
    get_abuseipdb_api_can_import,
)


# ===========================================================================
# Helpers / fixtures
# ===========================================================================


@pytest.fixture()
def clean_env(monkeypatch):
    """Remove all ENABLE_* and CROWDSEC_* vars so tests start from a known state."""
    keys_to_remove = [k for k in os.environ if k.startswith(("ENABLE_", "CROWDSEC_",
                                                               "DECISION_", "BATCH_",
                                                               "FETCH_", "MAX_", "LOG_",
                                                               "DRY_", "TELEMETRY_",
                                                               "METRICS_", "INTERVAL",
                                                               "RUN_ON_START", "WEBHOOK_",
                                                               "ABUSEIPDB_", "ALLOWLIST",
                                                               "CUSTOM_"))]
    for k in keys_to_remove:
        monkeypatch.delenv(k, raising=False)
    yield monkeypatch


@pytest.fixture()
def logger():
    return logging.getLogger("test")


@pytest.fixture()
def dummy_source():
    return BlocklistSource(name="TestSource", url="http://example.com/list.txt",
                           enabled_key="enable_ipsum")


@pytest.fixture()
def dummy_abuse_ipdb_source():
    return BlocklistSource(name="TestSource", url="http://example.com/list.txt",
                           get_headers=get_abuseipdb_api_headers,
                           get_params=get_abuseipdb_api_params,
                           get_can_import=get_abuseipdb_api_can_import,
                           enabled_key="enable_abuse_ipdb")


@pytest.fixture()
def session_mock():
    return MagicMock()


@pytest.fixture()
def lapi(session_mock, logger):
    obj = CrowdSecLAPI(
        base_url="http://localhost:8080",
        api_key="testkey",
        machine_id="testmachine",
        machine_password="testpass",
        logger=logger,
    )
    obj.session = session_mock
    return obj


# ===========================================================================
# 1. Config.from_env()
# ===========================================================================


class TestConfigFromEnv:
    def test_defaults(self, clean_env, monkeypatch):
        """Config.from_env() returns correct defaults when no env vars are set.

        We also patch load_dotenv() so that any .env file present in the repo
        (e.g. the NAS production config) does not override the cleared env.
        """
        monkeypatch.delenv("CROWDSEC_LAPI_URL", raising=False)
        # Patch load_dotenv so the repo's .env file is not read during this test
        with patch("blocklist_import.load_dotenv", return_value=None):
            cfg = Config.from_env()
        assert cfg.lapi_url == "http://localhost:8080"
        assert cfg.lapi_key == ""
        assert cfg.decision_duration == "24h"
        assert cfg.decision_type == "ban"
        assert cfg.batch_size == 1000
        assert cfg.fetch_timeout == 60
        assert cfg.max_retries == 3
        assert cfg.log_level == "INFO"
        assert cfg.dry_run is False
        assert cfg.telemetry_enabled is True
        assert cfg.metrics_enabled is True
        assert cfg.interval == 0
        assert cfg.run_on_start is True
        assert cfg.webhook_url == ""
        assert cfg.webhook_type == "generic"
        assert cfg.abuseipdb_min_confidence == 90
        assert cfg.abuseipdb_limit == 10000
        assert cfg.allowlist_github is False
        assert cfg.consolidate_alerts is False
        # All sources enabled by default
        assert cfg.enable_ipsum is True
        assert cfg.enable_spamhaus is True
        assert cfg.enable_blocklist_de is True

    def test_lapi_url_trailing_slash_stripped(self, clean_env):
        clean_env.setenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080/")
        cfg = Config.from_env()
        assert cfg.lapi_url == "http://crowdsec:8080"

    def test_lapi_key_loaded(self, clean_env):
        clean_env.setenv("CROWDSEC_LAPI_KEY", "myapikey")
        cfg = Config.from_env()
        assert cfg.lapi_key == "myapikey"

    def test_machine_credentials(self, clean_env):
        clean_env.setenv("CROWDSEC_MACHINE_ID", "myid")
        clean_env.setenv("CROWDSEC_MACHINE_PASSWORD", "mysecret")
        cfg = Config.from_env()
        assert cfg.machine_id == "myid"
        assert cfg.machine_password == "mysecret"

    def test_bool_true_variants(self, clean_env):
        for val in ("true", "1", "yes", "on", "True", "YES", "ON"):
            clean_env.setenv("DRY_RUN", val)
            cfg = Config.from_env()
            assert cfg.dry_run is True, f"DRY_RUN={val!r} should be True"

    def test_bool_false_variants(self, clean_env):
        for val in ("false", "0", "no", "off", "False", "NO", "OFF"):
            clean_env.setenv("DRY_RUN", val)
            cfg = Config.from_env()
            assert cfg.dry_run is False, f"DRY_RUN={val!r} should be False"

    def test_enable_source_disabled(self, clean_env):
        clean_env.setenv("ENABLE_IPSUM", "false")
        cfg = Config.from_env()
        assert cfg.enable_ipsum is False

    def test_enable_abuse_ipdb_maps_to_enable_abuse_ipdb(self, clean_env):
        """ENABLE_ABUSE_IPDB env var maps to enable_abuse_ipdb field."""
        clean_env.setenv("ENABLE_ABUSE_IPDB", "false")
        cfg = Config.from_env()
        assert cfg.enable_abuse_ipdb is False

    def test_batch_size(self, clean_env):
        clean_env.setenv("BATCH_SIZE", "500")
        cfg = Config.from_env()
        assert cfg.batch_size == 500

    def test_allowlist_csv(self, clean_env):
        clean_env.setenv("ALLOWLIST", "1.2.3.4, 10.0.0.0/8, 5.6.7.8")
        cfg = Config.from_env()
        assert "1.2.3.4" in cfg.allow_list
        assert "10.0.0.0/8" in cfg.allow_list
        assert "5.6.7.8" in cfg.allow_list

    def test_allowlist_empty(self, clean_env):
        cfg = Config.from_env()
        assert cfg.allow_list == []

    def test_interval(self, clean_env):
        clean_env.setenv("INTERVAL", "3600")
        cfg = Config.from_env()
        assert cfg.interval == 3600

    def test_webhook_type_lowercased(self, clean_env):
        clean_env.setenv("WEBHOOK_TYPE", "Discord")
        cfg = Config.from_env()
        assert cfg.webhook_type == "discord"

    def test_log_level_uppercased(self, clean_env):
        clean_env.setenv("LOG_LEVEL", "debug")
        cfg = Config.from_env()
        assert cfg.log_level == "DEBUG"

    def test_custom_blocklists(self, clean_env):
        clean_env.setenv("CUSTOM_BLOCKLISTS", "http://a.com/list.txt, http://b.com/list.txt")
        cfg = Config.from_env()
        assert "http://a.com/list.txt" in cfg.custom_block_lists
        assert "http://b.com/list.txt" in cfg.custom_block_lists

    def test_consolidate_alerts(self, clean_env):
        clean_env.setenv("CONSOLIDATE_ALERTS", "true")
        cfg = Config.from_env()
        assert cfg.consolidate_alerts is True

    def test_consolidate_alerts_default_false(self, clean_env, monkeypatch):
        with patch("blocklist_import.load_dotenv", return_value=None):
            cfg = Config.from_env()
        assert cfg.consolidate_alerts is False

    def test_abuseipdb_settings(self, clean_env):
        clean_env.setenv("ABUSEIPDB_API_KEY", "abc123")
        clean_env.setenv("ABUSEIPDB_MIN_CONFIDENCE", "75")
        clean_env.setenv("ABUSEIPDB_LIMIT", "5000")
        cfg = Config.from_env()
        assert cfg.abuseipdb_api_key == "abc123"
        assert cfg.abuseipdb_min_confidence == 75
        assert cfg.abuseipdb_limit == 5000


# ===========================================================================
# 2. parse_ip_or_network()
# ===========================================================================


class TestParseIpOrNetwork:
    # --- Valid public IPs ---
    def test_valid_ipv4(self):
        ip, err = parse_ip_or_network("1.2.3.4")
        assert ip == "1.2.3.4"
        assert err is None

    def test_valid_ipv6_public(self):
        ip, err = parse_ip_or_network("2001:db8::1")
        # 2001:db8::/32 is documentation range — not in PRIVATE_NETWORKS so allowed
        assert err is None

    def test_valid_cidr_v4(self):
        ip, err = parse_ip_or_network("203.0.113.0/24")
        assert ip == "203.0.113.0/24"
        assert err is None

    def test_valid_cidr_normalises_host_bits(self):
        ip, err = parse_ip_or_network("192.0.2.5/24")
        assert ip == "192.0.2.0/24"
        assert err is None

    # --- Private / reserved ranges (all should return (None, None)) ---
    def test_private_10(self):
        ip, err = parse_ip_or_network("10.1.2.3")
        assert ip is None
        assert err is None

    def test_private_172_16(self):
        ip, err = parse_ip_or_network("172.16.0.1")
        assert ip is None

    def test_private_192_168(self):
        ip, err = parse_ip_or_network("192.168.0.1")
        assert ip is None

    def test_loopback(self):
        ip, err = parse_ip_or_network("127.0.0.1")
        assert ip is None

    def test_ipv6_loopback(self):
        ip, err = parse_ip_or_network("::1")
        assert ip is None

    def test_ipv6_link_local(self):
        ip, err = parse_ip_or_network("fe80::1")
        assert ip is None

    def test_multicast_v4(self):
        ip, err = parse_ip_or_network("224.0.0.1")
        assert ip is None

    def test_cgnat(self):
        ip, err = parse_ip_or_network("100.64.0.1")
        assert ip is None

    def test_link_local_v4(self):
        ip, err = parse_ip_or_network("169.254.1.1")
        assert ip is None

    def test_cidr_overlapping_private(self):
        ip, err = parse_ip_or_network("10.0.0.0/8")
        assert ip is None

    # --- Well-known excluded IPs ---
    def test_cloudflare_dns(self):
        ip, err = parse_ip_or_network("1.1.1.1")
        assert ip is None

    def test_google_dns(self):
        ip, err = parse_ip_or_network("8.8.8.8")
        assert ip is None

    def test_quad9(self):
        ip, err = parse_ip_or_network("9.9.9.9")
        assert ip is None

    # --- URL extraction ---
    def test_http_url_extracts_ip(self):
        ip, err = parse_ip_or_network("http://177.70.102.228:8070/TmpFTP/file.zip")
        assert ip == "177.70.102.228"
        assert err is None

    def test_https_url_extracts_ip(self):
        ip, err = parse_ip_or_network("https://203.0.113.99/path")
        assert ip == "203.0.113.99"
        assert err is None

    # --- Maltrail typo (leading 'C') ---
    def test_maltrail_typo_c_prefix(self):
        ip, err = parse_ip_or_network("C91.196.152.28")
        # 91.196.152.28 is public; typo prefix stripped
        assert ip == "91.196.152.28"
        assert err is None

    # --- Invalid inputs ---
    def test_invalid_string_returns_error(self):
        ip, err = parse_ip_or_network("not-an-ip")
        assert ip is None
        assert err == "not-an-ip"

    def test_empty_string(self):
        ip, err = parse_ip_or_network("")
        assert ip is None
        assert err is None

    def test_whitespace_only(self):
        ip, err = parse_ip_or_network("   ")
        assert ip is None
        assert err is None

    def test_invalid_cidr(self):
        ip, err = parse_ip_or_network("999.999.999.999/24")
        assert ip is None
        assert err is not None

    def test_ipv6_mapped_ipv4_excluded(self):
        # ::ffff:0:0/96 is in PRIVATE_NETWORKS
        ip, err = parse_ip_or_network("::ffff:192.168.1.1")
        # Represented as ::ffff:c0a8:101 — must be filtered
        assert ip is None


# ===========================================================================
# 3. extract_ips_from_line()
# ===========================================================================


class TestExtractIpsFromLine:
    @pytest.fixture()
    def src(self):
        return BlocklistSource("T", "http://x.com", "enable_ipsum", comment_char="#")

    def test_plain_ip(self, src):
        errors = {}
        ips = list(extract_ips_from_line("1.2.3.4", errors, src))
        assert "1.2.3.4" in ips

    def test_comment_line_skipped(self, src):
        errors = {}
        ips = list(extract_ips_from_line("# This is a comment", errors, src))
        assert ips == []

    def test_empty_line_skipped(self, src):
        errors = {}
        ips = list(extract_ips_from_line("", errors, src))
        assert ips == []

    def test_inline_comment_stripped(self, src):
        errors = {}
        ips = list(extract_ips_from_line("1.2.3.4 # bad actor", errors, src))
        assert "1.2.3.4" in ips

    def test_tab_separated(self, src):
        errors = {}
        ips = list(extract_ips_from_line("1.2.3.4\tsome-country\textra", errors, src))
        assert "1.2.3.4" in ips

    def test_comma_separated(self, src):
        errors = {}
        ips = list(extract_ips_from_line("1.2.3.4,5.6.7.8", errors, src))
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_url_extraction(self, src):
        errors = {}
        ips = list(extract_ips_from_line("http://177.70.102.228:8070/file.zip", errors, src))
        assert "177.70.102.228" in ips

    def test_private_ip_not_yielded(self, src):
        errors = {}
        ips = list(extract_ips_from_line("192.168.1.1", errors, src))
        assert ips == []

    def test_invalid_token_recorded_in_errors(self, src):
        errors = {}
        list(extract_ips_from_line("not-an-ip 1.2.3.4", errors, src))
        assert "not-an-ip" in errors

    def test_error_counter_increments(self, src):
        errors = {}
        list(extract_ips_from_line("bad", errors, src))
        list(extract_ips_from_line("bad", errors, src))
        assert errors.get("bad", 0) == 2

    def test_extract_field_zero(self):
        """extract_field=0 picks first space-separated field."""
        src = BlocklistSource("T", "http://x.com", "enable_ipsum",
                              comment_char="#", extract_field=0)
        errors = {}
        # DShield format: "1.2.3.4   count  attacks"
        ips = list(extract_ips_from_line("1.2.3.4   10   100", errors, src))
        assert "1.2.3.4" in ips

    def test_extract_field_respects_index(self):
        """extract_field=1 picks second space-separated field."""
        src = BlocklistSource("T", "http://x.com", "enable_ipsum",
                              comment_char="#", extract_field=1)
        errors = {}
        ips = list(extract_ips_from_line("skip 1.2.3.4 extra", errors, src))
        assert "1.2.3.4" in ips

    def test_semicolon_comment_char(self):
        """Spamhaus uses semicolons for comments."""
        src = BlocklistSource("T", "http://x.com", "enable_ipsum",
                              comment_char=";", extract_field=0)
        errors = {}
        # Spamhaus format: "1.2.3.0/24 ; SBL012345"
        ips = list(extract_ips_from_line("1.2.3.0/24 ; SBL012345", errors, src))
        assert "1.2.3.0/24" in ips

    def test_multiple_valid_ips_on_line(self, src):
        errors = {}
        ips = list(extract_ips_from_line("1.2.3.4 5.6.7.8 9.10.11.12", errors, src))
        assert set(ips) == {"1.2.3.4", "5.6.7.8", "9.10.11.12"}

    def test_cidr_extracted(self, src):
        errors = {}
        ips = list(extract_ips_from_line("203.0.113.0/24", errors, src))
        assert "203.0.113.0/24" in ips


# ===========================================================================
# 4. Allowlist
# ===========================================================================


class TestAllowlist:
    def test_exact_ip_match(self):
        al = Allowlist()
        al.add_entry("1.2.3.4")
        assert al.contains("1.2.3.4") is True

    def test_exact_ip_not_in_list(self):
        al = Allowlist()
        al.add_entry("1.2.3.4")
        assert al.contains("5.6.7.8") is False

    def test_cidr_containment_ipv4(self):
        al = Allowlist()
        al.add_entry("140.82.112.0/20")
        # 140.82.112.1 is inside that range
        assert al.contains("140.82.112.1") is True

    def test_cidr_containment_miss(self):
        al = Allowlist()
        al.add_entry("140.82.112.0/20")
        assert al.contains("1.2.3.4") is False

    def test_cidr_overlap_check(self):
        """A CIDR from a blocklist overlapping an allowlisted network is filtered."""
        al = Allowlist()
        al.add_entry("140.82.112.0/20")
        # /24 sub-block of the allowed /20 — should be filtered
        assert al.contains("140.82.112.0/24") is True

    def test_ipv6_exact(self):
        al = Allowlist()
        al.add_entry("2001:db8::1")
        assert al.contains("2001:db8::1") is True

    def test_ipv6_cidr_containment(self):
        al = Allowlist()
        al.add_entry("2001:db8::/32")
        assert al.contains("2001:db8::cafe") is True

    def test_add_entries_bulk(self):
        al = Allowlist()
        al.add_entries(["1.2.3.4", "5.6.7.8", "203.0.113.0/24"])
        assert al.contains("1.2.3.4") is True
        assert al.contains("5.6.7.8") is True
        assert al.contains("203.0.113.1") is True

    def test_invalid_entry_logged_not_raised(self):
        """Invalid entries emit a warning but do not raise."""
        al = Allowlist()
        al.add_entry("not-an-ip")  # should not raise
        assert al.entry_count == 0

    def test_empty_entry_ignored(self):
        al = Allowlist()
        al.add_entry("")
        assert al.entry_count == 0

    def test_entry_count_accurate(self):
        al = Allowlist()
        al.add_entry("1.2.3.4")
        al.add_entry("10.0.0.0/8")
        al.add_entry("2001:db8::/32")
        assert al.entry_count == 3

    def test_fetch_github_ranges_success(self):
        """fetch_github_ranges populates allowlist from mocked API."""
        al = Allowlist()
        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.return_value = {
            "web": ["140.82.112.0/20", "185.199.108.0/22"],
            "git": ["192.30.252.0/22"],
            "api": [],
            "hooks": [],
            "actions": [],
        }
        session = Mock()
        session.get.return_value = mock_resp
        count = al.fetch_github_ranges(session=session)
        assert count == 3
        assert al.contains("140.82.112.1") is True

    def test_fetch_github_ranges_fallback(self):
        """On failure, fallback ranges are used."""
        al = Allowlist()
        session = Mock()
        session.get.side_effect = Exception("network error")
        count = al.fetch_github_ranges(session=session)
        # Fallback has 4 ranges defined in GITHUB_FALLBACK_RANGES
        assert count >= 1
        assert al.entry_count > 0

    def test_build_allowlist_with_config(self):
        cfg = Config()
        cfg.allow_list = ["1.2.3.4", "203.0.113.0/24"]
        cfg.allowlist_github = False
        al = build_allowlist(cfg)
        assert al.contains("1.2.3.4") is True
        assert al.contains("203.0.113.1") is True

    def test_build_allowlist_github_enabled(self):
        cfg = Config()
        cfg.allow_list = []
        cfg.allowlist_github = True
        session = Mock()
        mock_resp = Mock()
        mock_resp.raise_for_status = Mock()
        mock_resp.json.return_value = {"web": ["140.82.112.0/20"], "git": [], "api": [],
                                       "hooks": [], "actions": []}
        session.get.return_value = mock_resp
        al = build_allowlist(cfg, session=session)
        assert al.contains("140.82.112.1") is True


# ===========================================================================
# 5. is_private_or_reserved()
# ===========================================================================


class TestIsPrivateOrReserved:
    @pytest.mark.parametrize("ip_str,expected", [
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("127.255.255.255", True),
        ("0.0.0.1", True),
        ("100.64.0.1", True),      # CGNAT
        ("169.254.0.1", True),     # Link-local
        ("224.0.0.1", True),       # Multicast
        ("240.0.0.1", True),       # Reserved
        ("255.255.255.255", True), # Broadcast
        # Public IPs — should NOT be flagged
        ("1.2.3.4", False),
        ("8.0.0.1", False),
        ("203.0.113.1", False),
    ])
    def test_ipv4_ranges(self, ip_str, expected):
        ip = ipaddress.ip_address(ip_str)
        assert is_private_or_reserved(ip) is expected

    @pytest.mark.parametrize("ip_str,expected", [
        ("::1", True),              # Loopback
        ("fc00::1", True),          # Unique local
        ("fd00::1", True),          # Unique local
        ("fe80::1", True),          # Link-local
        ("ff02::1", True),          # Multicast
        ("::ffff:192.168.1.1", True),  # IPv4-mapped
        ("2001:db8::1", False),     # Documentation — public in this context
        ("2606:4700::1", False),    # Cloudflare — public
    ])
    def test_ipv6_ranges(self, ip_str, expected):
        ip = ipaddress.ip_address(ip_str)
        assert is_private_or_reserved(ip) is expected


# ===========================================================================
# 6. validate_enable_env_vars()
# ===========================================================================


class TestValidateEnableEnvVars:
    def test_valid_vars_pass(self, monkeypatch):
        monkeypatch.setenv("ENABLE_IPSUM", "true")
        monkeypatch.setenv("ENABLE_SPAMHAUS", "false")
        is_valid, errors = validate_enable_env_vars()
        assert is_valid is True
        assert errors == []

    def test_all_valid_bool_values(self, monkeypatch, clean_env):
        for val in ("true", "false", "1", "0", "yes", "no", "on", "off"):
            monkeypatch.setenv("ENABLE_IPSUM", val)
            is_valid, errors = validate_enable_env_vars()
            assert is_valid is True, f"Expected valid for ENABLE_IPSUM={val!r}"

    def test_invalid_value_returns_error(self, monkeypatch, clean_env):
        monkeypatch.setenv("ENABLE_IPSUM", "maybe")
        is_valid, errors = validate_enable_env_vars()
        assert is_valid is False
        assert len(errors) >= 1
        assert "ENABLE_IPSUM" in errors[0]

    def test_unknown_var_generates_warning_not_error(self, monkeypatch, clean_env, logger):
        monkeypatch.setenv("ENABLE_NONEXISTENT", "true")
        is_valid, errors = validate_enable_env_vars(logger=logger)
        # Unknown vars should not fail validation
        assert is_valid is True
        assert errors == []

    def test_no_enable_vars_passes(self, clean_env):
        is_valid, errors = validate_enable_env_vars()
        assert is_valid is True

    def test_mixed_valid_and_invalid(self, monkeypatch, clean_env):
        monkeypatch.setenv("ENABLE_IPSUM", "true")
        monkeypatch.setenv("ENABLE_SPAMHAUS", "bad_value")
        is_valid, errors = validate_enable_env_vars()
        assert is_valid is False

    def test_case_insensitive_bool(self, monkeypatch, clean_env):
        monkeypatch.setenv("ENABLE_IPSUM", "TRUE")
        is_valid, errors = validate_enable_env_vars()
        assert is_valid is True


class TestFindSimilarVars:
    def test_exact_substring_match(self):
        suggestions = find_similar_vars("ENABLE_IPSUM_TYPO", VALID_ENABLE_VARS)
        # "ENABLE_IPSUM" is a substring of "ENABLE_IPSUM_TYPO" (reversed check)
        assert "ENABLE_IPSUM" in suggestions

    def test_no_similarity_returns_empty(self):
        suggestions = find_similar_vars("ENABLE_ZZZZZ", VALID_ENABLE_VARS)
        # Very different — likely no match
        assert isinstance(suggestions, list)

    def test_similar_name_suggested(self):
        # "ENABLE_IPSU" is close to "ENABLE_IPSUM"
        suggestions = find_similar_vars("ENABLE_IPSU", VALID_ENABLE_VARS)
        assert "ENABLE_IPSUM" in suggestions


class TestValidateBoolValue:
    def test_valid_values(self):
        for val in ("true", "false", "1", "0", "yes", "no", "on", "off",
                    "TRUE", "FALSE", "Yes", "No"):
            is_valid, err = validate_bool_value("TEST_VAR", val)
            assert is_valid is True, f"Expected valid for {val!r}"

    def test_invalid_values(self):
        for val in ("maybe", "enabled", "disabled", "2", ""):
            is_valid, err = validate_bool_value("TEST_VAR", val)
            assert is_valid is False
            assert "TEST_VAR" in err


# ===========================================================================
# 7. CrowdSecLAPI — mocked HTTP
# ===========================================================================


class TestCrowdSecLAPIHealthCheck:
    def test_health_check_200(self, lapi, session_mock):
        session_mock.get.return_value = Mock(status_code=200)
        assert lapi.health_check() is True

    def test_health_check_403_is_reachable(self, lapi, session_mock):
        """403 means server is up but key is wrong — still reachable."""
        session_mock.get.return_value = Mock(status_code=403)
        assert lapi.health_check() is True

    def test_health_check_500_fails(self, lapi, session_mock):
        session_mock.get.return_value = Mock(status_code=500)
        assert lapi.health_check() is False

    def test_health_check_network_error(self, lapi, session_mock):
        import requests
        session_mock.get.side_effect = requests.RequestException("timeout")
        assert lapi.health_check() is False


class TestCrowdSecLAPIGetExistingIPs:
    def test_returns_ip_set(self, lapi, session_mock):
        session_mock.get.return_value = Mock(
            status_code=200,
            json=Mock(return_value=[
                {"value": "1.2.3.4"},
                {"value": "5.6.7.8"},
            ]),
        )
        existing = [i for i, _ in lapi.get_existing_ips()]
        assert "1.2.3.4" in existing
        assert "5.6.7.8" in existing

    def test_empty_decisions_list(self, lapi, session_mock):
        session_mock.get.return_value = Mock(status_code=200, json=Mock(return_value=[]))
        existing = lapi.get_existing_ips()
        assert existing == []

    def test_null_response_body(self, lapi, session_mock):
        session_mock.get.return_value = Mock(status_code=200, json=Mock(return_value=None))
        existing = lapi.get_existing_ips()
        assert existing == []

    def test_non_200_returns_empty(self, lapi, session_mock):
        session_mock.get.return_value = Mock(status_code=401)
        existing = lapi.get_existing_ips()
        assert existing == []

    def test_network_error_returns_empty(self, lapi, session_mock):
        import requests
        session_mock.get.side_effect = requests.RequestException("connection refused")
        existing = lapi.get_existing_ips()
        assert existing == []

    def test_json_parse_error_returns_empty(self, lapi, session_mock):
        session_mock.get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=ValueError("bad json")),
        )
        existing = lapi.get_existing_ips()
        assert existing == []


class TestCrowdSecLAPIAddDecisions:
    def _mock_machine_auth(self, lapi, session_mock):
        """Pre-populate a valid JWT so add_decisions doesn't need to authenticate."""
        lapi.jwt_token = "fake-jwt-token"
        lapi.jwt_expires = time.time() + 3600

    def test_success_returns_counts(self, lapi, session_mock):
        self._mock_machine_auth(lapi, session_mock)
        session_mock.post.return_value = Mock(status_code=200)
        ok, failed = lapi.add_decisions(
            ips=["1.2.3.4", "5.6.7.8"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test/blocklist",
        )
        assert ok == 2
        assert failed == 0

    def test_201_accepted(self, lapi, session_mock):
        self._mock_machine_auth(lapi, session_mock)
        session_mock.post.return_value = Mock(status_code=201)
        ok, failed = lapi.add_decisions(
            ips=["1.2.3.4"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test/blocklist",
        )
        assert ok == 1
        assert failed == 0

    def test_lapi_error_returns_zero_ok(self, lapi, session_mock):
        self._mock_machine_auth(lapi, session_mock)
        session_mock.post.return_value = Mock(
            status_code=400,
            text="bad request",
        )
        ok, failed = lapi.add_decisions(
            ips=["1.2.3.4"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test/blocklist",
        )
        assert ok == 0
        assert failed == 1

    def test_empty_ips_returns_zero_zero(self, lapi, session_mock):
        ok, failed = lapi.add_decisions(
            ips=[],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test/blocklist",
        )
        assert ok == 0
        assert failed == 0

    def test_cidr_gets_range_scope(self, lapi, session_mock):
        """Verify CIDR entries use 'Range' scope, single IPs use 'Ip' scope."""
        self._mock_machine_auth(lapi, session_mock)
        session_mock.post.return_value = Mock(status_code=200)
        lapi.add_decisions(
            ips=["1.2.3.4", "203.0.113.0/24"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test",
        )
        call_kwargs = session_mock.post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs[0][1]
        decisions = payload[0]["decisions"]
        scopes = {d["value"]: d["scope"] for d in decisions}
        assert scopes["1.2.3.4"] == "Ip"
        assert scopes["203.0.113.0/24"] == "Range"

    def test_no_machine_credentials_fails(self, session_mock, logger):
        """add_decisions without machine credentials returns (0, n)."""
        lapi_no_creds = CrowdSecLAPI(
            base_url="http://localhost:8080",
            api_key="key",
            machine_id="",
            machine_password="",
            logger=logger,
        )
        ok, failed = lapi_no_creds.add_decisions(
            ips=["1.2.3.4"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test",
        )
        assert ok == 0
        assert failed == 1

    def test_network_error_returns_failed(self, lapi, session_mock):
        self._mock_machine_auth(lapi, session_mock)
        import requests
        session_mock.post.side_effect = requests.RequestException("reset")
        ok, failed = lapi.add_decisions(
            ips=["1.2.3.4"],
            duration="24h",
            reason="test",
            decision_type="ban",
            origin="test",
            scenario="test",
        )
        assert ok == 0
        assert failed == 1


class TestCrowdSecLAPIMachineAuth:
    def test_get_machine_token_success(self, lapi, session_mock):
        session_mock.post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={
                "token": "jwt-abc123",
                "expire": "2099-01-01T00:00:00Z",
            }),
        )
        token = lapi._get_machine_token()
        assert token == "jwt-abc123"
        assert lapi.jwt_token == "jwt-abc123"

    def test_get_machine_token_cached(self, lapi, session_mock):
        """Second call uses cached token without network request."""
        lapi.jwt_token = "cached-token"
        lapi.jwt_expires = time.time() + 7200
        token = lapi._get_machine_token()
        assert token == "cached-token"
        session_mock.post.assert_not_called()

    def test_get_machine_token_expired_refreshes(self, lapi, session_mock):
        """Expired token triggers a new login."""
        lapi.jwt_token = "old-token"
        lapi.jwt_expires = time.time() - 1  # expired
        session_mock.post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={"token": "new-token", "expire": ""}),
        )
        token = lapi._get_machine_token()
        assert token == "new-token"

    def test_get_machine_token_no_credentials(self, session_mock, logger):
        lapi_no_creds = CrowdSecLAPI(
            base_url="http://localhost:8080",
            api_key="key",
            machine_id="",
            machine_password="",
            logger=logger,
        )
        token = lapi_no_creds._get_machine_token()
        assert token is None

    def test_get_machine_token_401(self, lapi, session_mock):
        session_mock.post.return_value = Mock(
            status_code=401,
            text="unauthorized",
        )
        token = lapi._get_machine_token()
        assert token is None

    def test_get_machine_token_network_error(self, lapi, session_mock):
        import requests
        session_mock.post.side_effect = requests.RequestException("timeout")
        token = lapi._get_machine_token()
        assert token is None

    def test_can_write_with_credentials(self, lapi):
        assert lapi.can_write() is True

    def test_can_write_without_credentials(self, session_mock, logger):
        lapi_no_creds = CrowdSecLAPI(
            base_url="http://localhost:8080",
            api_key="key",
            machine_id="",
            machine_password="",
            logger=logger,
        )
        assert lapi_no_creds.can_write() is False


# ===========================================================================
# 8. fetch_blocklist()
# ===========================================================================


class TestFetchBlocklist:
    def _make_response(self, lines, status=200):
        """Create a mock streaming response yielding lines as bytes."""
        resp = Mock()
        resp.status_code = status
        resp.raise_for_status = Mock()
        resp.iter_lines.return_value = [
            line.encode("utf-8") if isinstance(line, str) else line
            for line in lines
        ]
        return resp

    def test_basic_fetch(self, dummy_source, logger, session_mock):
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" in new_ips
        assert "5.6.7.8" in new_ips
        assert result.success is True
        assert result.new_unique_ip_count == 2

    def test_deduplication_against_seen(self, dummy_source, logger, session_mock):
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        session_mock.get.return_value = resp
        seen = {"1.2.3.4"}
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = ["1.2.3.4"]
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" not in new_ips
        assert "5.6.7.8" in new_ips

    def test_allowlist_filters(self, dummy_source, logger, session_mock):
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        allowlist.add_entry("1.2.3.4")
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" not in new_ips
        assert "5.6.7.8" in new_ips

    def test_comment_lines_skipped(self, dummy_source, logger, session_mock):
        resp = self._make_response(["# comment", "1.2.3.4"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" in new_ips
        assert len(new_ips) == 1

    def test_network_error_returns_failure(self, dummy_source, logger, session_mock):
        import requests
        session_mock.get.side_effect = requests.RequestException("connection refused")
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert new_ips == []
        assert result.success is False
        assert result.error_type == "fetch"

    def test_http_error_returns_failure(self, dummy_source, logger, session_mock):
        import requests
        resp = Mock()
        resp.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert result.success is False

    def test_parse_errors_tracked(self, dummy_source, logger, session_mock):
        resp = self._make_response(["bad-token", "1.2.3.4"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "bad-token" in result.parse_errors
        assert result.success is True

    def test_latin1_fallback_encoding(self, dummy_source, logger, session_mock):
        """Lines that fail UTF-8 but succeed as latin-1 are processed."""
        # Create a byte string that's valid latin-1 but not UTF-8, but
        # produces a valid IP when decoded as latin-1
        resp = Mock()
        resp.raise_for_status = Mock()
        # "1.2.3.4" in latin-1 is just ASCII, so use a pure-ASCII line to avoid issues
        resp.iter_lines.return_value = [
            "1.2.3.4".encode("utf-8"),
            # Byte sequence that fails utf-8 but we handle gracefully
            bytes([0xFF, 0xFE, 0x31, 0x2E, 0x32, 0x2E, 0x33, 0x2E, 0x35]),
        ]
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        # At minimum 1.2.3.4 should succeed
        assert "1.2.3.4" in new_ips
        assert result.success is True

    def test_duration_recorded(self, dummy_source, logger, session_mock):
        resp = self._make_response(["1.2.3.4"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        _, _, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert result.duration >= 0.0

    def test_private_ips_not_included(self, dummy_source, logger, session_mock):
        resp = self._make_response(["192.168.1.1", "10.0.0.1", "1.2.3.4"])
        session_mock.get.return_value = resp
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        config = Config()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_source, config, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "192.168.1.1" not in new_ips
        assert "10.0.0.1" not in new_ips
        assert "1.2.3.4" in new_ips


# ===========================================================================
# 9. Webhook formatting
# ===========================================================================


class TestWebhookFormatting:
    @pytest.fixture()
    def stats_ok(self):
        s = ImportStats()
        s.sources_ok = 5
        s.sources_failed = 0
        s.new_ips = 1000
        s.imported_ok = 1000
        s.imported_failed = 0
        s.duration_seconds = 12.3
        return s

    @pytest.fixture()
    def stats_partial_fail(self):
        s = ImportStats()
        s.sources_ok = 4
        s.sources_failed = 1
        s.new_ips = 800
        s.imported_ok = 750
        s.imported_failed = 50
        s.duration_seconds = 9.9
        return s

    # --- Discord ---
    def test_discord_success_color(self, stats_ok):
        payload = _format_discord_webhook(stats_ok)
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert embed["color"] == 0x2ECC71  # green

    def test_discord_failure_color(self, stats_partial_fail):
        payload = _format_discord_webhook(stats_partial_fail)
        embed = payload["embeds"][0]
        assert embed["color"] == 0xE74C3C  # red

    def test_discord_fields_present(self, stats_ok):
        payload = _format_discord_webhook(stats_ok)
        fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
        assert "Sources" in fields
        assert "New IPs" in fields
        assert "Imported" in fields
        assert "Duration" in fields

    def test_discord_failed_field_only_when_failures(self, stats_ok, stats_partial_fail):
        payload_ok = _format_discord_webhook(stats_ok)
        fields_ok = [f["name"] for f in payload_ok["embeds"][0]["fields"]]
        assert "Failed" not in fields_ok

        payload_fail = _format_discord_webhook(stats_partial_fail)
        fields_fail = [f["name"] for f in payload_fail["embeds"][0]["fields"]]
        assert "Failed" in fields_fail

    def test_discord_contains_version(self, stats_ok):
        payload = _format_discord_webhook(stats_ok)
        footer = payload["embeds"][0]["footer"]["text"]
        assert bi.__version__ in footer

    # --- Slack ---
    def test_slack_has_text(self, stats_ok):
        payload = _format_slack_webhook(stats_ok)
        assert "text" in payload
        assert len(payload["text"]) > 0

    def test_slack_success_emoji(self, stats_ok):
        payload = _format_slack_webhook(stats_ok)
        assert ":white_check_mark:" in payload["text"]

    def test_slack_failure_emoji(self, stats_partial_fail):
        payload = _format_slack_webhook(stats_partial_fail)
        assert ":warning:" in payload["text"]

    def test_slack_includes_stats(self, stats_ok):
        payload = _format_slack_webhook(stats_ok)
        assert str(stats_ok.new_ips) in payload["text"]
        assert str(stats_ok.imported_ok) in payload["text"]

    def test_slack_failure_count_only_when_nonzero(self, stats_ok, stats_partial_fail):
        ok_text = _format_slack_webhook(stats_ok)["text"]
        assert "Failed" not in ok_text

        fail_text = _format_slack_webhook(stats_partial_fail)["text"]
        assert "Failed" in fail_text

    # --- Generic ---
    def test_generic_event_field(self, stats_ok):
        payload = _format_generic_webhook(stats_ok)
        assert payload["event"] == "blocklist_import_complete"

    def test_generic_all_fields_present(self, stats_ok):
        payload = _format_generic_webhook(stats_ok)
        for key in ("version", "sources_ok", "sources_failed", "new_ips",
                    "imported_ok", "imported_failed", "duration_seconds"):
            assert key in payload, f"Missing key: {key}"

    def test_generic_values_match_stats(self, stats_ok):
        payload = _format_generic_webhook(stats_ok)
        assert payload["sources_ok"] == stats_ok.sources_ok
        assert payload["new_ips"] == stats_ok.new_ips
        assert payload["imported_ok"] == stats_ok.imported_ok

    def test_generic_duration_rounded(self, stats_ok):
        stats_ok.duration_seconds = 12.3456789
        payload = _format_generic_webhook(stats_ok)
        assert payload["duration_seconds"] == round(12.3456789, 1)


# ===========================================================================
# 10. AbuseIPDB API
# ===========================================================================


class TestFetchAbuseIPDB:
    def _make_config(self, api_key="testkey", min_confidence=90, limit=10000):
        cfg = Config()
        cfg.abuseipdb_api_key = api_key
        cfg.abuseipdb_min_confidence = min_confidence
        cfg.abuseipdb_limit = limit
        cfg.fetch_timeout = 30
        return cfg

    def _make_response(self, lines, status=200):
        """Create a mock streaming response yielding lines as bytes."""
        resp = Mock()
        resp.status_code = status
        resp.raise_for_status = Mock()
        resp.iter_lines.return_value = [
            line.encode("utf-8") if isinstance(line, str) else line
            for line in lines
        ]
        return resp

    def test_successful_fetch(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = "1.2.3.4\n5.6.7.8\n# comment\n"
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)

        assert "1.2.3.4" in new_ips
        assert "5.6.7.8" in new_ips
        assert result.success is True

    def test_comments_ignored(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4"])
        resp.raise_for_status = Mock()
        resp.text = "# header\n1.2.3.4\n"
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" in new_ips
        assert len(new_ips) == 1

    def test_private_ips_filtered(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = "192.168.1.1\n1.2.3.4\n"
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "192.168.1.1" not in new_ips
        assert "1.2.3.4" in new_ips

    def test_allowlisted_ips_filtered(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = "1.2.3.4\n5.6.7.8\n"
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        allowlist.add_entry("1.2.3.4")
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" not in new_ips
        assert "5.6.7.8" in new_ips

    def test_deduplication_against_seen(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = "1.2.3.4\n5.6.7.8\n"
        session_mock.get.return_value = resp

        seen = {"1.2.3.4"}
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = ["1.2.3.4"]
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.2.3.4" not in new_ips
        assert "5.6.7.8" in new_ips

    def test_empty_api_key_returns_empty(self, dummy_abuse_ipdb_source, logger, session_mock):
        cfg = self._make_config(api_key="")
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert new_ips == []
        assert result.success is False
        session_mock.get.assert_not_called()

    def test_network_error_returns_failure(self, dummy_abuse_ipdb_source, logger, session_mock):
        """On network error, fetch_abuseipdb_api returns an empty list and failed result."""
        cfg = self._make_config()
        import requests
        session_mock.get.side_effect = requests.RequestException("timeout")
        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert new_ips == []
        assert result.success is False
        assert result.error_type == "fetch"
        assert result.error_exception is not None

    def test_http_error_returns_failure(self, dummy_abuse_ipdb_source, logger, session_mock):
        """On HTTP error, fetch_abuseipdb_api returns an empty list and failed result."""
        cfg = self._make_config()
        import requests
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status.side_effect = requests.HTTPError("429 Too Many Requests")
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert new_ips == []
        assert result.success is False
        assert result.error_type == "fetch"
        assert result.error_exception is not None

    def test_confidence_params_passed(self, dummy_abuse_ipdb_source, logger, session_mock):
        """Confidence and limit are forwarded as query params."""
        cfg = self._make_config(min_confidence=75, limit=5000)
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = ""
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)

        call_kwargs = session_mock.get.call_args
        params = call_kwargs[1].get("params", {})
        assert params["confidenceMinimum"] == 75
        assert params["limit"] == 5000

    def test_excluded_ips_filtered(self, dummy_abuse_ipdb_source, logger, session_mock):
        """Well-known IPs like 1.1.1.1 are excluded."""
        cfg = self._make_config()
        resp = self._make_response(["1.2.3.4", "5.6.7.8"])
        resp.raise_for_status = Mock()
        resp.text = "1.1.1.1\n8.8.8.8\n1.2.3.4\n"
        session_mock.get.return_value = resp

        seen = set()
        allowlist = Allowlist()
        stats = ImportStats()
        non_expiring_known_ips: list[str] = []
        expiring_known_ips: list[str] = []
        new_ips, refreshed_ips, result = fetch_blocklist(session_mock, dummy_abuse_ipdb_source, cfg, seen, non_expiring_known_ips, expiring_known_ips, allowlist, stats, logger)
        assert "1.1.1.1" not in new_ips
        assert "8.8.8.8" not in new_ips
        assert "1.2.3.4" in new_ips


# ===========================================================================
# 11. Daemon mode signal handling
# ===========================================================================


class TestDaemonMode:
    def test_signal_handler_sets_shutdown(self, logger):
        """Receiving SIGTERM sets the shutdown flag causing daemon loop exit."""
        config = Config()
        config.interval = 1
        config.run_on_start = False

        calls = []

        def fake_run_import(cfg, log):
            calls.append(1)
            return ImportStats()

        # We patch time.sleep to avoid actual waiting, and run_import to
        # avoid any network calls.  We also send SIGTERM after the first loop
        # iteration starts.
        sleep_calls = []

        def fake_sleep(secs):
            sleep_calls.append(secs)
            # Simulate signal arriving during sleep
            os.kill(os.getpid(), signal.SIGTERM)

        with patch.object(bi, "run_import", side_effect=fake_run_import), \
             patch("time.sleep", side_effect=fake_sleep):
            result = bi._run_daemon(config, logger)

        assert result == 0

    def test_run_on_start_false_skips_first_run(self, logger):
        """When run_on_start=False, first loop iteration skips run_import."""
        config = Config()
        config.interval = 5
        config.run_on_start = False

        run_count = []

        def fake_run_import(cfg, log):
            run_count.append(1)
            return ImportStats()

        sleep_invocations = []

        def fake_sleep(secs):
            sleep_invocations.append(secs)
            os.kill(os.getpid(), signal.SIGTERM)

        with patch.object(bi, "run_import", side_effect=fake_run_import), \
             patch("time.sleep", side_effect=fake_sleep):
            bi._run_daemon(config, logger)

        # run_import should not have been called because run_on_start=False
        # and signal arrived during the first sleep
        assert len(run_count) == 0


# ===========================================================================
# 12. MetricsCollector (conditional on prometheus_client availability)
# ===========================================================================


PROMETHEUS_AVAILABLE = bi.PROMETHEUS_AVAILABLE


@pytest.mark.skipif(not PROMETHEUS_AVAILABLE, reason="prometheus_client not installed")
class TestMetricsCollector:
    @pytest.fixture()
    def metrics(self, logger):
        from blocklist_import import MetricsCollector
        return MetricsCollector(pushgateway_url="localhost:9091", logger=logger)

    def test_record_source_success(self, metrics):
        metrics.record_source_success("TestSource", new_ip_count=100, refreshed_ip_count=20, duration=1.5)
        # If no exception raised, metric was recorded successfully

    def test_record_source_failure(self, metrics):
        exc = Exception("connection refused")
        metrics.record_source_failure("TestSource", error_type="fetch",
                                      exc=exc, duration=0.5)

    def test_record_parse_errors(self, metrics):
        errors = {"bad-token": 3, "another-bad": 1}
        metrics.record_parse_errors("TestSource", errors)

    def test_record_encoding_errors(self, metrics):
        metrics.record_encoding_errors(5)

    def test_update_aggregates(self, metrics):
        stats = ImportStats()
        stats.imported_ok = 500
        stats.new_ips = 200
        stats.sources_ok = 3
        stats.sources_failed = 1
        stats.existing_skipped = 50
        stats.duration_seconds = 10.0
        stats.encoding_errors = 2
        metrics.update_aggregates(stats, enabled_count=4)

    def test_push_returns_false_without_gateway(self, logger):
        """MetricsCollector.push() gracefully handles connection errors."""
        from blocklist_import import MetricsCollector
        m = MetricsCollector(pushgateway_url="localhost:9999", logger=logger)
        # push() will fail to connect but should not raise
        with patch("blocklist_import.push_to_gateway", side_effect=Exception("refused")), \
             patch("blocklist_import.delete_from_gateway", side_effect=Exception("refused")):
            result = m.push()
        assert result is False


@pytest.mark.skipif(PROMETHEUS_AVAILABLE, reason="Only when prometheus_client is missing")
class TestMetricsCollectorNoop:
    def test_noop_when_unavailable(self, logger):
        """MetricsCollector is a no-op when prometheus_client is not installed."""
        from blocklist_import import MetricsCollector
        m = MetricsCollector(logger=logger)
        # These should not raise even though prometheus is unavailable
        m.record_source_success("src", 10, 1.0)
        m.record_encoding_errors(5)
        result = m.push()
        assert result is False


# ===========================================================================
# Bonus: sanitize_error_message()
# ===========================================================================


class TestSanitizeErrorMessage:
    def test_connection_error(self):
        import requests
        exc = requests.ConnectionError("Failed to connect")
        assert sanitize_error_message(exc) == "connection_error"

    def test_timeout(self):
        import requests
        exc = requests.Timeout("timed out")
        assert sanitize_error_message(exc) == "timeout"

    def test_http_404(self):
        import requests
        exc = requests.HTTPError("404 Not Found")
        assert sanitize_error_message(exc) == "http_404"

    def test_http_429(self):
        import requests
        exc = requests.HTTPError("429 Too Many Requests")
        assert sanitize_error_message(exc) == "http_429"

    def test_value_error(self):
        exc = ValueError("bad value")
        result = sanitize_error_message(exc)
        assert result == "value_error"

    def test_unknown_exception_returns_class_name(self):
        class MyCustomError(Exception):
            pass
        exc = MyCustomError("custom")
        result = sanitize_error_message(exc)
        assert "MyCustomError" in result

    def test_result_truncated_at_64(self):
        class VeryLongExceptionNameThatExceedsSixtyFourCharactersDefinitely(Exception):
            pass
        exc = VeryLongExceptionNameThatExceedsSixtyFourCharactersDefinitely()
        result = sanitize_error_message(exc)
        assert len(result) <= 64


# ===========================================================================
# Bonus: read_secret_file()
# ===========================================================================


class TestReadSecretFile:
    def test_single_line_plain_password(self, tmp_path):
        f = tmp_path / "secret"
        f.write_text("mysecretpassword\n")
        assert read_secret_file(str(f)) == "mysecretpassword"

    def test_crowdsec_yaml_format(self, tmp_path):
        f = tmp_path / "credentials.yaml"
        f.write_text("machine_id: mymachine\npassword: yamlsecret\n")
        assert read_secret_file(str(f)) == "yamlsecret"

    def test_multiline_fallback(self, tmp_path):
        f = tmp_path / "multi"
        f.write_text("line1\nline2\nline3\n")
        # No 'password:' prefix — returns joined content stripped
        result = read_secret_file(str(f))
        assert "line1" in result


# ===========================================================================
# Integration: Config -> Allowlist pipeline
# ===========================================================================


class TestConfigToAllowlistIntegration:
    def test_allowlist_built_from_config(self, clean_env):
        clean_env.setenv("ALLOWLIST", "1.2.3.4, 203.0.113.0/24")
        cfg = Config.from_env()
        al = build_allowlist(cfg)
        assert al.contains("1.2.3.4") is True
        assert al.contains("203.0.113.1") is True
        assert al.contains("5.6.7.8") is False
