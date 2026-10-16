"""Tests for the report-only impact preview (impact_preview.py + CLI wiring).

No network and no LAPI: compute/render paths are pure, and the CLI test
monkeypatches feed collection.
"""
import html

import pytest

import blocklist_import
from impact_preview import (
    NetworkSet,
    compute_impact,
    extract_log_ips,
    render_html,
    render_text,
)


NGINX_LOG = """
203.0.113.9 - - [10/Oct/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 181
198.51.100.23 - - [10/Oct/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 612
203.0.113.9 - - [10/Oct/2026:10:00:02 +0000] "GET /xmlrpc.php HTTP/1.1" 404 181
192.0.2.5 - - [10/Oct/2026:10:00:03 +0000] "GET / HTTP/1.1" 200 612
2001:db8:1::10 - - [10/Oct/2026:10:00:04 +0000] "GET / HTTP/1.1" 200 612
not-an-ip just text with 999.999.1.1 garbage
"""


def test_extract_log_ips_dedupes_and_validates():
    ips = extract_log_ips(NGINX_LOG)
    assert "203.0.113.9" in ips
    assert "198.51.100.23" in ips
    assert "192.0.2.5" in ips
    assert "2001:db8:1::10" in ips
    assert len(ips) == 4  # duplicate 203.0.113.9 counted once
    assert "999.999.1.1" not in ips


def test_extract_log_ips_plain_list():
    assert extract_log_ips("1.2.3.4\n5.6.7.8\n") == {"1.2.3.4", "5.6.7.8"}


def test_network_set_cidr_and_single():
    nets = NetworkSet({"203.0.113.0/24", "198.51.100.7"})
    assert nets.covers("203.0.113.9")
    assert nets.covers("203.0.113.255")
    assert nets.covers("198.51.100.7")
    assert not nets.covers("198.51.100.8")
    assert not nets.covers("192.0.2.5")


def test_network_set_ipv6_and_version_separation():
    nets = NetworkSet({"2001:db8::/32", "203.0.113.0/24"})
    assert nets.covers("2001:db8:1::10")
    assert not nets.covers("2001:db9::1")
    # v4 address must never match a v6 range and vice versa
    assert not nets.covers("192.0.2.1")
    assert not NetworkSet({"203.0.113.9"}).covers("::ffff:203.0.113.9")


def test_network_set_overlapping_ranges():
    nets = NetworkSet({"203.0.113.0/24", "203.0.113.128/25", "203.0.113.9"})
    assert nets.covers("203.0.113.200")


def test_compute_impact_unique_and_shared():
    feeds = [
        ("Feed A", "enable_a", {"203.0.113.0/24"}),
        ("Feed B", "enable_b", {"203.0.113.9", "198.51.100.23"}),
    ]
    log_ips = {"203.0.113.9", "198.51.100.23", "192.0.2.5"}
    report = compute_impact(feeds, log_ips, log_label="test.log")
    by_name = {f.feed: f for f in report.feeds}
    # 203.0.113.9 is covered by both feeds (shared); 198.51.100.23 only by B
    assert by_name["Feed A"].hits == 1
    assert by_name["Feed A"].shared_hits == 1
    assert by_name["Feed A"].unique_hits == 0
    assert by_name["Feed B"].hits == 2
    assert by_name["Feed B"].unique_hits == 1
    assert by_name["Feed B"].shared_hits == 1
    assert report.log_ips_total == 3
    assert report.matched_ips == 2
    assert report.union_entries == 3
    assert report.matched_samples["Feed B"] == ("198.51.100.23", "203.0.113.9")


def test_compute_impact_rejects_duplicate_feed_names():
    with pytest.raises(ValueError):
        compute_impact(
            [("A", "k1", set()), ("A", "k2", set())], {"1.2.3.4"})


def test_compute_impact_presets_marginal():
    feeds = [
        ("Small", "enable_small", {"203.0.113.9"}),
        ("Big", "enable_big", {"198.51.100.23"}),
    ]
    membership = {
        "enable_small": ("embedded", "server", "max"),
        "enable_big": ("max",),
    }
    log_ips = {"203.0.113.9", "198.51.100.23"}
    report = compute_impact(feeds, log_ips, preset_membership=membership)
    by_preset = {p.preset: p for p in report.presets}
    assert by_preset["embedded"].hits == 1
    assert by_preset["embedded"].marginal_hits == 1
    assert by_preset["max"].hits == 2
    assert by_preset["max"].marginal_hits == 1
    assert by_preset["max"].entries == 2


def test_compute_impact_error_feed_kept():
    feeds = [
        ("Good", "enable_a", {"203.0.113.9"}),
        ("Dead", "enable_b", set(), "fetch failed"),
    ]
    report = compute_impact(feeds, {"203.0.113.9"})
    by_name = {f.feed: f for f in report.feeds}
    assert by_name["Dead"].error == "fetch failed"
    assert by_name["Dead"].hits == 0
    assert report.matched_ips == 1


def test_render_text_report_only_banner():
    report = compute_impact(
        [("Feed A", "enable_a", {"203.0.113.9"})], {"203.0.113.9"})
    text = render_text(report)
    assert "report only" in text.lower()
    assert "Feed A" in text
    assert "no decisions" in text.lower() or "nothing imported" in text.lower()


def test_render_html_escapes_and_banners():
    report = compute_impact(
        [('<script>alert(1)</script>', "enable_a", {"203.0.113.9"})],
        {"203.0.113.9"},
        log_label='<img src=x>',
    )
    page = render_html(report)
    assert "<script>alert(1)</script>" not in page
    assert html.escape('<script>alert(1)</script>') in page
    assert "<img src=x>" not in page
    assert "Report only" in page
    assert "<svg" in page
    assert "SYNTHETIC" not in page


def test_render_html_demonstration_label():
    report = compute_impact(
        [("Feed A", "enable_a", {"203.0.113.9"})],
        {"203.0.113.9"},
        demonstration=True,
    )
    assert "SYNTHETIC DEMONSTRATION DATA" in render_html(report)


def test_render_html_empty_hits():
    report = compute_impact(
        [("Feed A", "enable_a", {"203.0.113.9"})], {"192.0.2.5"})
    page = render_html(report)
    assert "No feed would have matched" in page


def test_cli_impact_preview_no_lapi(monkeypatch, tmp_path, capsys):
    """The preview must run with no LAPI key and never build a LAPI client."""
    log_file = tmp_path / "access.log"
    log_file.write_text(NGINX_LOG)
    html_file = tmp_path / "report.html"

    def fake_collect(config, logger, all_feeds=False):
        return [
            ("Feed A", "enable_ipsum", {"203.0.113.0/24"}, ""),
            ("Feed B", "enable_tor", set(), "fetch failed"),
        ]

    monkeypatch.setattr(blocklist_import, "collect_preview_feeds", fake_collect)
    monkeypatch.setattr(
        blocklist_import, "create_lapi_client_from_config",
        lambda *a, **k: pytest.fail("preview must not touch LAPI"))
    monkeypatch.setenv("METRICS_ENABLED", "false")
    monkeypatch.setenv("TELEMETRY_ENABLED", "false")
    monkeypatch.delenv("CROWDSEC_LAPI_KEY", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["blocklist_import.py", "--impact-preview", str(log_file),
         "--impact-preview-html", str(html_file)])

    assert blocklist_import.main() == 0
    out = capsys.readouterr().out
    assert "IMPACT PREVIEW" in out
    page = html_file.read_text()
    assert "Report only" in page
    assert "Feed A" in page


def test_cli_impact_preview_missing_log(monkeypatch, tmp_path):
    monkeypatch.setenv("METRICS_ENABLED", "false")
    monkeypatch.setattr(
        "sys.argv",
        ["blocklist_import.py", "--impact-preview",
         str(tmp_path / "nope.log")])
    assert blocklist_import.main() == 1


def test_render_html_scope_and_sensitivity_notes():
    report = compute_impact(
        [("Feed A", "enable_a", {"203.0.113.9"})],
        {"203.0.113.9"},
        preset_membership={"enable_a": ("embedded", "server", "max")},
        feed_scope="currently enabled feeds",
    )
    page = render_html(report)
    assert "scope: currently enabled feeds" in page
    assert "treat it as sensitive" in page
    text = render_text(report)
    assert "scope: currently enabled feeds" in text
    assert "sensitive" in text


def test_render_html_no_scope_note_when_unscoped():
    report = compute_impact(
        [("Feed A", "enable_a", {"203.0.113.9"})], {"203.0.113.9"})
    assert "scope:" not in render_html(report)
