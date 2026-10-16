"""Tests for the FEEDS_FILE declarative custom feeds file.

Covers parsing (TOML and JSON), validation errors, defaults, provenance,
and the --list-sources / Config integration. All local: no network.
"""
import json
import logging

import pytest

import blocklist_import as bi
from blocklist_import import (
    Config,
    FeedConfigError,
    feed_slug,
    list_blocklist_sources,
    load_feeds_file,
    _parse_feeds_file,
)

VALID_FEED = {"name": "My ISP blocklist", "url": "https://feeds.example.com/blocklist.txt"}


def _toml_available() -> bool:
    try:
        import tomllib  # noqa: F401
        return True
    except ModuleNotFoundError:
        try:
            import tomli  # noqa: F401
            return True
        except ModuleNotFoundError:
            return False


requires_toml = pytest.mark.skipif(not _toml_available(), reason="needs tomllib (3.11+) or tomli")


def write_json(path, feeds):
    path.write_text(json.dumps({"feeds": feeds}))
    return str(path)


def write_toml(path, body):
    path.write_text(body)
    return str(path)


class TestJsonParsing:
    def test_minimal_feed_defaults(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [VALID_FEED])
        sources = load_feeds_file(path)
        assert len(sources) == 1
        s = sources[0]
        assert s.name == "My ISP blocklist"
        assert s.url == "https://feeds.example.com/blocklist.txt"
        assert s.comment_char == "#"
        assert s.extract_field is None
        assert s.field_separator == " "
        assert s.rate_limited is False
        assert s.license == "unknown"
        assert s.attribution_required is None
        assert s.commercial_ok is None
        assert s.license_note == ""

    def test_full_schema_maps_to_source(self, tmp_path):
        feed = dict(
            VALID_FEED,
            comment_char=";",
            extract_field=0,
            field_separator=",",
            rate_limited=True,
            license="CC-BY-4.0",
            attribution_required=True,
            commercial_ok=False,
            license_note="Credit the vendor",
        )
        path = write_json(tmp_path / "feeds.json", [feed])
        s, _ = _parse_feeds_file(path)[0]
        assert s.comment_char == ";"
        assert s.extract_field == 0
        assert s.field_separator == ","
        assert s.rate_limited is True
        assert s.license == "CC-BY-4.0"
        assert s.attribution_required is True
        assert s.commercial_ok is False
        assert s.license_note == "Credit the vendor"

    def test_origin_records_provenance(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [VALID_FEED])
        s = load_feeds_file(path)[0]
        assert s.origin == f"feeds file ({path})"

    def test_disabled_feed_excluded_from_load(self, tmp_path):
        path = write_json(
            tmp_path / "feeds.json",
            [VALID_FEED, {"name": "Paused feed", "url": "https://example.com/p.txt", "enabled": False}],
        )
        assert [s.name for s in load_feeds_file(path)] == ["My ISP blocklist"]
        assert [(s.name, en) for s, en in _parse_feeds_file(path)] == [
            ("My ISP blocklist", True),
            ("Paused feed", False),
        ]

    def test_multiple_feeds(self, tmp_path):
        path = write_json(
            tmp_path / "feeds.json",
            [VALID_FEED, {"name": "Second", "url": "http://192.0.2.1/list.txt"}],
        )
        assert len(load_feeds_file(path)) == 2


@requires_toml
class TestTomlParsing:
    def test_toml_feed(self, tmp_path):
        path = write_toml(
            tmp_path / "feeds.toml",
            '[[feeds]]\nname = "My ISP blocklist"\nurl = "https://feeds.example.com/blocklist.txt"\n'
            'comment_char = ";"\nextract_field = 0\nrate_limited = true\n'
            'license = "internal"\nlicense_note = "Private, do not redistribute"\n',
        )
        (s,) = load_feeds_file(path)
        assert s.name == "My ISP blocklist"
        assert s.comment_char == ";"
        assert s.extract_field == 0
        assert s.rate_limited is True
        assert s.license_note == "Private, do not redistribute"

    def test_toml_disabled_feed(self, tmp_path):
        path = write_toml(
            tmp_path / "feeds.toml",
            '[[feeds]]\nname = "Off"\nurl = "https://example.com/off.txt"\nenabled = false\n',
        )
        assert load_feeds_file(path) == []
        assert [(s.name, en) for s, en in _parse_feeds_file(path)] == [("Off", False)]

    def test_invalid_toml(self, tmp_path):
        path = write_toml(tmp_path / "feeds.toml", "[[feeds]\nnot toml\n")
        with pytest.raises(FeedConfigError, match="invalid TOML"):
            load_feeds_file(path)


class TestValidationErrors:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(FeedConfigError, match="cannot read"):
            load_feeds_file(str(tmp_path / "missing.json"))

    def test_bad_extension(self, tmp_path):
        path = write_json(tmp_path / "feeds.yaml", [VALID_FEED])
        with pytest.raises(FeedConfigError, match="must be a .toml or .json file"):
            load_feeds_file(path)

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "feeds.json"
        p.write_text("{not json")
        with pytest.raises(FeedConfigError, match="invalid JSON"):
            load_feeds_file(str(p))

    def test_missing_feeds_key(self, tmp_path):
        p = tmp_path / "feeds.json"
        p.write_text(json.dumps({"feed": []}))
        with pytest.raises(FeedConfigError, match="expected a 'feeds' list"):
            load_feeds_file(str(p))

    def test_top_level_not_object(self, tmp_path):
        p = tmp_path / "feeds.json"
        p.write_text(json.dumps([VALID_FEED]))
        with pytest.raises(FeedConfigError, match="expected a 'feeds' list"):
            load_feeds_file(str(p))

    def test_unknown_key_rejected(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, urll="https://typo.example.com/x.txt")])
        with pytest.raises(FeedConfigError, match="unknown keys: urll"):
            load_feeds_file(path)

    def test_missing_name(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [{"url": "https://example.com/x.txt"}])
        with pytest.raises(FeedConfigError, match="'name' is required"):
            load_feeds_file(path)

    def test_missing_url(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [{"name": "No URL"}])
        with pytest.raises(FeedConfigError, match="'url' is required"):
            load_feeds_file(path)

    def test_name_without_slug_chars(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [{"name": "!!!", "url": "https://example.com/x.txt"}])
        with pytest.raises(FeedConfigError, match="at least one letter or digit"):
            load_feeds_file(path)

    def test_builtin_name_collision(self, tmp_path):
        builtin_name = bi.BLOCKLIST_SOURCES[0].name
        path = write_json(tmp_path / "feeds.json", [{"name": builtin_name, "url": "https://example.com/x.txt"}])
        with pytest.raises(FeedConfigError, match="collides with a built-in feed"):
            load_feeds_file(path)

    def test_duplicate_names(self, tmp_path):
        path = write_json(
            tmp_path / "feeds.json",
            [VALID_FEED, {"name": "My  ISP   blocklist", "url": "https://example.com/other.txt"}],
        )
        with pytest.raises(FeedConfigError, match="duplicate feed name"):
            load_feeds_file(path)

    def test_non_http_scheme_rejected(self, tmp_path):
        for url in ("ftp://example.com/x.txt", "file:///etc/passwd", "gopher://x/"):
            path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, url=url)])
            with pytest.raises(FeedConfigError, match="must be an http"):
                load_feeds_file(path)

    def test_credentials_in_url_rejected(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, url="https://user:pass@example.com/x.txt")])
        with pytest.raises(FeedConfigError, match="credentials in URLs"):
            load_feeds_file(path)

    def test_url_with_whitespace_rejected(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, url="https://example.com/x.txt ")])
        # trailing whitespace is stripped; interior whitespace is rejected
        sources = load_feeds_file(path)
        assert sources[0].url == "https://example.com/x.txt"
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, url="https://exam ple.com/x.txt")])
        with pytest.raises(FeedConfigError, match="whitespace"):
            load_feeds_file(path)

    def test_comment_char_length(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, comment_char="##")])
        with pytest.raises(FeedConfigError, match="single character"):
            load_feeds_file(path)

    def test_extract_field_negative(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, extract_field=-1)])
        with pytest.raises(FeedConfigError, match="integer >= 0"):
            load_feeds_file(path)

    def test_extract_field_bool_rejected(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, extract_field=True)])
        with pytest.raises(FeedConfigError, match="integer >= 0"):
            load_feeds_file(path)

    def test_enabled_must_be_bool(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, enabled="yes")])
        with pytest.raises(FeedConfigError, match="'enabled' must be true or false"):
            load_feeds_file(path)

    def test_license_tristate_must_be_bool(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", [dict(VALID_FEED, commercial_ok="maybe")])
        with pytest.raises(FeedConfigError, match="'commercial_ok' must be true or false"):
            load_feeds_file(path)

    def test_feed_count_cap(self, tmp_path):
        feeds = [{"name": f"Feed {i}", "url": "https://example.com/x.txt"} for i in range(257)]
        path = write_json(tmp_path / "feeds.json", feeds)
        with pytest.raises(FeedConfigError, match="256-feed limit"):
            load_feeds_file(path)

    def test_entry_not_an_object(self, tmp_path):
        path = write_json(tmp_path / "feeds.json", ["just a string"])
        with pytest.raises(FeedConfigError, match="must be a table/object"):
            load_feeds_file(path)


class TestConfigIntegration:
    def test_from_env_reads_feeds_file(self, monkeypatch):
        monkeypatch.setenv("FEEDS_FILE", "/config/feeds.toml")
        config = Config.from_env()
        assert config.feeds_file == "/config/feeds.toml"
        assert config.feeds_file_sources is None

    def test_from_env_default_empty(self, monkeypatch):
        monkeypatch.delenv("FEEDS_FILE", raising=False)
        assert Config.from_env().feeds_file == ""

    def test_feed_confidence_applies_to_custom_feed(self):
        overrides = bi.parse_feed_confidence(f"{feed_slug(VALID_FEED['name'])}=12")
        assert bi.feed_confidence(VALID_FEED["name"], overrides) == 12
        assert bi.feed_confidence(VALID_FEED["name"]) == bi.DEFAULT_FEED_CONFIDENCE


class TestListSources:
    def test_custom_feeds_listed_with_provenance(self, tmp_path, caplog):
        path = write_json(
            tmp_path / "feeds.json",
            [VALID_FEED, {"name": "Paused", "url": "https://example.com/p.txt", "enabled": False}],
        )
        logger = logging.getLogger("blocklist-import")
        with caplog.at_level(logging.INFO, logger="blocklist-import"):
            list_blocklist_sources(logger, fmt="text", feeds_file=path)
        text = caplog.text
        assert f"Custom feeds from FEEDS_FILE ({path})" in text
        assert "- My ISP blocklist (enabled)" in text
        assert "- Paused (disabled in file)" in text

    def test_broken_file_reported_in_listing(self, tmp_path, caplog):
        logger = logging.getLogger("blocklist-import")
        with caplog.at_level(logging.INFO, logger="blocklist-import"):
            list_blocklist_sources(logger, fmt="text", feeds_file=str(tmp_path / "nope.json"))
        assert "could not be loaded" in caplog.text

    def test_no_feeds_file_unchanged(self, caplog):
        logger = logging.getLogger("blocklist-import")
        with caplog.at_level(logging.INFO, logger="blocklist-import"):
            list_blocklist_sources(logger, fmt="text")
        assert "FEEDS_FILE" not in caplog.text


class TestRunImportWiring:
    """run_import appends validated feeds-file sources after CUSTOM_BLOCKLISTS."""

    def test_feeds_file_sources_reach_the_fetch_loop(self, tmp_path, caplog):
        from unittest.mock import MagicMock, patch
        from datetime import timedelta
        from blocklist_import import FetchResult

        path = write_json(tmp_path / "feeds.json", [VALID_FEED])
        config = Config(lapi_key="k", feeds_file=path)
        assert config.feeds_file_sources is None  # run_import loads on demand

        lapi = MagicMock()
        lapi.health_check.return_value = True
        lapi.can_write.return_value = True
        lapi.get_existing_ips.return_value = [("10.0.0.1", timedelta(hours=24))]
        lapi.add_decisions.side_effect = lambda ips, **kw: (len(ips), 0)

        seen = {}

        def fake_fetch(source, *args, **kwargs):
            seen[source.name] = source.origin
            return ([], [], FetchResult(
                source=source, success=True, new_unique_ip_count=0,
                refreshed_unique_ip_count=0, duration=0.1,
                error_type="", error_exception=None, parse_errors={},
            ))

        patchers = [
            patch.object(bi, "create_http_session", return_value=MagicMock()),
            patch.object(bi, "build_allowlist", return_value=MagicMock()),
            patch.object(bi, "get_metrics", return_value=None),
            patch.object(bi, "create_lapi_client_from_config", return_value=lapi),
            patch.object(bi, "fetch_blocklist", side_effect=fake_fetch),
            patch.object(bi, "send_telemetry"),
            patch.object(bi, "send_webhook"),
        ]
        for patcher in patchers:
            patcher.start()
        try:
            with caplog.at_level(logging.INFO, logger="blocklist-import"):
                bi.run_import(config, logging.getLogger("blocklist-import"))
        finally:
            for patcher in patchers:
                patcher.stop()

        assert VALID_FEED["name"] in seen
        assert seen[VALID_FEED["name"]] == f"feeds file ({path})"
        assert "Loaded 1 custom feed(s) from FEEDS_FILE" in caplog.text

    def test_broken_feeds_file_fails_loud_in_run_import(self, tmp_path):
        from unittest.mock import MagicMock, patch

        config = Config(lapi_key="k", feeds_file=str(tmp_path / "missing.json"))
        lapi = MagicMock()
        lapi.health_check.return_value = True
        lapi.can_write.return_value = True
        lapi.get_existing_ips.return_value = []
        with patch.object(bi, "create_lapi_client_from_config", return_value=lapi), \
                patch.object(bi, "send_telemetry"), patch.object(bi, "send_webhook"):
            with pytest.raises(FeedConfigError, match="cannot read"):
                bi.run_import(config, logging.getLogger("blocklist-import"))
