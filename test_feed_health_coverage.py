"""Feed-health coverage: every defined feed is checked or explicitly skipped.

Closes the hole where a feed could silently drop out of the weekly health
check: disabled-by-default feeds used to be skipped without being named,
so a feed users could still enable (Monty Security C2, known dead) was
never checked and never reported, and any feed going opt-in later would
have vanished the same way. Now a feed is skipped only via a named skip
list with a reason, and these tests fail when any feed is neither checked
nor on that list.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
sys.path.insert(0, os.path.dirname(__file__))

import blocklist_import as bi  # noqa: E402
import check_feeds as cf  # noqa: E402


def test_every_feed_is_probed_or_on_named_skip_list():
    """check_plan must cover every defined feed exactly once; it raises
    rather than leave a feed neither probed nor skipped."""
    probes, skips = cf.check_plan()
    covered = [s for s, _ in probes] + [s for s, _ in skips]
    assert len(covered) == len(bi.BLOCKLIST_SOURCES)
    assert {id(s) for s in covered} == {id(s) for s in bi.BLOCKLIST_SOURCES}
    for source, reason in skips:
        assert reason.strip(), f"{source.name} is skipped without a reason"


def test_skip_list_names_real_feeds():
    """A stale skip entry would hide a naming drift; every skip must name
    a feed that actually exists."""
    names = {s.name for s in bi.BLOCKLIST_SOURCES}
    for name in cf.SKIP_FEEDS:
        assert name in names, f"SKIP_FEEDS names {name!r}, which is not a defined feed"


def test_key_required_feeds_have_keyless_probes():
    """Every key-required feed is either probed keyless or explicitly
    skipped - never dropped for lack of a key."""
    key_required = {s.name for s in bi.BLOCKLIST_SOURCES if cf.needs_api_key(s)}
    covered = set(cf.KEYLESS_PROBE_STATUS) | set(cf.SKIP_FEEDS)
    assert key_required <= covered
    for name, status in cf.KEYLESS_PROBE_STATUS.items():
        assert name in key_required, f"KEYLESS_PROBE_STATUS names {name!r}, which needs no key"
        assert status in (401, 403)


def test_monty_c2_removed_from_enableable_set():
    """Regression: the dead Monty C2 feed must stay out of the registry,
    the toggles, and the Config."""
    assert all("Monty" not in s.name for s in bi.BLOCKLIST_SOURCES)
    assert "ENABLE_MONTY_SECURITY_C2" not in bi.VALID_ENABLE_VARS
    assert "enable_monty_security_c2" not in bi.Config.__dataclass_fields__


def test_removed_toggle_logs_error_naming_feed(monkeypatch, caplog):
    """A config that still sets a removed feed's toggle gets an error
    naming the feed as removed, not a generic unknown-variable warning."""
    monkeypatch.setenv("ENABLE_MONTY_SECURITY_C2", "true")
    logger = logging.getLogger("test_removed_toggle")
    with caplog.at_level(logging.ERROR, logger="test_removed_toggle"):
        bi.validate_enable_env_vars(logger)
    messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("ENABLE_MONTY_SECURITY_C2" in m and "removed" in m for m in messages), messages
