#!/usr/bin/env python3
"""Assertions for the live-LAPI CI job.

Usage:
    assert_live_lapi.py decisions.json              # per-decision round-trip
    assert_live_lapi.py alerts.json --consolidated  # per-feed consolidation
"""
import json
import sys

PREFIX = "external/blocklist-import"
LOW = f"{PREFIX}/custom-blocklist-0/c30"
HIGH = f"{PREFIX}/custom-blocklist-1/c95"
# 203.0.113.7 is listed by both feeds and must carry the HIGHEST confidence.
EXPECTED_DECISIONS = {
    "203.0.113.7": HIGH,
    "203.0.113.8": LOW,
    "203.0.113.9": HIGH,
}


def main() -> int:
    path = sys.argv[1]
    consolidated = "--consolidated" in sys.argv
    with open(path) as f:
        data = json.load(f)
    data = data or []

    if consolidated:
        scenarios = [a.get("scenario", "") for a in data]
        # One consolidated alert per feed; the mixed all-sources scenario
        # must NOT appear in structured mode.
        assert len(data) == 2, f"expected 2 per-feed alerts, got {len(data)}: {scenarios}"
        assert sorted(scenarios) == sorted([LOW, HIGH]), scenarios
        assert not any("all-sources" in s for s in scenarios), scenarios
        print(f"OK: consolidated alerts are per-feed: {sorted(scenarios)}")
        return 0

    # `cscli decisions list -o json` returns alerts, each with a nested
    # "decisions" list; flatten to one entry per decision.
    decisions = [d for alert in data for d in (alert.get("decisions") or [])]
    got = {}
    for d in decisions:
        ip, scenario = d.get("value"), d.get("scenario")
        assert d.get("origin") == "blocklist-import", d
        assert ip not in got, f"duplicate decision for {ip}: {got[ip]} and {scenario}"
        got[ip] = scenario
    assert got == EXPECTED_DECISIONS, f"decision scenarios differ:\ngot:      {got}\nexpected: {EXPECTED_DECISIONS}"
    print("OK: scenarios round-tripped byte-for-byte; "
          "203.0.113.7 (on both feeds) carries c95, the highest confidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
