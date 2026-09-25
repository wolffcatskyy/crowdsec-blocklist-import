#!/usr/bin/env python3
"""Check every feed defined in blocklist_import.BLOCKLIST_SOURCES.

Coverage is total: every defined feed is either probed or explicitly
skipped, and a feed may be skipped ONLY by being named in SKIP_FEEDS with
a reason. Skips are listed by name in the report. Whether a feed is
enabled by default is irrelevant - a feed that users can turn on must be
checked. tests/test_feed_health_coverage.py fails when any feed is
neither probed nor on the named skip list, so a feed can never silently
drop out of the health check (e.g. when one goes opt-in).

Probing sends a HEAD request (falls back to a small ranged GET when a
server rejects HEAD) and retries transient errors. Feeds that need an API
key get a keyless probe that expects an auth-failure status (401), which
is enough to prove the endpoint is alive. Results go to a JSON report.

Exit code is always 0 so the workflow can decide what to do with the
report; use --strict to exit 1 when any feed fails.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import blocklist_import as bi  # noqa: E402

USER_AGENT = (f"crowdsec-blocklist-import-feed-health/{bi.__version__} "
              "(+https://github.com/wolffcatskyy/crowdsec-blocklist-import)")
TIMEOUT = 30
ATTEMPTS = 3

# The ONLY feeds the health check may skip, each with its reason. A feed
# that is neither probed nor named here fails the test suite.
SKIP_FEEDS: dict[str, str] = {
    "Static scanner IPs (Censys)": "static preset CIDRs; there is no URL to fetch",
}

# Key-required feeds are probed without a key; the expected auth-failure
# status proves the endpoint is alive.
KEYLESS_PROBE_STATUS: dict[str, int] = {
    "AbuseIPDB API": 401,
}


def needs_api_key(source) -> bool:
    return source.get_can_import is not bi.get_normal_can_import or bool(source.api_key_name)


def classify(source) -> str:
    """How the health check covers a feed: 'url', 'keyless', or 'skip'.

    Raises for a feed it cannot cover. That is what keeps coverage total:
    no feed can fall through a condition and silently vanish from the
    report the way disabled-by-default feeds used to.
    """
    if source.name in SKIP_FEEDS:
        return "skip"
    if not source.url:
        raise ValueError(
            f"{source.name}: no URL and not on the named skip list - "
            "probe it or add it to SKIP_FEEDS with a reason")
    if needs_api_key(source):
        if source.name not in KEYLESS_PROBE_STATUS:
            raise ValueError(
                f"{source.name}: requires an API key and has no keyless probe - "
                "add it to KEYLESS_PROBE_STATUS or to SKIP_FEEDS with a reason")
        return "keyless"
    return "url"


def check_plan(sources=None) -> tuple[list[tuple[object, str]], list[tuple[object, str]]]:
    """Return (probes, skips) covering every defined feed exactly once.

    probes: list of (source, mode), mode 'url' or 'keyless'.
    skips:  list of (source, reason).
    """
    probes, skips = [], []
    for source in (sources if sources is not None else bi.BLOCKLIST_SOURCES):
        mode = classify(source)
        if mode == "skip":
            skips.append((source, SKIP_FEEDS[source.name]))
        else:
            probes.append((source, mode))
    return probes, skips


def probe(url: str) -> tuple[bool, str]:
    """Return (ok, detail) for one URL."""
    headers = {"User-Agent": USER_AGENT}
    last = ""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            r = requests.head(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (403, 405, 501) or r.status_code >= 500:
                # Some servers refuse HEAD; confirm with a tiny GET.
                g = requests.get(url, headers={**headers, "Range": "bytes=0-1023"},
                                 timeout=TIMEOUT, allow_redirects=True, stream=True)
                g.close()
                r = g
            if 200 <= r.status_code < 300:
                if r.headers.get("Content-Length") == "0":
                    return False, f"HTTP {r.status_code} but empty body (Content-Length: 0)"
                return True, f"HTTP {r.status_code}"
            last = f"HTTP {r.status_code}"
            if 400 <= r.status_code < 500 and r.status_code not in (408, 429):
                break  # a real 404/410 won't fix itself on retry
        except requests.RequestException as exc:
            last = f"{type(exc).__name__}: {exc}"[:300]
        if attempt < ATTEMPTS:
            time.sleep(5 * attempt)
    return False, last


def probe_keyless(url: str, expect_status: int) -> tuple[bool, str]:
    """Probe a key-required endpoint without a key.

    The expected auth-failure status (e.g. 401) proves the endpoint is
    alive; anything else (DNS failure, 5xx, an unexpected 2xx) is reported
    as unhealthy.
    """
    headers = {"User-Agent": USER_AGENT}
    last = ""
    for attempt in range(1, ATTEMPTS + 1):
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == expect_status:
                return True, f"HTTP {r.status_code} (expected without API key; endpoint alive)"
            last = f"HTTP {r.status_code} (expected {expect_status})"
            if r.status_code < 500 and r.status_code not in (408, 429):
                break  # a definitive unexpected status won't fix itself on retry
        except requests.RequestException as exc:
            last = f"{type(exc).__name__}: {exc}"[:300]
        if attempt < ATTEMPTS:
            time.sleep(5 * attempt)
    return False, last


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="feed-health.json")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    probes, skips = check_plan()

    skipped = []
    for source, reason in skips:
        print(f"SKIP  {source.name}: {reason}")
        skipped.append({
            "name": source.name,
            "enabled_key": (source.enabled_key or "").upper(),
            "skipped": True,
            "reason": reason,
        })

    results = []
    seen = set()
    for source, mode in probes:
        if source.url in seen:
            continue  # same URL already probed via another feed entry
        seen.add(source.url)
        if mode == "keyless":
            ok, detail = probe_keyless(source.url, KEYLESS_PROBE_STATUS[source.name])
        else:
            ok, detail = probe(source.url)
        print(f"{'OK  ' if ok else 'FAIL'}  {source.name}: {detail}  {source.url}")
        results.append({
            "name": source.name,
            "url": source.url,
            "enabled_key": (source.enabled_key or "").upper(),
            "ok": ok,
            "detail": detail,
        })

    with open(args.output, "w") as f:
        json.dump(results + skipped, f, indent=2)
    failed = [r for r in results if not r["ok"]]
    skip_note = ", ".join(f"{s['name']} ({s['reason']})" for s in skipped) or "none"
    print(f"\n{len(results) - len(failed)}/{len(results)} feeds healthy; skipped by name: {skip_note}")
    return 1 if (args.strict and failed) else 0


if __name__ == "__main__":
    sys.exit(main())
