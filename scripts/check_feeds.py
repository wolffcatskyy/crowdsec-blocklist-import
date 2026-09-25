#!/usr/bin/env python3
"""Check every feed URL defined in blocklist_import.BLOCKLIST_SOURCES.

Sends a HEAD request (falls back to a small ranged GET when a server
rejects HEAD), retries transient errors, and writes a JSON report.

Exit code is always 0 so the workflow can decide what to do with the
report; use --strict to exit 1 when any feed fails.

Feeds without a public URL (preset values) or that need an API key
(AbuseIPDB API) are skipped.
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


def needs_api_key(source) -> bool:
    return source.get_can_import is not bi.get_normal_can_import or bool(source.api_key_name)


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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="feed-health.json")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    results = []
    seen = set()
    for source in bi.BLOCKLIST_SOURCES:
        if not source.url:
            continue
        if needs_api_key(source):
            print(f"SKIP  {source.name} (requires API key)")
            continue
        if source.url in seen:
            continue
        seen.add(source.url)
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
        json.dump(results, f, indent=2)
    failed = [r for r in results if not r["ok"]]
    print(f"\n{len(results) - len(failed)}/{len(results)} feeds healthy")
    return 1 if (args.strict and failed) else 0


if __name__ == "__main__":
    sys.exit(main())
