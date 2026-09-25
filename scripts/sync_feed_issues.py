#!/usr/bin/env python3
"""Open / close GitHub issues from a check_feeds.py report.

- One open issue per failing feed URL. An existing open issue (found by a
  hidden marker in its body) is reused: we comment only when the failure
  detail changes, so weekly runs don't spam.
- When a feed with an open issue is healthy again, the issue gets a comment
  and is closed.

Needs GITHUB_TOKEN (issues: write) and GITHUB_REPOSITORY.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

LABEL = "feed-health"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REPO = os.environ["GITHUB_REPOSITORY"]
RUN_URL = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{REPO}/actions/runs/"
           f"{os.environ.get('GITHUB_RUN_ID', '')}")
S = requests.Session()
S.headers.update({
    "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})


def marker(url: str) -> str:
    return f"<!-- feed-health:{url} -->"


def api(method: str, path: str, **kw):
    r = S.request(method, f"{API}{path}", timeout=30, **kw)
    if r.status_code >= 400:
        print(f"::error::{method} {path} -> {r.status_code} {r.text[:300]}")
        r.raise_for_status()
    return r.json() if r.content else None


def ensure_label() -> None:
    r = S.get(f"{API}/repos/{REPO}/labels/{LABEL}", timeout=30)
    if r.status_code == 404:
        api("POST", f"/repos/{REPO}/labels",
            json={"name": LABEL, "color": "d93f0b", "description": "Automated feed URL health check"})


def open_issues() -> list[dict]:
    issues, page = [], 1
    while True:
        batch = api("GET", f"/repos/{REPO}/issues",
                    params={"labels": LABEL, "state": "open", "per_page": 100, "page": page})
        issues += [i for i in batch if "pull_request" not in i]
        if len(batch) < 100:
            return issues
        page += 1


def main() -> int:
    report = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "feed-health.json"))
    ensure_label()
    existing = open_issues()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def find(url: str):
        return next((i for i in existing if marker(url) in (i.get("body") or "")), None)

    for feed in report:
        if feed.get("skipped"):
            print(f"Skipped by name: {feed['name']} ({feed['reason']})")
            continue
        issue = find(feed["url"])
        if not feed["ok"]:
            if issue is None:
                body = (
                    f"{marker(feed['url'])}\n"
                    f"The weekly feed health check could not fetch **{feed['name']}**.\n\n"
                    f"- URL: {feed['url']}\n"
                    f"- Result: `{feed['detail']}`\n"
                    f"- Config switch: `{feed['enabled_key']}`\n"
                    f"- First seen: {today}\n"
                    f"- Run: {RUN_URL}\n\n"
                    "Users with this feed enabled are silently getting zero entries from it. "
                    "Fix the URL, switch to a mirror, or disable the feed by default.\n\n"
                    "This issue closes itself when the check passes again."
                )
                created = api("POST", f"/repos/{REPO}/issues", json={
                    "title": f"Feed health: {feed['name']} is failing ({feed['detail'][:60]})",
                    "body": body, "labels": [LABEL]})
                print(f"Opened #{created['number']} for {feed['name']}")
            else:
                last = f"`{feed['detail']}`"
                if last not in (issue.get("body") or "") and not _last_comment_has(issue, last):
                    api("POST", f"/repos/{REPO}/issues/{issue['number']}/comments",
                        json={"body": f"Still failing on {today}, now with {last}. Run: {RUN_URL}"})
                print(f"#{issue['number']} already open for {feed['name']}")
        elif issue is not None:
            api("POST", f"/repos/{REPO}/issues/{issue['number']}/comments",
                json={"body": f"Feed is reachable again ({feed['detail']}) as of {today}. Closing. Run: {RUN_URL}"})
            api("PATCH", f"/repos/{REPO}/issues/{issue['number']}",
                json={"state": "closed", "state_reason": "completed"})
            print(f"Closed #{issue['number']}: {feed['name']} recovered")
    return 0


def _last_comment_has(issue: dict, text: str) -> bool:
    if not issue.get("comments"):
        return False
    comments = api("GET", f"/repos/{REPO}/issues/{issue['number']}/comments",
                   params={"per_page": 100})
    return bool(comments) and text in comments[-1].get("body", "")


if __name__ == "__main__":
    sys.exit(main())
