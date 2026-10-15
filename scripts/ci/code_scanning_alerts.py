#!/usr/bin/env python3
"""Read only GitHub Code Scanning alert lifecycle metadata, not source snippets.

The Code Scanning API reports open/fixed/dismissed alerts; SARIF alone cannot.
Use a permission-scoped Actions job with GITHUB_TOKEN, never print the token.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter


def describe(alert):
    """Allowlist metadata to prevent accidental code/secret text logging."""
    location = ((alert.get("most_recent_instance") or {}).get("location") or {})
    return {
        "number": int(alert["number"]),
        "state": alert.get("state") or "unknown",
        "rule": (alert.get("rule") or {}).get("id") or "unknown",
        "path": location.get("path") or "",
        "line": location.get("start_line") or 0,
        "tool": ((alert.get("tool") or {}).get("name") or ""),
        "reason": alert.get("dismissed_reason"),
    }


def fetch_open_alerts(repository, token):
    if not repository or not token:
        raise ValueError("GITHUB_REPOSITORY and GITHUB_TOKEN are required")
    items = []
    for page in range(1, 21):
        query = urllib.parse.urlencode({"state": "open", "per_page": 100, "page": page})
        url = f"https://api.github.com/repos/{repository}/code-scanning/alerts?{query}"
        request = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "KAORI-security-inventory",
        })
        with urllib.request.urlopen(request, timeout=30) as response:
            page_items = json.load(response)
        if not isinstance(page_items, list):
            raise ValueError("Expected a list of code-scanning alerts")
        items.extend(describe(item) for item in page_items)
        if len(page_items) < 100:
            return items
    raise ValueError("Alert inventory exceeds 2000 results; refusing incomplete report")


def main():
    records = fetch_open_alerts(
        os.environ.get("GITHUB_REPOSITORY", ""),
        os.environ.get("GITHUB_TOKEN", ""),
    )
    counts = Counter(record["rule"] for record in records)
    print("CODE_SCANNING_OPEN_SUMMARY " + json.dumps({
        "open_count": len(records), "rule_counts": dict(sorted(counts.items())),
        "source": "GitHub Code Scanning Alerts REST API",
    }, sort_keys=True))
    for record in sorted(records, key=lambda item: item["number"]):
        print("CODE_SCANNING_OPEN_ALERT " + json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, urllib.error.URLError, OSError) as exc:
        print("ERROR: Code Scanning alert inventory unavailable: " +
              type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
