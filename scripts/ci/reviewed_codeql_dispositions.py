#!/usr/bin/env python3
"""One-time, audited disposition of the 31 intentional KAORI CLI metadata alerts.

Never apply to unrecognized alerts: the exact rule, path, line and number must
match the reviewed baseline. CodeQL queries and SARIF uploads remain enabled.
This is NOT a vulnerability fix or a general-purpose alert dismissal tool.
"""
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from code_scanning_alerts import fetch_open_alerts

REPOSITORY = "OXY7O/kaori-tls-secret-manager"
ROOT = "scripts/kubernetes/tls-secret-manager/"
RULE = "py/clear-text-logging-sensitive-data"
WIZARD_LINES = (
    301, 305, 309, 366, 427, 445, 457, 487, 520, 527, 540, 579,
    600, 723, 831, 929, 1062, 1152, 1201, 1232, 1239, 1603, 1626, 1637,
)
EXPECTED = {
    5: (ROOT + "tls_ops.py", 509),
    6: ("scripts/tls_crud.py", 699),
    7: ("scripts/tls_crud.py", 716),
    8: (ROOT + "tls_secret_manager.py", 679),
    9: (ROOT + "tls_secret_manager.py", 1226),
    10: (ROOT + "tls_secret_manager.py", 1248),
    11: (ROOT + "tls_secret_manager.py", 1313),
    **{i + 12: (ROOT + "tls_secret_wizard.py", line)
       for i, line in enumerate(WIZARD_LINES)},
}

REASON = (
    "Reviewed under KAORI security audit #17. This data-flow sink displays "
    "Kubernetes Secret RESOURCE IDENTITY or diagnostic metadata intentionally "
    "to the authorized operator, not Kubernetes Secret VALUE, tls.key, "
    "kubeconfig, recovery identity, or credentials. Operational metadata is "
    "confidential: restrict terminal logs, stdout capture, screenshots and "
    "evidence to the authorized operator per docs/CODE-SCANNING.md. "
    "Intentional CLI behavior retained; residual metadata exposure accepted."
)


def validate(alerts):
    actual = {alert["number"]: alert for alert in alerts}
    if len(actual) != len(alerts) or set(actual) != set(EXPECTED):
        raise ValueError("Current open alerts do not exactly match reviewed baseline")
    for number, (path, line) in sorted(EXPECTED.items()):
        alert = actual[number]
        if (alert["state"] != "open"
            or alert["rule"] != RULE
            or alert["path"] != path
            or alert["line"] != line
            or alert["tool"] != "CodeQL"):
            raise ValueError("Alert identity mismatch: number " + str(number))
    return True


def dismiss(number, token):
    payload = json.dumps({
        "state": "dismissed",
        "dismissed_reason": "won't fix",
        "dismissed_comment": REASON + " Alert #" + str(number) + ".",
    }).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/code-scanning/alerts/{number}",
        data=payload,
        method="PATCH",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "KAORI-reviewed-CodeQL-triage",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        updated = json.load(response)
    if updated.get("number") != number or updated.get("state") != "dismissed":
        raise ValueError("Dismissal not confirmed for alert " + str(number))


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Disposition permitted on protected main only")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or not token:
        raise ValueError("Repository/token mismatch")
    alerts = fetch_open_alerts(REPOSITORY, token)
    validate(alerts)
    print("REVIEWED_DISPOSITION_PREFLIGHT " + json.dumps({
        "reviewed_alerts": len(alerts),
        "rule": RULE,
        "decision": "won't fix — confidential metadata only",
    }, sort_keys=True), flush=True)
    for number in sorted(EXPECTED):
        dismiss(number, token)
        print("REVIEWED_DISPOSITION " + json.dumps({
            "number": number, "decision": "won't fix", "status": "dismissed",
        }), flush=True)
    remaining = fetch_open_alerts(REPOSITORY, token)
    if remaining:
        raise ValueError("Unexpected open alerts remain after reviewed dispositions")
    print("REVIEWED_DISPOSITION_COMPLETE " + json.dumps({
        "dismissed": len(EXPECTED), "open": 0,
        "note": "Accepted operational metadata risk; SARIF detections remain.",
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, urllib.error.URLError, OSError) as exc:
        print("REVIEWED_DISPOSITION_STOPPED: " + type(exc).__name__,
              file=sys.stderr)
        raise SystemExit(1)
