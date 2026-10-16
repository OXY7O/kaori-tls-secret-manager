#!/usr/bin/env python3
"""Fail-closed, read-only GitHub release eligibility check.

Run after Quality Gate on trusted pushes to main. An already-published immutable
release must never trigger archive packaging or a write-permission job.
"""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")
ROOT = Path(__file__).resolve().parents[2]


def release_version(root=ROOT):
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        raise ValueError("VERSION must be MAJOR.MINOR.PATCH")
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if not re.search(r"^## \[" + re.escape(version) + r"\](?:\s|$)", changelog, re.MULTILINE):
        raise ValueError("Missing release entry in CHANGELOG.md")
    for path in (f"docs/releases/v{version}.md", "assets/kaori-logo.png",
                 "assets/kaori-mark.png"):
        if not (root / path).is_file():
            raise ValueError("Missing release metadata or branding file: " + path)
    return version


def github_get(path, *, repository, token):
    """Return (HTTP status, JSON). Only 404 denotes absence; all other failures abort."""
    if not REPOSITORY_RE.fullmatch(repository) or not token:
        raise ValueError("Missing or invalid GitHub repository/token")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + repository + "/" + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "KAORI-release-preflight",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        # Never expose response body or token in CI output.
        raise RuntimeError("GitHub release preflight API returned HTTP " +
                           str(error.code)) from None


def decide(root, *, repository, token):
    version = release_version(root)
    tag = "v" + version
    status, release = github_get("releases/tags/" + tag, repository=repository, token=token)
    if status == 200:
        assets = {asset.get("name") for asset in release.get("assets", [])}
        expected = {"kaori-tls-management-" + tag + ".tar.gz", "SHA256SUMS"}
        if release.get("draft") or release.get("prerelease") or not expected.issubset(assets):
            raise ValueError("Existing release has incomplete or unexpected metadata; manual review required")
        return {"publish": False, "tag": tag, "reason": "immutable release already published"}
    if status != 404:
        raise RuntimeError("Unexpected release API response")
    # A manually created tag without a release must never be repurposed.
    tag_status, _ = github_get("git/ref/tags/" + tag, repository=repository, token=token)
    if tag_status == 200:
        raise ValueError("Git tag exists without a release; refusing to repurpose immutable tag")
    if tag_status != 404:
        raise RuntimeError("Unexpected tag API response")
    return {"publish": True, "tag": tag, "reason": "new version without existing tag or release"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--github-output", required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Release preflight must run on main")
    result = decide(
        ROOT,
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GH_TOKEN", ""),
    )
    with open(args.github_output, "a", encoding="utf-8") as stream:
        stream.write("publish=" + str(result["publish"]).lower() + "\n")
        stream.write("tag=" + result["tag"] + "\n")
    print("RELEASE_PREFLIGHT " + json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
