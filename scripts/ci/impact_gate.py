#!/usr/bin/env python3
"""Fail-closed change-impact selection for KAORI's always-required Quality Gate.

Unsafe or unknown paths select the FULL regression suite; docs-only changes run
documentation checks. All Kubernetes/TLS mutation and shared runtime modules
always select FULL safety coverage. Full scans run weekly and on demand.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import unittest

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
ROOT = Path(__file__).resolve().parents[2]

CORE_RUNTIME = {
    "scripts/tls_crud.py",
    "scripts/tls-secret-manager.sh",
    "scripts/kaori-tls-secret-manager.sh",
    "scripts/kubernetes/tls-secret-manager/tls-secret-manager.sh",
    "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py",
    "scripts/kubernetes/tls-secret-manager/tls_secret_wizard.py",
    "scripts/kubernetes/tls-secret-manager/tls_ops.py",
    "scripts/kubernetes/tls-secret-manager/tls_inventory.py",
}
CI_HELPERS = {
    "scripts/ci/sarif_triage.py": "test_sarif_triage.py",
    "scripts/ci/code_scanning_alerts.py": "test_code_scanning_alerts.py",
    "scripts/ci/changed_python_quality.py": "test_changed_python_quality.py",
}
SAFE_CONFIGURATION = {
    "ruff.toml": {"test_changed_python_quality.py", "test_required_check_policy.py"},
    ".github/workflows/python-quality.yml": {
        "test_changed_python_quality.py", "test_required_check_policy.py"},
}
BASE_TESTS = {"test_documentation_integrity.py"}
BRANDING_TESTS = {"test_branding_assets.py", "test_documentation_integrity.py"}


def changed_paths(base, head, *, root=ROOT):
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("Base and head must be full commit SHAs")
    if base == "0" * 40:
        # First push: no trustworthy previous baseline; force full validation.
        return {"<initial-push>"}
    command = ["git", "diff", "--no-renames", "--name-only", "-z", base, head, "--"]
    result = subprocess.run(command, cwd=root, capture_output=True, check=True)
    paths = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    return {p for p in paths if p}


def classify(paths, *, event="pull_request"):
    if event in {"schedule", "workflow_dispatch"}:
        return {"mode": "full", "reason": event + " complete baseline", "tests": []}
    if not paths:
        # No diff or unexpected event: never report a misleading validated build.
        return {"mode": "full", "reason": "empty/unresolved diff", "tests": []}
    tests = set()
    docs_only = True
    for item in sorted(paths):
        path = PurePosixPath(item)
        if (item.startswith("<") or path.is_absolute() or ".." in path.parts
                or "\n" in item or "\r" in item or "\\" in item):
            return {"mode": "full", "reason": "untrusted change path", "tests": []}
        if item in CORE_RUNTIME:
            return {"mode": "full", "reason": "TLS/Kubernetes runtime change", "tests": []}
        if item in {".github/workflows/ci.yml", ".github/workflows/codeql.yml",
                    "scripts/ci/impact_gate.py", "VERSION", ".gitignore"}:
            return {"mode": "full", "reason": "quality/security control changed", "tests": []}
        if item in CI_HELPERS:
            tests.add(CI_HELPERS[item])
            docs_only = False
        elif item in SAFE_CONFIGURATION:
            tests.update(SAFE_CONFIGURATION[item])
            docs_only = False
        elif item.startswith("tests/") and item.endswith(".py"):
            # Only the touched test modules; runtime changes are handled above.
            tests.add(path.name)
            docs_only = False
        elif item.startswith("assets/"):
            tests.update(BRANDING_TESTS)
            docs_only = False
        elif item.startswith("scripts/kubernetes/tls-secret-manager/examples/"):
            tests.update({"test_tls_inventory.py", "test_tls_staged_endpoints.py"})
            docs_only = False
        elif (item.endswith(".md") or item in {"LICENSE", "CODE_OF_CONDUCT.md", ".editorconfig"}
              or item.startswith(".github/ISSUE_TEMPLATE/")
              or item == ".github/PULL_REQUEST_TEMPLATE.md"):
            tests.update(BASE_TESTS)
        else:
            return {"mode": "full", "reason": "unmapped path (fail closed)", "tests": []}
    return {
        "mode": "docs" if docs_only else "selected",
        "reason": "documentation-only" if docs_only else "mapped changed files",
        "tests": sorted(tests),
    }


def write_plan(plan, *, output, filename):
    Path(filename).write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write("mode=" + plan["mode"] + "\n")
        stream.write("run_syntax=" + ("true" if plan["mode"] != "docs" else "false") + "\n")
        stream.write("run_smoke=" + ("true" if plan["mode"] == "full" else "false") + "\n")
    print("IMPACT_PLAN " + json.dumps(plan, sort_keys=True), flush=True)


def run_tests(plan, *, root=ROOT):
    if plan["mode"] == "full":
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
        return subprocess.run(cmd, cwd=root, check=False).returncode
    tests = plan["tests"]
    if not tests:
        raise ValueError("Selected/docs mode must specify regression test modules")
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for name in tests:
        if (not re.fullmatch(r"test_[A-Za-z0-9_]+\.py", name)
                or not (root / "tests" / name).is_file()):
            raise ValueError("Mapped regression module missing/unsafe: " + name)
        suite.addTests(loader.discover(str(root / "tests"), pattern=name,
                                      top_level_dir=str(root / "tests")))
    if suite.countTestCases() == 0:
        raise ValueError("No tests loaded from mapped modules")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    detector = sub.add_parser("detect")
    detector.add_argument("--base", required=True)
    detector.add_argument("--head", required=True)
    detector.add_argument("--event", required=True)
    detector.add_argument("--output", required=True)
    detector.add_argument("--plan", required=True)
    runner = sub.add_parser("test")
    runner.add_argument("--plan", required=True)
    args = parser.parse_args()
    if args.command == "detect":
        if args.event in {"schedule", "workflow_dispatch"}:
            plan = classify({"<scheduled-full>"}, event=args.event)
        else:
            plan = classify(changed_paths(args.base, args.head), event=args.event)
        write_plan(plan, output=args.output, filename=args.plan)
    else:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        if plan.get("mode") not in {"full", "docs", "selected"}:
            raise ValueError("Unknown impact plan mode")
        raise SystemExit(run_tests(plan))


if __name__ == "__main__":
    main()
