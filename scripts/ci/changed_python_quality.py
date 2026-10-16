#!/usr/bin/env python3
"""Run Ruff on Python files changed by this PR/push, never the whole legacy tree.

No external action, credential, or Kubernetes context required. Filename lists
are passed as JSON/argv, not interpolated into shell commands.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path


SHA = re.compile(r"[a-fA-F0-9]{40}\Z")


def changed_python_files(base, head, *, root=Path(".")):
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("Expected 40-character commit SHA for base and head")
    if base == "0" * 40:
        command = ["git", "ls-files", "-z", "--", "*.py"]
    else:
        command = [
            "git", "diff", "--name-only", "-z", "--diff-filter=ACMR",
            base, head, "--", "*.py",
        ]
    result = subprocess.run(command, cwd=root, check=True, capture_output=True)
    names = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    return sorted({
        name for name in names
        if name.endswith(".py") and
        not Path(name).is_absolute() and
        ".." not in Path(name).parts and
        (root / name).is_file()
    })


def write_detection(paths, json_file, github_output):
    Path(json_file).write_text(json.dumps(paths, ensure_ascii=True) + "\n", encoding="utf-8")
    with open(github_output, "a", encoding="utf-8") as output:
        output.write("has_python=" + ("true" if paths else "false") + "\n")
    print(f"Python files affected by this change: {len(paths)}")
    if not paths:
        print("Skipping Ruff: no Python source changed.")


def lint_files(json_file):
    files = json.loads(Path(json_file).read_text(encoding="utf-8"))
    if not isinstance(files, list) or not files:
        raise ValueError("Expected at least one changed Python file to lint")
    for name in files:
        if (not isinstance(name, str) or not name.endswith(".py")
                or Path(name).is_absolute() or ".." in Path(name).parts
                or not Path(name).is_file()):
            raise ValueError("Unsafe or missing Python path in changed-file manifest")
    print(f"Ruff checking exactly {len(files)} changed Python file(s).", flush=True)
    command = ["ruff", "check", "--no-cache", "--output-format=github", "--", *files]
    return subprocess.run(command, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    detector = subcommands.add_parser("detect")
    detector.add_argument("--base", required=True)
    detector.add_argument("--head", required=True)
    detector.add_argument("--json-file", required=True)
    detector.add_argument("--github-output", required=True)
    checker = subcommands.add_parser("lint")
    checker.add_argument("--json-file", required=True)
    args = parser.parse_args()
    if args.command == "detect":
        paths = changed_python_files(args.base, args.head)
        write_detection(paths, args.json_file, args.github_output)
    else:
        raise SystemExit(lint_files(args.json_file))


if __name__ == "__main__":
    main()
