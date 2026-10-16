# Python Code Quality (Ruff)

KAORI uses **Ruff** as an open-source, repo-owned Python linter. The GitHub product **Code Quality Findings** is intentionally **not enabled**; it is not needed for this workflow. GitHub Actions runner usage follows the repository's normal billing and quota policy.

## Scope and cost controls

- Workflow: [KAORI Python Quality](../.github/workflows/python-quality.yml), separate from CodeQL SAST and the established `Quality Gate`.
- The **Python Quality (Ruff)** status check runs on **every pull request targeting `main`**, including documentation-only changes, because GitHub branch protection requires this check. Pushes to `main` remain path-filtered to Python source or Ruff/workflow configuration changes.
- Within the workflow, checks **only existing Python files changed** between the base and the new commit, including renamed files. Deleted files, Markdown, shell files, and unchanged Python files are not linted.
- A workflow run with no Python file changes skips **Python setup, Ruff installation and lint execution**. This does not claim GitHub Actions runner startup is free.
- Shallow-history ambiguity is avoided using `fetch-depth: 0`; missing/bad Git SHAs cause detection to fail instead of silently skipping.
- Ruff version is pinned to `0.17.1`; install is conditional. Files are forwarded as JSON and argv, not interpolated into shell commands.
- For a repository's first push (zero base SHA), the detector checks all tracked Python files. Manual complete scans are also possible: `ruff check scripts tests`.

## Initial incremental rule set

The [Ruff configuration](../ruff.toml) targets Python 3.10 and selects `E4`, `E7`, `E9`, `F601`, `F602`, `F632`, `F811`, `F821`, `F822`, and `F823`: import/statement errors, certain unsafe constructs, duplicate dictionary keys, symbol redefinitions, and undefined/unbound names. These are deliberately **high signal**, not a claim of full style or maintainability coverage. Formatting and broader categories can be expanded through separate measured PRs after assessing existing code debt.

## Developer usage

~~~bash
python3 -m pip install 'ruff==0.17.1'
ruff check scripts/ci/changed_python_quality.py tests/test_changed_python_quality.py
python3 -m unittest tests/test_changed_python_quality.py
~~~

A failed Ruff check must be fixed before merging the associated PR. Ruff never runs with `--fix` in CI. Do not suppress findings, loosen rules or widen check scope just to obtain a green status without review.

**GitHub branch protection:** the active `main-branch-protection` ruleset requires `Quality Gate`, `CodeQL (python)`, `CodeQL (actions)`, and `Python Quality (Ruff)` from GitHub Actions. Keep PR-level path filters **disabled** on the Ruff workflow. The job uses internal change detection, reports success on documentation-only PRs without setting up Python or installing Ruff, and genuinely fails for Ruff violations in modified Python files. CodeQL continues running on every PR. Push-level path filters remain enabled solely to avoid unnecessary post-merge Ruff jobs. Do not add `Publish Release` or conditional/post-merge alert inventory jobs as required checks.

## Required-check smoke test: documentation-only pull request

A documentation-only pull request provides a useful regression check for required status-check wiring: all four required contexts should be present, but the Ruff job must skip Python setup, dependency installation, and lint execution when no Python files changed. Check the job's `Python files affected by this change: 0` output. This tests branch-protection readiness without touching live Kubernetes configuration or TLS material.
