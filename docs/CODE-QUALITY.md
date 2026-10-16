# Python Code Quality (Ruff)

KAORI uses **Ruff** as an open-source, repo-owned Python linter. The GitHub product **Code Quality Findings** is intentionally **not enabled**; it is not needed for this workflow. GitHub Actions runner usage follows the repository's normal billing and quota policy.

## Scope and cost controls

- Workflow: [KAORI Python Quality](../.github/workflows/python-quality.yml), separate from CodeQL SAST and the established `Quality Gate`.
- Runs only for **pull requests to main** or **pushes to main** that touch a Python file, `ruff.toml`, or the quality workflow.
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

**GitHub branch protection:** `Quality Gate` remains required. To enforce the new job independently, an administrator can add `Python Quality (Ruff)` as a required check, but only after considering the behavior of **path-filtered workflows**: a required check skipped entirely by workflow path filters can block unrelated PRs. If promoting this job to required, remove event-level `paths` and keep the lightweight internal change detection and conditional Ruff installation so the check reports success for docs-only PRs.
