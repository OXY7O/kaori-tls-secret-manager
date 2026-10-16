# Change-Impact CI/CD — KAORI

## Purpose

The always-required **Quality Gate** should not run every old test for every change. KAORI selects the smallest safe synthetic regression suite *without* waiving Kubernetes TLS Secret safety or GitHub's existing branch protection. This is a conservative first version, not an assumption that module dependencies are fully independent.

### Selection matrix

| Changed file/area | Quality Gate scope |
| --- | --- |
| README, Markdown docs, community templates | Documentation integrity tests only |
| Branding assets | Branding and documentation tests |
| Synthetic example input CSV/TXT | Inventory and staged endpoint tests |
| Individual `tests/test_*.py` | Only changed test module(s) |
| CI helper `sarif_triage.py`, `code_scanning_alerts.py`, `changed_python_quality.py` | Corresponding helper tests |
| Ruff configuration / Ruff workflow | Ruff selection and required-check policy tests |
| TLS Secret manager, CRUD, wizard, inventory, ops, shell entrypoints | **FULL** tests + Python/Bash syntax + CLI smoke |
| CI, CodeQL, impact analyzer, version, gitignore | **FULL** tests + syntax + CLI smoke |
| Unknown/unsafe file, empty diff, missing mapping | **FULL**, never silent skip |
| Scheduled Monday 10:00 WIB / manual dispatch | **FULL** baseline regardless of changes |

The selected mode loads only mapped `unittest` modules. Documentation mode skips Python setup, full source compilation and CLI smoke; the required job still completes normally. The full mode preserves the historical `python3 -m unittest discover -s tests -v` and all CLI checks.

The minimum safety check (no `KUBECONFIG` in CI) **always runs**, even for a Markdown-only change. Missing files, invalid commit hashes and Git-diff failures **fail closed**. The analyzer uses NUL-separated filenames and `--no-renames`, so renamed/deleted sensitive sources cannot hide behind a destination path.

### Security and coverage guardrails

- Existing **CodeQL (python)**, **CodeQL (actions)** and **Python Quality (Ruff)** remain separately required in branch protection. Change-impact optimization does not disable or skip CodeQL.
- Changes to mutation paths always run comprehensive synthetic safety tests. Only controlled operator UAT can establish real-cluster correctness, backup recovery and RBAC behavior; CI never operates production Kubernetes.
- No cache or unchecked test-results reuse: each PR re-executes impacted suites.
- Full regression is enforced on a scheduled weekly baseline, on workflow dispatch, and for critical/shared runtime changes.
- To add a new module or test group, first update `scripts/ci/impact_gate.py` and `tests/test_impact_gate.py`; otherwise the path triggers full regression.

### Evidence and monitoring

Look for the `IMPACT_PLAN` line in each **Quality Gate** run. It records `mode`, `reason` and selected test modules. Compare `docs` and `selected` duration against `full` before expanding the mapping. Because the check name is **Quality Gate** for every mode, the existing required-check ruleset stays compatible.

Avoid deleting important safety tests or reducing assertions to make CI faster. Security-critical false negatives are more expensive than a full run.

## Verification scenario — documentation-only PR

To validate the policy end to end, edit only this documentation page and open a PR against `main`. In the always-present **Quality Gate**, check that `IMPACT_PLAN` reports `"mode": "docs"`; it should run documentation integrity tests, skip Python setup, source syntax checks and CLI smoke, but still perform Cluster Isolation. Required CodeQL and Ruff checks must still PASS independently.
