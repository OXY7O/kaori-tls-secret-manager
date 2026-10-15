# Code scanning

KAORI TLS Management analyzes **Python source and GitHub Actions workflows** using GitHub CodeQL Advanced Setup.

## Scanning policy

- **PRs targeting main:** security analysis before merge.
- **Pushes to main:** scan the merged source independently from the existing `Quality Gate`.
- **Schedule:** weekly on Monday at 09:15 Asia/Jakarta (02:15 UTC).
- **Manual:** Actions → **KAORI Code Scanning** → **Run workflow**.
- **Queries:** `security-extended`, expanding the default security suite.
- **Uploads:** GitHub code scanning results (SARIF), scoped through `security-events: write` on the CodeQL job only.

The matrix runs `CodeQL (python)` and `CodeQL (actions)` in separate jobs. The Python scan covers utility modules; the Actions scan checks workflow security patterns including token and untrusted-input usage. Neither requires access to kubeconfig, secrets, cluster endpoints, or production TLS keys.

## Downloadable analysis evidence

Each successful CodeQL matrix job still uploads its findings to **Security → Code scanning**, and also stores the generated SARIF as a short-lived (14-day) GitHub Actions artifact named `codeql-sarif-python` or `codeql-sarif-actions`. From the **KAORI Code Scanning** workflow run, open **Artifacts** to retrieve the per-language ZIP.

A `triage-summary.json` is included in each artifact. The repository-local `scripts/ci/sarif_triage.py` emits machine-readable `SARIF_SUMMARY` and `SARIF_FINDING` log lines for remote auditing without the Code Scanning Alerts API. Printed records contain **rule IDs, severity, code file/line and flow source/sink locations only**; no result messages, extracted literals, secret values, or source snippets. Missing/invalid SARIF aborts the job instead of producing a false zero-finding report.

**Important:** SARIF is a snapshot of per-run query results, not the GitHub alert lifecycle. Result counts cannot by themselves establish the number of *open* alerts or which alerts were *dismissed*. Upload artifacts are accessible under repository Actions permissions; never upload production certificates, kubeconfigs, TLS keys, or live infrastructure evidence to a public repository.

## Review workflow

1. Open [Security → Code scanning](https://github.com/OXY7O/kaori-tls-secret-manager/security/code-scanning).
2. Check the analysis history for **both** languages on the default branch.
3. Triage findings by **reachability, severity, and relevance to Kubernetes Secret handling**. Prioritize credential exposure, command injection, unsafe subprocess usage, authorization bypass, dangerous file operations, and overly broad GitHub Actions permissions.
4. Fix confirmed vulnerabilities through focused PRs and synthetic regression tests.
5. Document false positives with a technical rationale instead of suppressing them globally.
6. Verify each PR passes `Quality Gate` and the corresponding CodeQL jobs before merge. **Do not make an unproven scanning job a required branch check until runs stabilize and baseline findings have been reviewed.**

CodeQL is static analysis. A passing scan cannot certify safe live Kubernetes behavior, endpoint identity, or encrypted recovery procedures. The existing [security policy](../SECURITY.md) and [release quality policy](RELEASE-POLICY.md) remain applicable.

## Interpretation of the initial 38-result baseline

The initial `security-extended` scan flagged 32 `py/clear-text-logging-sensitive-data` sinks, four `py/clear-text-storage-sensitive-data` sinks, a Gateway API exact-match check, and one obsolete-TLS policy concern. The TLS concern was addressed by [PR #18](https://github.com/OXY7O/kaori-tls-secret-manager/pull/18). The remaining findings must be **triaged individually** using the [security backlog](https://github.com/OXY7O/kaori-tls-secret-manager/issues/17) and SARIF paths.

**Threat model and output contract:** the guided wizard and command-line interfaces intentionally display the **namespace, Kubernetes Secret *resource name*, SANs, issuer, fingerprint, endpoint IP/hostname, diagnostic status, and local evidence path** to an authenticated, accountable operator. Kubernetes Secret **values** (`data.tls.key`, private keys, kubeconfigs, recovery identities, and API tokens) are *not authorized* in reports or terminal output. A resource named `web-tls` is not the value of its `tls.key` field. **Nevertheless, resource names, hostnames, IPs, and run context are operationally sensitive infrastructure metadata, not public information.**

For production operations, use a private workstation/session. Treat terminal scrollback, shell transcripts, JSON stdout, redirected output, support screenshots, and exported evidence as **confidential operational data**. Do not route these into shared log aggregators, tickets, public repositories, CI artifacts, or public chat channels. Evidence files must be created as mode `0600` inside mode `0700` directories; the helper creates sensitive reports with restricted permissions **before** writing content, even under a permissive process umask.

When triaging a logging alert, establish whether CodeQL's **source** is a resource identity (intentional), a verified metadata field, or an actual credential/key value (must fix). Do not dismiss a finding solely based on its message or occurrence in an operator terminal. Record rule ID, sink, source, classification, allowed exposure, and mitigation. A justified *won't-fix* for intentional operator metadata is an acknowledged conditional risk, not proof that metadata cannot be disclosed.

## Branch protection

The current required status check remains **Quality Gate**. After the CodeQL runs are green and findings have been reviewed, consider adding both **CodeQL (python)** and **CodeQL (actions)** as required GitHub Actions checks under the main ruleset. Do not require the post-merge **Publish Release** job on pull requests.

Repository rulesets are managed in GitHub Settings; committing a workflow does not update branch protection.
