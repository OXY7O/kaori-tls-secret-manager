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

## Review workflow

1. Open [Security → Code scanning](https://github.com/OXY7O/kaori-tls-secret-manager/security/code-scanning).
2. Check the analysis history for **both** languages on the default branch.
3. Triage findings by **reachability, severity, and relevance to Kubernetes Secret handling**. Prioritize credential exposure, command injection, unsafe subprocess usage, authorization bypass, dangerous file operations, and overly broad GitHub Actions permissions.
4. Fix confirmed vulnerabilities through focused PRs and synthetic regression tests.
5. Document false positives with a technical rationale instead of suppressing them globally.
6. Verify each PR passes `Quality Gate` and the corresponding CodeQL jobs before merge. **Do not make an unproven scanning job a required branch check until runs stabilize and baseline findings have been reviewed.**

CodeQL is static analysis. A passing scan cannot certify safe live Kubernetes behavior, endpoint identity, or encrypted recovery procedures. The existing [security policy](../SECURITY.md) and [release quality policy](RELEASE-POLICY.md) remain applicable.

## Branch protection

The current required status check remains **Quality Gate**. After the CodeQL runs are green and findings have been reviewed, consider adding both **CodeQL (python)** and **CodeQL (actions)** as required GitHub Actions checks under the main ruleset. Do not require the post-merge **Publish Release** job on pull requests.

Repository rulesets are managed in GitHub Settings; committing a workflow does not update branch protection.
