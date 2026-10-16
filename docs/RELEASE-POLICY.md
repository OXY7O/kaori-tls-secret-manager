# Release quality and operational assurance

KAORI TLS Secret Manager publishes immutable SemVer source archives with SHA-256 checksums through GitHub Releases. The release workflow is documented in [RELEASING.md](RELEASING.md); the published version is identified by the [VERSION file](../VERSION).

## What the Quality Gate verifies

The **Quality Gate** on pull requests and the merged main commit performs **change-impact-aware checks**:

- For TLS/Kubernetes runtime, mutation, unknown and critical workflow changes: full Python/Bash syntax validation, all synthetic regression tests (including guarded lifecycle safety) and CLI smoke checks.
- For approved documentation or isolated CI/test changes: mapped regression tests only; skipped steps remain visible in Actions. See [Change-Impact CI/CD](CI-CHANGE-IMPACT.md).
- On a scheduled weekly baseline or manual dispatch: full tests, syntax and CLI checks regardless of change scope.
- For **every** mode: an assertion that the workflow does not receive Kubernetes credentials.

The GitHub required status context remains `Quality Gate` regardless of selected scope. CodeQL and Ruff remain separate required branch checks; a docs-only PR cannot bypass those scans.

After the main Quality Gate passes, **Release Preflight** checks version metadata and GitHub's existing tag/release with read-only permissions. If the immutable version is already complete, the write-capable **Publish Release** job is skipped entirely—no archive or checksum is rebuilt. For a genuinely new version, Publish Release rechecks eligibility after serialization, packages the exact commit, verifies the archive and publishes SHA256SUMS. Any API failure, pre-existing orphan tag or incomplete published release triggers a fail-closed stop; existing versions are never overwritten.

## What a source release does not certify

Public release artifacts do **not** establish an independent security audit, a supported Kubernetes distribution/version matrix, a service-level agreement, or successful operation in any specific cluster. GitHub Actions never connects to a live Kubernetes environment.

For operational changes, the accountable administrator must verify Kubernetes context and RBAC, certificate policy and SANs, target ownership and references, endpoint trust, encrypted recovery and restore procedures, and any required change approvals. An uncertain API result or incomplete dependency scan remains a STOP/HOLD condition.

See [Security](../SECURITY.md), [Architecture](ARCHITECTURE.md), [Operator guide](OPERATOR-GUIDE.md) and the [Delete procedure](DELETE-TLS-SECRET-SOP.md) for controls and responsibilities.

## Compatibility and maintenance

The current public release is **v0.2.7** under Semantic Versioning. The 0.x series may introduce interface changes between releases; release notes document changes. Operators should use immutable tags for reproducibility and inspect the [changelog](../CHANGELOG.md) before upgrading. No managed infrastructure support or guaranteed response time is included.
