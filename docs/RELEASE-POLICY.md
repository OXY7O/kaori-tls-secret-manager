# Release quality and operational assurance

KAORI TLS Management publishes immutable SemVer source archives with SHA-256 checksums through GitHub Releases. The release workflow is documented in [RELEASING.md](RELEASING.md); the published version is identified by the [VERSION file](../VERSION).

## What the Quality Gate verifies

The **Quality Gate** on pull requests and the merged main commit performs:

- Python and Bash syntax validation for CLI modules and launchers.
- Automated synthetic regression tests, including guarded lifecycle safety cases.
- CLI help and dependency-doctor smoke checks.
- An assertion that the workflow does not receive Kubernetes credentials.

After the main Quality Gate passes, **Publish Release** validates version metadata, packages the exact commit, checks archive readability and publishes SHA256SUMS. Published versions are not overwritten.

## What a source release does not certify

Public release artifacts do **not** establish an independent security audit, a supported Kubernetes distribution/version matrix, a service-level agreement, or successful operation in any specific cluster. GitHub Actions never connects to a live Kubernetes environment.

For operational changes, the accountable administrator must verify Kubernetes context and RBAC, certificate policy and SANs, target ownership and references, endpoint trust, encrypted recovery and restore procedures, and any required change approvals. An uncertain API result or incomplete dependency scan remains a STOP/HOLD condition.

See [Security](../SECURITY.md), [Architecture](ARCHITECTURE.md), [Operator guide](OPERATOR-GUIDE.md) and the [Delete procedure](DELETE-TLS-SECRET-SOP.md) for controls and responsibilities.

## Compatibility and maintenance

The current public release is **v0.1.0** under Semantic Versioning. The 0.x series may introduce interface changes between releases; release notes document changes. Operators should use immutable tags for reproducibility and inspect the [changelog](../CHANGELOG.md) before upgrading. No managed infrastructure support or guaranteed response time is included.
