# Project governance

KAORI TLS Certificate Manager is maintained in the open in the [OXY7O repository](https://github.com/OXY7O/kaori-tls-secret-manager).

## Collaboration

Anyone may propose issues, documentation improvements, synthetic tests and pull requests under the [Code of Conduct](CODE_OF_CONDUCT.md). Maintainers decide what to merge based on technical merit, usability, regression risk, security and compatibility; opening a PR does not guarantee acceptance.

Security-impacting decisions require explicit review of failure modes, dependency visibility, backup integrity, authentication/approval behavior, idempotency and error handling. Changes to fail-closed controls must not be silently combined with unrelated formatting improvements.

## Roles and decision making

- **Contributors** propose focused changes and respond to review.
- **Maintainers** triage reports, review patches, curate milestones, approve merges and control repository settings.
- **Release maintainers** additionally validate the [release checklist](docs/RELEASE-CHECKLIST.md), versioning, integrity evidence and change log before creating a public release.

Maintainers retain final discretion over merges, security disclosure coordination, release approval, branch policy and moderation. No current support SLA or dedicated maintainer on-call schedule is implied.

## Release lifecycle

The application publishes **v0.1.0**, its initial public Semantic Versioning source release, after an offline regression gate on `main`. Release tags and dated changelog entries are immutable. **0.x** permits an evolving interface and does **not** constitute real Kubernetes DEV/UAT acceptance, production authorization or an operations SLA.

Compatibility-breaking CLI/menu/output changes require explicit rationale, documentation and regression testing. Production-impacting changes must be validated in an approved isolated environment before a maintainer can claim production readiness.
