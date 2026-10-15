# Project governance

KAORI TLS Management is maintained in the open in the [OXY7O repository](https://github.com/OXY7O/kaori-tls-secret-manager).

## Collaboration

Anyone may propose issues, documentation improvements, synthetic tests and pull requests under the [Code of Conduct](CODE_OF_CONDUCT.md). Maintainers decide what to merge based on technical merit, usability, regression risk, security and compatibility; opening a PR does not guarantee acceptance.

Security-impacting decisions require explicit review of failure modes, dependency visibility, backup integrity, authentication/approval behavior, idempotency and error handling. Changes to fail-closed controls must not be silently combined with unrelated formatting improvements.

## Roles and decision making

- **Contributors** propose focused changes and respond to review.
- **Maintainers** triage reports, review patches, curate milestones, approve merges and control repository settings.
- **Release maintainers** additionally validate the [release policy](docs/RELEASE-POLICY.md), versioning, integrity evidence and change log before creating a public release.

Maintainers retain final discretion over merges, security disclosure coordination, release approval, branch policy and moderation. No current support SLA or dedicated maintainer on-call schedule is implied.

## Release lifecycle

KAORI TLS Management publishes versioned releases after the **Quality Gate** passes on `main`. Release tags and dated changelog entries are immutable. The `0.x` series permits interface changes; publishing source code does not confer authorization to modify Kubernetes workloads or a service-level guarantee.

Compatibility-breaking CLI/menu/output changes require explicit rationale, documentation and regression testing. Operational changes must be validated and authorized for the target environment by the responsible operator.
