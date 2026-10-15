# GitHub community publishing setup

Repository documents and templates live in Git. Some repository-wide GitHub settings **cannot be applied by committing files** and require an authorized repository administrator. This page records the recommended public-facing configuration without claiming that it has been activated.

## Suggested repository metadata

**About description:**
> Operator-first CLI for inspecting, validating, renewing, creating and safely decommissioning Kubernetes TLS Secrets.

**Suggested GitHub Topics:** `kubernetes`, `tls`, `certificates`, `cli`, `python`, `devops`, `sre`, `security`, `certificate-management`, `kubernetes-secrets`, `open-source`.

**Project identity:** KAORI TLS Certificate Manager. The GitHub repository remains **kaori-tls-secret-manager** for continuity; no name change is required to show the product name in README. Use **assets/kaori-mark.svg** for project mark and **assets/kaori-logo.svg** for the full wordmark.

## Recommended issue labels

| Label | Purpose |
| --- | --- |
| `bug` | Reproducible defect |
| `enhancement` | Feature request |
| `documentation` | Docs / examples |
| `security-review` | Internal tracking only; **never disclose vulnerability details in public issues** |
| `needs-reproduction` | Missing synthetic example |
| `good first issue` | Clearly scoped newcomer task |
| `help wanted` | Contributions welcome |
| `release` | Packaging / publishing |
| `blocked` | Waiting on an explicit dependency |

Labels are **recommendations**; adding this file does not create labels in the GitHub issue tracker.

## Repository settings

- Enable private vulnerability reporting under repository Security settings if supported and nominate a private disclosure contact.
- Set branch protections/rulesets so a maintainer review and relevant offline CI checks are required before merging to the future stable branch.
- Keep Actions permissions minimally scoped; do not add production kubeconfigs or recovery keys as CI secrets.
- Decide whether GitHub Discussions should be enabled for community questions; otherwise route sanitized support issues through existing templates.
- Confirm the initial release version, source archive integrity, supported environments and release note checks with [release checklist](RELEASE-CHECKLIST.md) before promoting from development preview.

## Community documentation already in the tree

README, CHANGELOG, LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, GOVERNANCE, command reference, FAQ, branding guidance, GitHub issue forms and PR template.

Documentation and assets are a readiness step, **not** a substitute for security testing and Kubernetes DEV/UAT sign-off.
