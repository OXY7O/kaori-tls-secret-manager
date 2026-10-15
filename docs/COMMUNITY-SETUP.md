# GitHub community publishing setup

Repository documents and templates live in Git. Some repository-wide GitHub settings **cannot be applied by committing files** and require an authorized repository administrator. This page records the recommended public-facing configuration without claiming that it has been activated.

## Suggested repository metadata

**About description:**
> Operator-first CLI for inspecting, validating, renewing, creating and safely decommissioning Kubernetes TLS Secrets.

**Suggested GitHub Topics:** `kubernetes`, `tls`, `certificates`, `cli`, `python`, `devops`, `sre`, `security`, `certificate-management`, `kubernetes-secrets`, `open-source`.

**Project identity:** KAORI TLS Management. The GitHub repository remains **kaori-tls-secret-manager** for continuity; no name change is required to show the product name in README. Use **assets/kaori-mark.png** for project mark and **assets/kaori-logo.png** for the full wordmark.

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
- Protect `main` with pull requests, resolved conversations, and a **required GitHub Actions check named `Quality Gate`** (job id: `quality_gate`). This runs syntax, regression, CLI smoke tests and a no-cluster-access assertion. For a single maintainer, configure 0 required approvals if GitHub offers that option; don't require a second reviewer.
- Do **not** require `Publish Release` for merging: the release job only runs after a push/merge to `main`, and would otherwise block pull requests.
- If a previous ruleset required `offline`, replace that obsolete check with `Quality Gate` and choose **GitHub Actions** as its source. The Actions connection cannot edit rulesets automatically; check repository Settings → Rules → Rulesets.
- Keep Actions permissions minimally scoped; do not add production kubeconfigs or recovery keys as CI secrets.
- Decide whether GitHub Discussions should be enabled for community questions; otherwise route sanitized support issues through existing templates.
- Confirm the initial release version, source archive integrity, supported environments and release note checks with [release checklist](RELEASE-CHECKLIST.md) before promoting from community prerelease to stable production support.

## Community documentation already in the tree

README, CHANGELOG, LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, GOVERNANCE, command reference, FAQ, branding guidance, GitHub issue forms and PR template.

Documentation and assets are a readiness step, **not** a substitute for security testing and Kubernetes DEV/UAT sign-off.
