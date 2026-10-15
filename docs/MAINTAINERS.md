# Repository maintenance

This document describes GitHub repository metadata, contribution workflow and branch governance for KAORI TLS Management. Configuration settings in GitHub are administered separately from source files.

## Project metadata

**Description:** Operator-first Kubernetes TLS certificate management utility with guided inventory, diagnostics, guarded renewal and lifecycle controls.

**Suggested topics:** kubernetes, tls, certificates, cli, python, devops, sre, security, certificate-management, kubernetes-secrets, open-source.

Project branding: [PNG wordmark](../assets/kaori-logo.png) and [orbital-K mark](../assets/kaori-mark.png).

## Branch governance

Recommended **main** branch ruleset:

- Pull request required before merging, conversation resolution required.
- Required status check **Quality Gate**, source **GitHub Actions**; this runs syntax, regression, CLI entrypoints and no-cluster-credentials checks.
- Block force pushes and branch deletion.
- For a single maintainer, do not require a second human approval unless organizational policy demands it.
- Do not require **Publish Release** to pass before merge: it runs only on main after merge.

Repository rulesets and security reporting settings are controlled in GitHub Settings. This documentation does not imply that settings have been activated.

## Maintenance practices

Use versioned tags and the [release policy](RELEASE-POLICY.md). Keep GitHub Actions permissions least-privileged; never inject kubeconfigs, certificates, TLS private keys or recovery identities into CI. Route security disclosures through [SECURITY.md](../SECURITY.md); ordinary support questions belong in sanitized public issues.

Issue and pull request templates are stored under .github/. See [CONTRIBUTING.md](../CONTRIBUTING.md) for tests and review expectations, and [GOVERNANCE.md](../GOVERNANCE.md) for decision authority.
