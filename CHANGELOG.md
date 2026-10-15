# Changelog

All notable changes to **KAORI TLS Certificate Manager** are documented here.

The project follows the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) structure and intends to use [Semantic Versioning](https://semver.org/) for **published stable releases**. Until an initial accepted release, changes are recorded under **Unreleased**; the VERSION file currently identifies the development source as **0.1.0-dev**. This document is not a production release announcement.

## [Unreleased]

### Added

- Original KAORI guided terminal wizard with inventory, reporting and diagnostics, TLS Inventory, Expiry Audit, Toolbox, renewal, HOLD review, run history and HTTPS verification.
- Integrated **Create TLS Secret** and **Delete TLS Secret** in the same operator interface.
- Guarded single-target CRUD engine for inventory, inspect, plan-create/create, plan-update/update and plan-delete/delete.
- Read-only dependency discovery for Delete covering Ingress TLS references, Pods, Gateway API references and controller ownership; incomplete visibility and referenced targets return HOLD.
- Single-operator prompted confirmations, an optional independent signed-approval flow, age-encrypted recovery for destructive operations and write journals.
- Local **TLS Doctor** with certificate-versus-HTTPS fingerprint and trust diagnostics, plus local Prometheus textfile metrics export.
- Offline regression tests, Linux/WSL validation guide and scoped GitHub Actions CI.
- Public-facing documentation, PNG branding assets, terminal-integrated shield identity, command reference, issue templates, contribution and community governance guidance.

### Security

- Delete is a single-target guarded operation with live UID/resourceVersion preconditions and post-delete absence verification.
- No forced deletion, automatic recovery after ambiguous writes, certificate issuance or bulk Delete.
- Encrypted backup verification precedes the guarded interactive Delete. Plans, backups, journals, kubeconfig and private keys stay outside source control.
- A clean Kubernetes scan does not establish absence of **external** consumers; deletion requires human attestation.

### Release status

- Implementation is on **feat/crud-and-repo-migration** pending merge and formal release approval.
- Offline tests passing does not replace independent security/privacy review, DEV/UAT Kubernetes acceptance, restore verification, endpoint owner sign-off, release attestation or installability checks.
- No stable release, support promise or production deployment approval is claimed.

<!-- Upon release, add: ## [X.Y.Z] - YYYY-MM-DD and a GitHub tag comparison link. -->
