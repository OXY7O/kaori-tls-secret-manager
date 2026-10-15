# Changelog

All notable changes to **KAORI TLS Management** are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

No subsequent user-facing changes have been recorded.

## [0.1.0-rc.1] - 2026-10-15

**First public community prerelease — evaluation only, not production-approved.**

### Added

- Single-repository operator utility with guided Kubernetes TLS inventory, expiry audit, Toolbox/Doctor, HTTPS verification, HOLD review, renewal, run history and restore flows.
- Guarded CRUD inventory/inspect plus explicit Create, single-target same-SAN Update and dependency-aware Delete plans with fail-closed protections.
- Delete preflight for Ingress, Pod, Gateway and controller ownership; incomplete reference visibility produces HOLD, not a force path.
- Single-operator interactive confirmations and optional separately signed approval for automation workflows.
- Encrypted `age` recovery backups, immutable plans, mutation journals, resourceVersion/UID preconditions and no blind replay on ambiguous API results.
- TLS Doctor (stored vs served certificate), aggregate Prometheus textfile output and synthetic offline test coverage.
- Professional documentation, supported command reference, examples, security guidance, contribution and community files, issue/PR templates and Ubuntu/WSL installation guide.
- Approved transparent PNG KAORI TLS Management wordmark and orbital-K companion icon, with terminal-aware inline logo display and plain fallback.

### Changed

- Repository default `main` is the distribution branch; no secondary checkout or migration branch is required.
- README and local validation instructions now distinguish a **prerelease** from a production-accepted release; badges point at main.

### Security

- No bulk/force Delete or unattended write modes; manual external-consumer attestation remains mandatory for guided Delete.
- No production access or credentials in offline CI. Outputs and backups must stay in protected directories outside Git.

### Known limitations

- Independent security/privacy review, real Kubernetes DEV/UAT, signed authorization acceptance, encrypted backup restore, and endpoint-owner sign-off are not complete.
- Only source distribution on Linux/WSL is documented; no binary installer, verified compatibility matrix or production support SLA.
- `0.1.0-rc.1` is **not** a stable production release. See [release notes](docs/releases/v0.1.0-rc.1.md) and [release checklist](docs/RELEASE-CHECKLIST.md).

[0.1.0-rc.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0-rc.1
