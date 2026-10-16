# Changelog

All notable changes to **KAORI TLS Management** are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

No additional user-facing changes beyond v0.2.0 have been recorded.

## [0.2.0] - 2026-10-16

**Guarded single-operator Kubernetes TLS lifecycle and encrypted recovery improvements.**

### Added

- Guided same-SAN **Update TLS Secret** using explicit target confirmation, encrypted backup, and post-write verification.
- Wizard **age setup / recovery help** and complete identity/key custody and restore documentation.
- **Delete recovery / Restore**: read-only reconciliation and explicitly authorized create-only restoration of verified deleted Secrets. No replay after ambiguous mutation.
- TLS Doctor override of connect IP/host with independently preserved hostname/SNI/trust validation.
- Isolated operator UAT plan and manual Gherkin scenarios; synthetic regression tests cover restoration, dormant workloads, RBAC visibility and Gateway reference scenarios.

### Changed

- Delete checks standard workload Pod templates, including scale-to-zero/suspended workloads, and cross-namespace Gateway references; missing permission remains HOLD.
- Toolbox Dependencies uses matching workload/Gateway coverage.
- Restore eligibility requires verified Delete journal, encrypted backup, unchanged cluster/namespace identity, and an absent Secret. Restores receive a new Kubernetes UID.

### Security and compatibility

- Existing Delete plans without a pinned namespace UID cannot be restored through the guided workflow. Manual incident procedure is required.
- No bulk/force Delete, no automatic retry/rollback, no overwrite during Restore.
- Published **source release** validates code and synthetic CI only. Isolated real-cluster UAT, backup drills, endpoint/application verification and operator authorization remain required before production use.

## [0.1.1] - 2026-10-15

**Documentation and release-process maintenance patch; no TLS management behavior changes.**

### Changed

- Reworked README, FAQ, Support, Security, Governance and Changelog messaging to reflect the published open-source utility.
- Consolidated installation, architecture, operator and maintainer guidance into current versioned documentation.
- Replaced obsolete migration and task-checklist documents with evergreen release quality guidance.
- Made published-version documentation regression checks derive their expected version from `VERSION` instead of hardcoding `v0.1.0`.
- Simplified generated GitHub Release titles for future SemVer versions.

### Added

- Automated relative documentation-link integrity checks and guards against obsolete project-state terms.
- Version-specific `v0.1.1` release notes and updated secure setup examples.

### Compatibility

- No changes to runtime TLS Secret operations, authorization, backup, rollback, or CLI commands.

## [0.1.0] - 2026-10-15

**First versioned public source release.** Semantic Versioning `0.x` allows interface evolution while retaining an immutable release history.

### Added

- Immutable GitHub tag and source archive distributed with SHA-256 checksum.
- Tagged installation workflow and release notes documenting scope, supported environment and runtime expectations.
- Reproducible SemVer release process with GitHub Actions Quality Gate on `main`.

### Changed

- `VERSION`, README, SECURITY, governance and release documentation now identify the first public source release as `v0.1.0`.
- Documented scope of release automation, security policy and operator-managed deployment verification.

### Operational scope

- The release includes automated source validation and reproducible archives. Environment authorization, restore drills, RBAC and endpoint verification are operator responsibilities. The project makes no independent deployment certification claim.

## [0.1.0-rc.1] - 2026-10-15

**Release candidate preceding `v0.1.0`.**

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
- README and installation instructions use the public source repository and its automated quality checks.

### Security

- No bulk/force Delete or unattended write modes; manual external-consumer attestation remains mandatory for guided Delete.
- No production access or credentials in offline CI. Outputs and backups must stay in protected directories outside Git.

### Distribution and support

- Source archives target Linux/WSL workflows. Binary installers, universal compatibility certification and commercial support SLAs are not provided.
- Deployment authorization and workload-specific verification are the responsibility of the operator. See the [release candidate notes](docs/releases/v0.1.0-rc.1.md) and [release quality policy](docs/RELEASE-POLICY.md).

[0.2.0]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.0
[0.1.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.1
[0.1.0]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0
[0.1.0-rc.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0-rc.1
