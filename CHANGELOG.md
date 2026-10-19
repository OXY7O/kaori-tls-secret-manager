# Changelog

All notable changes to **KAORI TLS Management** are recorded here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

No subsequent changes beyond v0.2.9 have been recorded.

## [0.2.9] - 2026-10-19

**Enable guided single-operator multi-Secret renewal for Kubernetes Secret-bound TLS endpoints.**

### Changed
- The interactive renewal wizard displays every READY `namespace/secret` and accepts one operator's `RENEW N TLS SECRETS`, `AUTHORIZED`, and exact Plan ID. No approval JSON, detached signature or separate approver public key is required for this Secret-bound batch path.
- Backend requires an interactive TTY and validates the exact batch count and plan identity. Operator mode cannot be combined with signed evidence or used for a single target.
- External TLS termination continues to require independent signed approval, even in a wizard. Non-interactive multi-target renewal still requires separately signed authorization.
- Renewal journals now record the authorization method for audit evidence. README, operator guide, FAQ, command reference, security policy and glossary updated; synthetic negative tests added.

### Safety unchanged
- Planned READY/HOLD/SKIPPED scope, target identities, cluster UID/resourceVersion protection, age-encrypted full backup, per-target HTTPS verification before proceeding to the next Secret, STOP/HOLD and recovery boundaries.
- No unattended or automatic write retry. CI validates offline code paths only; perform real-cluster UAT separately.

## [0.2.8] - 2026-10-16

**Repair Inventory ALL read timeouts and preserve distinct README/CLI logos.**

### Fixed

- Read-only Inventory defaults to a 90-second API request timeout, 100-object LIST pagination, and two bounded retries for transient API reads; namespace discovery uses the same policy.
- Retain the original blue orbital-K README image with corrected **KAORI / TLS Secret Manager** text; the violet CLI icon remains unchanged.
- Failed Kubernetes LIST/GET becomes `INVENTORY_INCOMPLETE` with context, namespace, verb, resource and safe failure category, without logging raw kubectl stderr or Secret payloads.
- Never classify an API timeout as an INVALID certificate. Only actual malformed certificate/key material may receive INVALID.
- Inventory failure instructions explicitly state no write/rollback occurred, without irrelevant journal-recovery advice.
- Add regression tests and troubleshooting instructions with complete `kubectl auth can-i VERB RESOURCE` commands.

### Safety and compatibility

- No changes to Secret mutation/backup/rollback or their network timeouts. Retries apply **only** to Inventory GET/LIST. Incomplete scans do not produce a completed inventory report. Offline CI is not cluster UAT.

## [0.2.7] - 2026-10-16

**Neofetch-style CLI: a full-height eight-row application information panel beside the approved purple logo.**

### Changed

- Show KAORI, TLS Secret Management, maintainer OXY7O, checked-out version, `kubernetes.io/tls` scope, Python runtime, detected platform and Apache-2.0 license.
- Use one metadata line per logo row, top-aligned and neatly separated, not a sparse two-line centered title.
- Read version from the local `VERSION` file; use runtime/platform information without a network or Kubernetes call.
- Retain original approved logo, iTerm2 inline PNG, ANSI color fallback and accessible no-color/plain/narrow/non-TTY output.
- Add tests for eight-row alignment, real checkout version and metadata fallback.

### Scope

- Interactive header presentation only; no changes to TLS Secret lifecycle, authorization, backups or cluster operations.

## [0.2.6] - 2026-10-16

**Refine the terminal CLI header to a compact, neofetch-inspired symmetrical layout.**

### Changed

- Reduce the approved violet icon's terminal display from 20x10 to 16x8 cells, retaining its original source PNG and colors.
- Vertically center the readable two-line KAORI / TLS Secret Management label beside the icon.
- Shorten the visual separator to the icon's height; preserve width-aware fallback on narrow/no-color terminals and safe output in scripts.
- Update layout regression tests, install guidance and branding documentation.

### Compatibility

- Presentation-only adjustment. No change to Kubernetes TLS Secret operations, authorization, backups, or recovery. Offline CI does not substitute real terminal/cluster UAT.

## [0.2.5] - 2026-10-16

**Ensure GitHub Release title, source archive and checksums use the canonical KAORI TLS Secret Manager product name.**

### Changed

- GitHub Actions release title: **KAORI TLS Secret Manager vX.Y.Z** (not the obsolete abbreviated TLS Management label).
- Versioned source archive and extracted directory: `kaori-tls-secret-manager-vX.Y.Z.tar.gz` / `kaori-tls-secret-manager-vX.Y.Z/`.
- Update release preflight validation, synthetic tests, and current installation/release metadata to the new artifact basename.
- No Kubernetes TLS Secret operation, CLI runtime, approval policy, or encrypted backup behavior changes.

### Compatibility

- Previous immutable release assets retain their historical names. Update automation that downloads source release archives by name to use the new basename for v0.2.5+.

## [0.2.4] - 2026-10-16

**Clarify that the product manages Kubernetes TLS Secrets, not certificate issuance or external certificate management.**

### Changed

- Canonical user-facing name: **KAORI TLS Secret Manager**. Scope/positioning: **Safer Kubernetes TLS Secret management**; managed resources are Kubernetes Secrets with type `kubernetes.io/tls`.
- Replace ambiguous `DEV/UAT only; approval required` renewal warning with precise cluster authorization, single-target operator confirmation and conditions requiring independent signed approval. Read-only operations do not require change approval.
- Standardize current README, CLI prompts, operator guide, FAQ, Security Policy, help/menu, architecture and project governance terminology without renaming CLI commands or safety statuses.
- Refresh the repository wordmark to say **KAORI TLS Secret Manager**, with the approved violet emblem; terminal icon and secure operational behavior remain unchanged.
- Add a scope/authorization glossary and automated wording regression checks to prevent future drift.

### Compatibility

- No changes to Kubernetes CRUD implementation, signed approval requirements, backup/recovery safeguards or certificate handling. CI uses synthetic checks and cannot certify any live cluster.
- Earlier versioned release notes remain historical records and retain their original release-time wording.

## [0.2.3] - 2026-10-16

**Terminal header readability improvement; no Kubernetes behavior change.**

### Changed

- Replace hard-to-read pixel/block-letter titles with **KAORI** and **TLS Secret Management** in a clean two-line terminal layout.
- Retain the approved violet four-petal icon (iTerm2 inline PNG or ANSI pixel-art fallback), the subtle vertical separator, and the familiar runs/default-operation line.
- Preserve accessible `--plain`, `NO_COLOR`, redirected output, narrow-terminal behavior, and machine-readable command output.
- Simplify the reusable CLI header module and extend regression tests for readability, terminal width, image protocol gating and text fallback.

### Scope

- Human-facing terminal UI only; no modifications to TLS certificate management, encryption, Kubernetes writes, or approvals. Real-cluster UAT is a separate operational acceptance step.

## [0.2.2] - 2026-10-16

**8-bit square-tile terminal header typography patch. No changes to Kubernetes or certificate operations.**

### Changed

- Render **KAORI** in large 5x5 bitmap terminal glyphs and **TLS MANAGEMENT** in compact 3x5 square-pixel glyphs beside the approved violet CLI icon.
- Support ANSI and iTerm2 terminal layouts with consistent letter alignment. The inline PNG remains the approved icon, while the retro letters are generated as real terminal glyphs, not an image-only mockup.
- Prevent unwanted line wraps on 80-column terminals; show readable compact typography when the viewport is narrow.
- Preserve plain-text, redirected-output, NO_COLOR and machine-readable command behavior; add synthetic layout and pixel-font tests.

### Compatibility

- Operator-UI-only source patch. No new runtime dependencies or Kubernetes access. Real-cluster acceptance remains separate from synthetic CI.

## [0.2.1] - 2026-10-16

**Terminal-only KAORI header branding patch; no Kubernetes operation semantics changed.**

### Changed

- Replaced the old terminal orbital-K ASCII header with the approved violet four-petal icon supplied for KAORI CLI tools.
- Added the terminal-only PNG asset and reusable standard-library-only terminal renderer. Compatible iTerm2 terminals receive the actual inline PNG; other color TTYs display ANSI half-block pixel artwork sampled from the same icon.
- Added compact ASCII fallbacks for non-TTY, plain/no-color, dumb and narrow terminals, without affecting machine-readable subcommands.
- Added regression coverage and documented the common KAORI terminal-header standard. Existing README and non-CLI branding unchanged.

### Operational scope

- Source-only presentation update. Synthetic checks do not certify Kubernetes UAT or production readiness.

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

[0.2.9]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.9
[0.2.8]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.8
[0.2.7]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.7
[0.2.6]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.6
[0.2.5]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.5
[0.2.4]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.4
[0.2.3]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.3
[0.2.2]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.2
[0.2.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.1
[0.2.0]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.2.0
[0.1.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.1
[0.1.0]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0
[0.1.0-rc.1]: https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0-rc.1
