# Historical migration record

KAORI TLS Management source and synthetic offline regression tests were transferred from the private operations repository into the independent public repository **without migrating private Git history**. The unified utility now lives on [`main`](https://github.com/OXY7O/kaori-tls-secret-manager/tree/main).

## Completed source publication

- Original renewal engine, terminal wizard, inventory, TLS Toolbox/Doctor, examples and regression tests transferred to `scripts/kubernetes/tls-secret-manager/` and `tests/`.
- Guarded Create, metadata-only Read, single-target same-SAN Update and dependency-aware Delete implemented in `scripts/tls_crud.py`.
- One supported launcher: `scripts/tls-secret-manager.sh`. The two-checkout bridge was removed.
- Public GitHub Actions runs offline tests **without Kubernetes credentials**.
- Approved PNG identity, complete operator docs, contribution files and public-source [prerelease `v0.1.0-rc.1`](https://github.com/OXY7O/kaori-tls-secret-manager/releases/tag/v0.1.0-rc.1) published after passing the offline gate.
- Original work delivered by merged [PR #4](https://github.com/OXY7O/kaori-tls-secret-manager/pull/4) and [PR #6](https://github.com/OXY7O/kaori-tls-secret-manager/pull/6). Previous implementation issues #1, #2, #3 and #5 are closed with implementation/acceptance boundaries documented.

## Production handoff is a separate acceptance decision

**The community prerelease is not production-authorized.** The following have not been independently signed off: public-source security/privacy review, real Kubernetes DEV/UAT exercises, live RBAC and API race conditions, TLS endpoint trust and external dependency validation, encrypted backup restoration, and owner/operations acceptance.

The current project status and unfulfilled production gates are maintained in [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md), not as a migration TODO in the homepage README.

The previous private ops-runbook handoff pointer is historical. Version pinning and operational cutover in private runbooks must be handled under their own approved change processes and must not imply this community prerelease is production-ready.
