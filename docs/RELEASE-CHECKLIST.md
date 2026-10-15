# Release readiness checklist

This is a **release acceptance gate**, not a backlog on the project homepage. The repository ships **v0.1.0** as an initial public SemVer source release; no production-accepted stable deployment or binary is approved. Fill these checks with evidence before advertising a stable release.

## Repository and community

- [ ] Complete application source, offline tests, real command documentation and generic examples are present on the release branch.
- [ ] README commands are independently tested from a fresh clone on supported Linux/WSL environments.
- [ ] Changelog, Apache-2.0 LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, SUPPORT, governance and bug/feature/PR templates are reviewed and linked.
- [ ] The PNG identity assets render correctly on GitHub; terminal branding is legible with **--plain** and **NO_COLOR** if integrated.
- [ ] Repository topic tags, Discussions policy (if enabled), issue labels, private vulnerability reporting and branch protections/rulesets are configured by authorized administrators.

## Source security and CI

- [ ] Source, fixtures, Git history, examples, test logs and CI artifacts have independent privacy and secret review.
- [ ] Offline suite, syntax checks, safe negative cases and static/security analysis pass on the **actual release commit**.
- [ ] CI does not authenticate against live clusters or perform Kubernetes writes.
- [ ] Dependency and toolchain compatibility are recorded: Python, Bash, OpenSSL, age, kubectl and supported Kubernetes versions.
- [ ] Release integrity/signing approach, reproducible source/tag and published checksums are independently verified.

## Functional acceptance (approved isolated DEV/UAT only)

- [ ] Create/Read/Update/Delete happy paths and negative cases are tested on real Kubernetes with scope-limited RBAC.
- [ ] Failed scans, incomplete Gateway/Pod/Ingress visibility, existing targets, controller ownership and stale resource identity cause HOLD/STOP as designed.
- [ ] Wrong/expired/untrusted PEM, key mismatch, changed SAN, missing backups and incomplete approvals are blocked.
- [ ] Concurrent updates/deletes, server-side UID/resourceVersion precondition conflicts, timeouts and ambiguous API outcomes have journal/reconciliation evidence.
- [ ] age-encrypted recovery material is verified and an authorized **actual restore** exercise succeeds.
- [ ] TLS Doctor/endpoint mapping, staged load balancer behavior and application-owner acceptance prove served HTTPS where required.
- [ ] Single-operator wizard confirmations are usable without enterprise signature artifacts; optional independently signed API workflow retains policy enforcement.

## Release and support

- [ ] Maintainers approve scope, release notes, VERSION change, tag, integrity artifacts and download/upgrade guidance.
- [ ] Public stable installation instructions no longer require switching to a temporary development branch.
- [ ] Operational runbooks reference a version-pinned release with checksum, while maintaining their own approval workflows.
- [ ] Maintainers update SECURITY supported versions, changelog release date, tested platforms and support expectations.

**Decision: PUBLIC v0.1.0 SOURCE RELEASE AVAILABLE; PRODUCTION ACCEPTANCE NOT GRANTED.** A signed-off production release requires every outstanding security, restore, compatibility, provenance and environment acceptance item above. Offline PASS or downloadable source is not Kubernetes DEV/UAT PASS.
