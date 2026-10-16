# Publishing Semantic Versioned Source Releases

KAORI TLS Management follows [Semantic Versioning](https://semver.org/) using `vMAJOR.MINOR.PATCH` Git tags. The first public source release is `v0.1.0`. The `0.y.z` series allows the project to evolve its CLI, JSON formats and operator workflows between releases.

## Choosing the version

- **PATCH:** compatible fixes and documentation corrections for a published interface.
- **MINOR:** new capabilities or intentional interface evolution while major version is `0`; document behavior changes.
- **MAJOR:** project-stable major version only after a separately approved production acceptance and compatibility policy.
- **Prereleases:** `-rc.N` denote release candidates. They do not automatically become a published source release.

## Publishing workflow

1. Create a dedicated `release/vX.Y.Z` branch from `main`.
2. Change `VERSION`, update `CHANGELOG.md`, add `docs/releases/vX.Y.Z.md`, and update README/security/release policy to match actual verification.
3. Run the offline GitHub Actions suite and review source provenance plus documentation. No automated production Kubernetes access is allowed.
4. Merge the PR into `main` after offline gates succeed.
5. GitHub Actions runs the **Quality Gate** on the merged `main` commit. After PASS, a lightweight **Release Preflight** reads the local version/release metadata and queries GitHub for the matching release/tag using a **read-only** token.
6. If that version has already been published with both required assets, preflight emits `publish=false` and **Publish Release is skipped entirely** (no write-permission runner, full checkout, archive or checksum generation). If the existing release is incomplete, a tag exists without a release, or an API call fails, preflight **fails closed** rather than overwriting history.
7. For a genuinely new version, preflight emits `publish=true`. The separate **Publish Release** job then checks eligibility **again after acquiring the release concurrency lock**, validates the exact version, archives the merged commit, verifies archive readability and publishes the immutable tag, archive and `SHA256SUMS`.
8. Verify the new GitHub Release is public, `prerelease=false`, tag target matches the merged commit and both assets exist. An existing release is **never overwritten**.

Use a **new version** for subsequent releases; never recycle an existing tag or rewrite existing assets. Checksums are integrity evidence, not publisher signatures.

## Operational boundary

A versioned source release certifies the published commit and its automated Quality Gate only; it does not certify third-party Kubernetes environments. Administrators must follow the [release policy](RELEASE-POLICY.md), security guidance and their own authorization, recovery and endpoint verification procedures.
