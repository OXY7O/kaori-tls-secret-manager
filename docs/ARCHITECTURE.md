# Architecture Decision: Standalone TLS Secret Manager

Status: **Original wizard, renewal modules and CRUD extension ported; DEV/UAT and release pending**  
Scope: Kubernetes `kubernetes.io/tls` Secrets  
Distribution target: public repository, versioned CLI releases  
Operational documentation source: `OXY7O/ops-runbooks` (private)

## 1. Boundary and source of truth

- **This repository** owns the CLI implementation, unit/integration tests, generic examples, open-source documentation, release pipeline and release artifacts.
- **ops-runbooks** owns internal rollout/operations procedures, ticket links, RBAC/deployment templates, and environment-specific evidence references. It must consume a pinned/versioned release of this tool and must not keep a duplicate actively maintained source tree.
- Migration is not complete until the new public CLI is independently runnable, regression-tested, reviewed for secrets/internal identifiers, and has a versioned release. **Do not delete the old working copy prematurely**.
- Existing protected renewal behavior and existing evidence/journal schemas should remain compatible, unless explicitly versioned with tests.

## 2. CRUD semantics

| Operation | CLI concept | Preconditions | Data mutation |
| --- | --- | --- | --- |
| Create | `create` | Scope + checked certificate/key + verify target absent + approval + final precondition | Only creates one `kubernetes.io/tls` Secret; never overwrites |
| Read | `inventory`, `inspect`, `health` | Explicit context and bounded namespaces; safe and private output | No Kubernetes Secret mutation; private local reports only |
| Update | `renew` / `update` | Fresh bound plan; SAN/issuer/ownership checks; backup; approval; optimistic concurrency | Update only approved READY Secret targets and verify |
| Delete | `delete` / `decommission` | Fresh dependency/ownership audit; encrypted backup; explicit deletion approval; live UID/resourceVersion preconditions | Deletes one approved, non-controller-managed Secret and verifies it is absent |

`create` manages Secret material; it **does not issue certificates**. Reading Secret contents is restricted: never echo `tls.key` or raw Secret payload into terminal, JSON output or CI logs.

## 3. Safety model

### Shared controls

1. Explicit Kubernetes context, namespace and target identity for mutations; refuse ambiguous or empty selection.
2. Kube API read failures, RBAC gaps, issuer/ownership mismatch, conflicting controller ownership, cluster identity drift and uncertain dependency state **STOP** before writes.
3. Dry-run/preflight must not mutate cluster state. Plans and expected fingerprints/UID/resourceVersions bind the exact approved targets. Revalidate immediately before any mutation.
4. Preserve original identity and write-ahead journal. Encrypted recovery snapshot and per-target evidence are kept privately under restrictive permissions.
5. No blind retry, implicit force, unattended mass operation, automatic rollback, or auto-deletion after a failed write. Reconciliation and operator approval are separate.
6. Human acceptance includes application/endpoint health; saved TLS Secret certificate and configured hostname alone do not imply verified served HTTPS.
7. No shell interpolation of untrusted names; use structured subprocess arguments; never log PEM private keys, backup material, or bearer tokens.
8. Treat `NO_COLOR`, `--plain` and non-TTY machine-readable output as supported accessibility/scripting modes. Do not require emoji.

### Create-specific

- Verify supported Secret type `kubernetes.io/tls`, PEM fullchain, matching unencrypted or safely provided key, valid cert dates, required SANs, CA chain/trust policy and explicit name/namespace.
- Fail on pre-existing Secret; use an atomic server-side create where `AlreadyExists` means STOP. Never silently upgrade create to update.
- Record the resulting UID/resourceVersion and certificate fingerprint, then verify stored Secret; HTTPS is a separate step.

### Delete-specific

- Reject missing or partial reference visibility. Inspect Ingress TLS, Gateway API certificateRefs (where available), Pod references, ownerReferences, cert-manager/controller associations, and declared external consumers. Discovery cannot prove absence of every external client: require owner attestation.
- Reject any controller-managed Secret, ambiguous consumer, namespace or cluster drift. Default to **blocked** for live references. No cascade deletions.
- Require explicit single-operator typed target/action, immutable Plan ID, external-consumer attestation, encrypted backup with recovery roundtrip, and short-lived deletion plan bound to cluster UID, Secret UID, resourceVersion and fingerprint.
- Use Kubernetes deletion **preconditions** on UID/resourceVersion (atomic API-side verification). Re-read or reconcile if preconditions fail; never delete by name alone on retry.
- Verify target absence and that application dependencies/other Secrets were unaffected. Store immutable disposition as complete, stopped, or uncertain; no unverified success.
- Initial release: one target per deletion. Bulk deletion, force, garbage collection or Secret ownership bypass are out of scope.

## 4. Public development repository layout

```text
scripts/
  tls-secret-manager.sh            # Default launcher, original KAORI UI
  tls_crud.py                     # Guarded CRUD backend
  kubernetes/tls-secret-manager/
    tls_secret_manager.py         # Original renewal engine
    tls_secret_wizard.py          # Original wizard + Create/Delete
    tls_inventory.py
    tls_ops.py
    examples/                     # Synthetic sample CSV files
tests/                            # Original + CRUD + integrated launcher tests
docs/                             # Architecture, security, operator/laptop guides
.github/workflows/ci.yml          # Offline regression
```

The existing launcher and Python stdlib implementation form the compatibility baseline. Public code must not hardcode organization-specific names, kube contexts, production endpoints, CA paths, private network addresses or credentials.

## 5. Migration and acceptance gates

- **Gate A — Public content review (file migration and synthetic fixture replacement complete; independent security review pending):** enumerate source/tests/example fixtures and scrub company identifiers, internal domains, cluster names, file paths, secret payloads and personal/production evidence. Git history from the private repository is **not copied** into the public repository.
- **Gate B — Functional preservation (ported and offline regression PASS; DEV/UAT pending):** migrate audited implementation and all applicable synthetic regression tests. Preserve existing renewal, journal, backup, verification, selective rollback, and text/ANSI CLI behavior.
- **Gate C — CRUD extension (wizard Create/Delete implemented; offline coverage present, DEV/UAT pending):** implement create and guarded delete with negative paths: already exists; wrong key; issuer/SAN mismatch; controller-owned target; active reference; RBAC incomplete; approval missing; stale UID/RV; failed backup; API timeout; uncertain deletion result.
- **Gate D — CI and packaging (offline CI PASS; release/checksum and security scans pending):** Python compilation, offline tests, contract/security checks, documentation link tests, reproducible versioned release, checksum/integrity verification and usage docs; no real-cluster writes in CI.
- **Gate E — DEV/UAT:** real-cluster permission-scoped tests, negative cases, audit evidence, operator sign-off. No claimed PASS before evidence.
- **Gate F — Cutover (partial):** private ops-runbooks main now links to this public source; the historical Issue #67 and PR #68 are closed-unmerged as transferred. Pin a tested version/checksum in the runbook **only after** UAT and release acceptance.

## 6. Changes not authorized by this decision

- Publishing unsanitized private-repository contents or Git history.
- Deploying to any production Kubernetes cluster.
- Running write actions, changing RBAC, changing security gates, or merging public/private PRs before validated acceptance.
- Claiming CRUD is available before create/delete implementations and tests pass.

