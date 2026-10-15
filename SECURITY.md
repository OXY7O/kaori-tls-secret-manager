# Security policy — KAORI TLS Secret Manager

**Pre-release prototype: no production security assurance.** This project is a Kubernetes
Secret management utility; compromise or misuse may expose private keys or disrupt TLS.

## Responsible operations

- Manage only authorized Kubernetes contexts and approved namespaces.
- Keep `kubeconfig`, approver signing keys, PEM private keys, evidence, encrypted backups and
  plan/journal files outside the source checkout and out of public Git.
- **Interactive single-operator Create/Delete:** intentionally uses a local TTY, typed exact action/target, immutable Plan ID and—for Delete—explicit no-external-consumers attestation. No external signature is required for this intended local usage.
- **Optional non-interactive signed approval mode:** continues to require an independent, root-anchored approver key. Plan IDs are integrity identifiers, not digital signatures. Keep signed approvals separate from single-operator interactive mode.
- Use least-privilege RBAC: scoped get/list for inventory and preflight; create/update/delete
  privileges only for approved operator identities in a controlled environment.
- Any API timeout, UID/resourceVersion drift, failed backup, unknown dependency, or uncertain
  journal status is **STOP**; reconcile manually before a new approved plan. Never blind retry.
- Read-only discovery may access TLS Secret payloads in memory to evaluate fingerprints.
  The CLI never intentionally renders or writes `tls.key` into reports.
- Server-side UID/RV delete preconditions and update resourceVersion conflicts are mandatory,
  not substitutes for change authorization, backup/restore or endpoint health checks.
- Ingress, Pod and Gateway API scans cannot prove absence of consumers outside their scope.
  The single operator must explicitly attest that no external consumers remain; this human assertion is not a substitute for automated dependency checks. A separately signed owner attestation is part of the optional enterprise policy, not the interactive default.

## Known limitations before a stable production release

- No real Kubernetes DEV/UAT acceptance evidence exists for this development branch.
- The historical multi-target renewal, selective rollback and interactive wizard have been ported into the public development branch, but **not tested on real Kubernetes DEV/UAT** after migration.
- The standalone CRUD `update` action is an additional **single-target same-SAN** path; the original renewal wizard remains available and retains its own safeguards.
- No automated rollback, bulk deletion, certificate issuance or unattended writes.
- No stable security support window, published release artifact or tested multi-platform installer.
- Server/kubectl version compatibility and encrypted backup restore are not yet validated.

Report potential vulnerabilities privately to maintainers; do **not** file tickets containing
real private keys, kubeconfig data, TLS Secret payloads, public endpoints needing disclosure,
or evidence from internal clusters.
