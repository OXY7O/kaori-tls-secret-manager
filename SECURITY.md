# Security policy — KAORI TLS Secret Manager

**Pre-release prototype: no production security assurance.** This project is a Kubernetes
Secret management utility; compromise or misuse may expose private keys or disrupt TLS.

## Responsible operations

- Manage only authorized Kubernetes contexts and approved namespaces.
- Keep `kubeconfig`, approver signing keys, PEM private keys, evidence, encrypted backups and
  plan/journal files outside the source checkout and out of public Git.
- Require an independent, root-anchored approver key for mutations. The PLAN ID is an integrity
  identifier, **not** a digital signature. Avoid granting approval solely to the requester.
- Use least-privilege RBAC: scoped get/list for inventory and preflight; create/update/delete
  privileges only for approved operator identities in a controlled environment.
- Any API timeout, UID/resourceVersion drift, failed backup, unknown dependency, or uncertain
  journal status is **STOP**; reconcile manually before a new approved plan. Never blind retry.
- Read-only discovery may access TLS Secret payloads in memory to evaluate fingerprints.
  The CLI never intentionally renders or writes `tls.key` into reports.
- Server-side UID/RV delete preconditions and update resourceVersion conflicts are mandatory,
  not substitutes for change authorization, backup/restore or endpoint health checks.
- Ingress, Pod and Gateway API scans cannot prove absence of consumers outside their scope.
  A signed owner attestation is mandatory but must not be treated as proof of safe deletion.

## Known limitations before public release

- No real Kubernetes DEV/UAT acceptance evidence exists for this local prototype.
- The legacy multi-target renewal, wave execution, selective rollback and interactive wizard
  are **not yet migrated** into the public codebase.
- Only **single-target same-SAN** Update is implemented in this local starter.
- No automated rollback, bulk deletion, certificate issuance or unattended writes.
- No stable security support window, published release artifact or tested multi-platform installer.
- Server/kubectl version compatibility and encrypted backup restore are not yet validated.

Report potential vulnerabilities privately to maintainers; do **not** file tickets containing
real private keys, kubeconfig data, TLS Secret payloads, public endpoints needing disclosure,
or evidence from internal clusters.
