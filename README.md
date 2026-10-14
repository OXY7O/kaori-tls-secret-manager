# KAORI TLS Secret Manager

A standalone, operator-controlled Kubernetes TLS Secret management toolkit.

> **Project status: migration and CRUD design in progress. Not production-ready.** The source currently being developed in a private operational repository has **not** yet been released here. Do not use this repository as a deployment tool until its implementation, security review, and automated tests are available.

## Scope

Manage Kubernetes Secrets of type `kubernetes.io/tls` through explicitly scoped operations:

| Operation | Planned behavior |
| --- | --- |
| Create | Validate a supplied PEM certificate/full chain and matching private key; create a new Secret only when the name is absent, the scope is authorized, and the operation is approved. |
| Read | Inventory, inspect metadata/certificate expiration, report configured Ingress references, and export private evidence without revealing private key bytes. |
| Update | Rotate/replace a Secret's TLS material using a fresh plan, identity/SAN checks, encrypted backup, optimistic concurrency, explicit authorization, and post-write verification. |
| Delete | Decommission a single named Secret after dependency/owner checks, encrypted backup, explicit change approval, live identity confirmation, and post-delete verification. |

**Create is not certificate issuance.** The operator supplies existing certificate/key files; automatic ACME or CA issuance is outside the initial CRUD scope.

## Safety requirements

- An explicit kubeconfig context, namespace and Secret name are required for mutations. Default discovery is read-only; **no automatic writes, deletion, rollback or retries**.
- Create must be non-overwriting. Update and delete must verify Secret UID/resourceVersion, certificate fingerprint where applicable, and live scope before writes.
- Controller-managed Secrets, missing visibility/RBAC, ambiguous consumers, or unsafe drift stop the operation. Delete must never assume that absence of an Ingress reference proves a Secret unused.
- Sensitive keys, kubeconfigs, cluster scans, approval artifacts and encrypted backups must remain outside Git and be excluded from published logs.
- Plans, signed approvals for high-risk operations, execution journals, encrypted backups, and explicit human acceptance are mandatory where applicable.
- Human-readable terminal menus and machine-readable CLI outputs must be deterministic, accessible, and safe in `--plain` / `NO_COLOR` mode.

## Intended structure

```text
kaori-tls-secret-manager/
  README.md
  docs/                 # Architecture, security, operator documentation
  scripts/              # Python CLI and launchers (after sanitization)
  tests/                # Offline safety regression tests (synthetic fixtures only)
  examples/             # Dummy-only generic data
  .github/workflows/    # Isolated lint/test/security CI
```

## Development and provenance

This repository supersedes the TLS helper's *source-code ownership* in the private `OXY7O/ops-runbooks` repository. The original repo remains the owner of internal operational procedures and environment-specific documentation; it will eventually refer to versioned releases of this standalone tool instead of storing a second source-code copy.

The initial private work is tracked in `OXY7O/ops-runbooks` issue #67 and Draft PR #68. Nothing from the private repo should be copied into this **public** repository before inspection and removal of environment-specific domains, namespaces, credentials and evidence.

See `docs/ARCHITECTURE.md` on the development branch for migration gates and the CRUD security contract.
