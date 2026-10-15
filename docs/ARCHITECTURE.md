# Architecture

KAORI TLS Management is a terminal-first utility for inspecting and managing Kubernetes Secrets of type **kubernetes.io/tls**. It combines a guided interface, an explicit lifecycle backend, certificate diagnostics and audit/recovery evidence.

## Components

| Component | Source | Responsibility |
| --- | --- | --- |
| Launchers | scripts/tls-secret-manager.sh, scripts/kaori-tls-secret-manager.sh | Select guided, diagnostic, CRUD or renewal operation |
| Guided interface | scripts/kubernetes/tls-secret-manager/tls_secret_wizard.py | Operator prompts, target selection, confirmation and status |
| Guarded lifecycle | scripts/tls_crud.py | Inventory, inspect, immutable Create/Update/Delete plans, single-target writes and safety enforcement |
| Renewal engine | scripts/kubernetes/tls-secret-manager/tls_secret_manager.py | Discovery, selective renewal, endpoint verification, scoped recovery and reporting |
| Inventory and diagnostics | tls_inventory.py, tls_ops.py | Expiry audit, stored certificate/HTTPS comparison and metrics textfile export |
| Regression suite | tests/ | Synthetic, cluster-isolated validation for parsing, safety and CLI behavior |

There is no background controller, custom Kubernetes operator or automatic ACME issuance. The utility runs from an authorized operator's workstation and uses the selected kubeconfig context.

## Lifecycle and trust boundaries

1. **Scope:** select explicit Kubernetes context, namespace and target. Read-only queries report certificate metadata without printing TLS private keys.
2. **Plan:** validate source PEM/key and Secret state, determine ownership/dependencies and record identity, UID/resourceVersion and fingerprint. An incomplete dependency scan yields **HOLD**.
3. **Authorize:** the normal guided path uses typed target/action confirmations by one authorized operator. An independent signed-approval path is available for automated workflows.
4. **Protect:** changes to existing material require age-encrypted recovery artifacts and journals stored outside the repository with restrictive access.
5. **Execute:** validate the current Kubernetes object against the plan and use API write preconditions. Conflicts or uncertainty result in STOP, not an automatic retry.
6. **Verify:** inspect resulting state and, where relevant, the separately served HTTPS certificate. A valid stored Secret does not prove that a proxy or load balancer serves it.

## CRUD contracts

| Operation | Preconditions | Result |
| --- | --- | --- |
| Create | Valid PEM/private-key pair, exact target, target absent, approved plan | Create only; existing Secrets are never overwritten |
| Read | Explicit cluster and namespace | Safe TLS metadata and certificate identity inspection |
| Update | Existing Secret, matching SAN set, fresh plan, encrypted backup, approval | One authorized replacement with concurrency checks |
| Delete | No known active consumers, complete reference scan, ownership check, external-consumer attestation, backup and approval | Conditional single-target delete with post-write absence verification |

Dependency discovery includes Ingress TLS references, Pod Secret references and Gateway API certificate references where available, along with owner/controller information. It cannot prove that out-of-cluster applications, load balancers or proxies do not rely on a Secret; those relationships require separate operator verification.

## Data protection

- Kubeconfig, private PEM material, evidence workspaces, age identities and backups must remain outside Git and public issue attachments.
- Source certificate fingerprint and live endpoint fingerprint are independent measurements; use correct hostname, SNI and trusted CA bundle.
- Rollback and reconciliation are explicit. A timeout or ambiguous Kubernetes response must not be treated as a successful write or retried blindly.
- Plain-text mode and non-interactive machine-readable output avoid decorative ANSI/image sequences.

## Source distribution

GitHub Actions **Quality Gate** compiles CLI modules and runs synthetic regression checks without cluster access. **Publish Release** builds a source archive and SHA256SUMS from the approved main commit. See the [release policy](RELEASE-POLICY.md) for the exact assurance boundary, and [command reference](COMMAND-REFERENCE.md) for the supported operations.
