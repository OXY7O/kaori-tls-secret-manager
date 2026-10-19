# Product scope and authorization terminology

## Canonical terminology

- **Product name:** KAORI TLS Secret Manager.
- **Tagline:** Safer Kubernetes TLS Secret management.
- **Managed object:** a Kubernetes API Secret with `type: kubernetes.io/tls` (typically `data["tls.crt"]` and `data["tls.key"]`).
- **TLS Secret renewal:** operator supplies a certificate/fullchain and matching private key **issued by an external CA/provider**; KAORI plans and updates the TLS Secret(s). It does not issue or renew CA certificates itself.
- **TLS Doctor / HTTPS diagnostics:** read-only comparison of certificate/key material stored in a TLS Secret with what a selected HTTPS endpoint serves. This is observation only, not configuration of an external load balancer.
- **Out of scope:** certificate issuance, ACME challenges, CA lifecycle, replacement of cert-manager, arbitrary Kubernetes Secret types, generic certificate management outside TLS Secrets, unattended reconciliation, and cluster-wide force-deletion.

Descriptions like **TLS Certificate Manager**, **Kubernetes TLS certificate management**, or the shortened product title **KAORI TLS Management** should not be used in active user-facing product copy. Keep legacy subcommand names and historical published release notes unchanged for compatibility/provenance.

## Read versus write and exact authorization

| Operator flow | Kubernetes write? | What authorization/confirmation actually applies? |
| --- | --- | --- |
| Help, dependency doctor, saved-run inspection | No | Local-only; no Kubernetes write approval |
| Inventory, Expiry Audit, TLS Toolbox / TLS Doctor | No TLS Secret write | Selected context and suitable Kubernetes **read RBAC** |
| `crud plan-create`, `plan-update`, `plan-delete`, renewal `plan` | No TLS Secret write | Read RBAC and private plan evidence; no mutation approval |
| Guided **Create/Update/Delete TLS Secret** | Yes | One authorized operator reviews plan, confirms **PROCEED** and the exact target; Delete also attests **UNUSED** external consumers and verifies an age backup before deleting. No independent signature file for guided single-operator CRUD |
| Guided renewal of **one READY TLS Secret** | Yes | Operator types **AUTHORIZED** and the exact Plan ID; backed up and verified before/after the conditional update |
| Guided renewal of **multiple Secret-bound READY TLS Secrets** | Yes | One TTY operator confirms listed targets with `RENEW N TLS SECRETS`, then `AUTHORIZED` and exact Plan ID; no separate signature files |
| Guided renewal with **external TLS termination** | Yes | Operator confirmation **and** independent signed approver, even for one target |
| Non-interactive **multi-target renewal** | Yes | Independently signed approval; no single-operator unattended shortcut |
| Advanced non-interactive CRUD and enterprise integrations | Yes | Documented independently signed approval record/signature/trust key; see [Operator guide](OPERATOR-GUIDE.md) |
| Guided restore after a verified Delete | Yes | Read-only reconciliation, pinned original context/namespace, verified complete journal and age backup, explicit exact **RESTORE** target; never overwrite or auto-retry |

**Authorization** always means permission to operate in the specified cluster, namespace and change scope. Typed confirmation is a safeguard and does **not** grant Kubernetes RBAC or waive the organization's change-control requirements. Where applicable, independently signed approval is an additional safeguard, not a replacement for those permissions. Single-operator multi-target renewal is restricted to TTY sessions and Secret-bound endpoints, with exact target review, age backup and per-target verification.

## Environment policy and claims

**DEV/UAT is where the operator should validate this source release and rehearse recovery.** The executable is not intrinsically restricted to nonproduction Kubernetes contexts. Any production use requires separate environment-specific UAT, backup/restore verification, authorized RBAC, confirmed consumers and owner acceptance. A successful GitHub Actions Quality Gate does not certify a real Kubernetes deployment.

Use **HOLD** to communicate incomplete dependency visibility, unsupported ownership or another safety block. **STOP / MUTATION_UNCERTAIN** after a write does not mean success or proof of failure. Never retry blindly or infer an unused Secret merely from an empty reference scan.

For exact steps, see [Operator guide](OPERATOR-GUIDE.md), [Delete SOP](DELETE-TLS-SECRET-SOP.md) and [Security Policy](../SECURITY.md).
