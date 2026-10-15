# CLI command reference

KAORI has one supported launcher, **bash scripts/tls-secret-manager.sh**, and two complementary interfaces: an interactive wizard and script-oriented command parsers.

## How command routing works

| Invocation | Destination |
| --- | --- |
| `bash scripts/tls-secret-manager.sh` | Wizard (default) |
| `bash scripts/tls-secret-manager.sh wizard [options]` | Wizard |
| `bash scripts/tls-secret-manager.sh doctor` | Local dependency report, no Kubernetes requests |
| `bash scripts/tls-secret-manager.sh crud [options] subcommand` | Guarded Create/Read/Update/Delete backend |
| `bash scripts/tls-secret-manager.sh [options] subcommand` | Advanced renewal engine |

The equivalent compatibility launcher **scripts/kaori-tls-secret-manager.sh** forwards into the same application. The Python implementation uses the standard library.

## Wizard

~~~bash
bash scripts/tls-secret-manager.sh wizard --plain
bash scripts/tls-secret-manager.sh wizard --context APPROVED_CONTEXT \
  --workspace "$HOME/k8s-tls-private"
~~~

Wizard options: **--context**, **--workspace**, **--cert**, **--key**, **--ca-bundle**, **--reviewed-holds**, **--review-plan**, **--plain**. With no argument, the wizard uses interactive prompts. At the first menu, **Enter defaults to Inventory**; use **9 Help** and **0 Exit** to explore without initiating discovery.

| Menu | Function | Notes |
| --- | --- | --- |
| 1 | Inventory | TLS Secret discovery |
| 2 | Expiry audit | Certificate validity |
| 3 | TLS Toolbox | Diagnostics; includes TLS Doctor and metrics export |
| 4 | Reverify HTTPS | Requires a previously saved renewal plan |
| 5 | Renew TLS | Existing selective multi-target renewal flow |
| 6 | Review HOLD | Read-only hold review from a prior plan |
| 7 | Run history | Prior plans/journals |
| 8 | Status guide | Explains READY/HOLD and other statuses |
| 9 | Help | Menu guidance |
| 10 | Create TLS Secret | Guided guarded Create |
| 11 | Delete TLS Secret | Guided guarded Delete |
| 0 | Exit | No operation |

## Guarded CRUD backend

Supply **--context** before subcommand names. **--plain** is a top-level global argument.

~~~bash
# Read: JSON metadata only (authorized context)
bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  inventory --namespace sandbox

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  inspect --namespace sandbox --secret demo-tls

# Plan only: create/rotate from existing local PEM/key pair
bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-create --namespace sandbox --secret demo-tls \
  --cert "$HOME/secure/fullchain.pem" --key "$HOME/secure/private.key" \
  --workspace "$HOME/k8s-tls-private"

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-update --namespace sandbox --secret demo-tls \
  --cert "$HOME/secure/fullchain.pem" --key "$HOME/secure/private.key" \
  --workspace "$HOME/k8s-tls-private"

# Read-only dependency check; may return HOLD rather than an executable plan
bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-delete --namespace sandbox --secret demo-tls \
  --workspace "$HOME/k8s-tls-private"
~~~

| Subcommand | Required primary arguments | Description |
| --- | --- | --- |
| **inventory** | --namespace | All TLS Secret metadata in one namespace |
| **inspect** | --namespace, --secret | One TLS Secret UID/resourceVersion/fingerprint |
| **plan-create** | --namespace, --secret, --cert, --key, --workspace | Immutable preflight; target must not already exist |
| **plan-update** | same | Existing target; same-SAN identity check |
| **plan-delete** | --namespace, --secret, --workspace | Dependency scan, HOLD or immutable delete plan |
| **create** | --namespace, --secret, --cert, --key, --plan, --approve, --confirm-target plus authorization | One guarded atomic create |
| **update** | same plus --backup-recipient | One guarded replace with encrypted backup |
| **delete** | --namespace, --secret, --plan, --approve, --confirm-target, --backup-recipient plus authorization | One guarded conditional deletion |

**Execution authorization:** after reviewing the exact immutable plan, use either the **single-operator interactive wizard** (menu 10 or 11) or the documented **independently signed non-interactive approval**. The CLI exposes **--operator-mode**, **--operator-ack**, **--operator-attested** (Delete) for TTY integration, and **--approval-record**, **--approval-signature**, **--approval-trust-key** for signed enterprise approvals. These are **not** interchangeable convenience flags; never use them to bypass review. Update/Delete support **--backup-identity** to validate encrypted recovery locally. For complete mutation examples and approval contract see [Operator guide](OPERATOR-GUIDE.md).

For Delete: observed **Ingress, Pod or Gateway API consumers**, known controller management, finalizers or incomplete scan visibility cause HOLD. A HOLD is not an executable deletion plan; no force override is available. An operator must separately attest to possible consumers outside Kubernetes.

## Advanced renewal engine

Invoke these as **bash scripts/tls-secret-manager.sh [--context CONTEXT] SUBCOMMAND [flags]**, not under **crud**.

| Command | Primary arguments | Purpose |
| --- | --- | --- |
| **discover** | --namespaces, optional --runs-dir, --warn-days | Enumerate certificate targets |
| **reconcile** | --namespaces, --targets, optional --runs-dir | Compare desired targets to discovered state |
| **inspect** | --namespace, --secret | One Secret's current certificate |
| **verify-source** | --cert, --key, optional --ca-bundle | Local PEM/key validation; does not need context |
| **plan** | --namespaces, --targets, --cert, --key | Build a reviewed renewal plan; optional fingerprint baseline/HOLD exceptions |
| **renew** | --namespaces, --cert, --key, --plan, --approve, --backup-recipient | Authorized write; optional staged/endpoint mapping |
| **verify** | --plan | Examine state after a renewal |
| **verify-endpoints** | --plan, --endpoints | Explicit hostname/port/SNI and endpoint certificate checks |
| **rollback** | --plan, --approve, --backup-identity | Guarded recovery, not automatic |
| **rollback-target** | --plan, --namespace, --secret, --backup-identity | Scoped recovery; **--dry-run** available |
| **report** | --plan | Generate renewal report without a context |

Command-specific flags can be inspected with **--help**. Renewal uses approved target CSV files; see [examples](../scripts/kubernetes/tls-secret-manager/examples/) for **synthetic** CSV format. Keep run directories outside Git. Avoid copying optional flags blindly between subcommands.

## TLS Toolbox: standalone read-only commands

~~~bash
# No mutation: inspect the stored certificate
python3 scripts/kubernetes/tls-secret-manager/tls_ops.py \
  --context APPROVED_CONTEXT \
  --output-dir "$HOME/k8s-tls-private/toolkit-reports" \
  doctor --namespace sandbox --secret demo-tls

# Export local Prometheus textfile metrics (does not configure scraping)
python3 scripts/kubernetes/tls-secret-manager/tls_ops.py \
  --context APPROVED_CONTEXT --namespaces sandbox \
  --output-dir "$HOME/k8s-tls-private/toolkit-reports" \
  metrics --cluster-label sandbox --warn-days 30
~~~

Pass a concrete approved **--hostname** (and optionally **--ca-bundle**) to TLS Doctor to compare the served HTTPS certificate with the Secret. Without a hostname, it only checks the stored Secret. See [Toolbox metrics and doctor guide](TOOLBOX-METRICS-DOCTOR.md).

## Exit status and evidence

- Successful JSON output may indicate **HOLD**; check the explicit returned **status** and **blockers**, not only process exit code.
- A timeout or write error can yield an **uncertain mutation**: preserve the journal and reconcile manually. **Do not retry blindly.**
- Artifact paths are local private evidence, not outputs to attach to public issues. Source PEM/private keys and recovery identities remain outside the repository.
- A newly written Secret's certificate fingerprint does **not** prove an HTTPS frontend currently serves the same fingerprint.

See [FAQ](FAQ.md), [Delete SOP](DELETE-TLS-SECRET-SOP.md) and [security policy](../SECURITY.md).
