# KAORI TLS Secret Manager

**Status: development / operator trial only. No production authorization.**

A standalone, terminal-first Kubernetes `kubernetes.io/tls` Secret manager. The **original KAORI operator wizard and renewal engine** were migrated from the archived `ops-runbooks` work. Create and Delete now run from that **same wizard** using the signed, plan-bound CRUD engine.

## One application, one repository

The operator menu retains the original KAORI ASCII banner, navigation and entries **1-9** (Inventory, Expiry Audit, TLS Toolbox, Verify HTTPS, Renew TLS, Review HOLD, Run history, Status guide, Help). It adds **10 Create TLS Secret** and **11 Delete TLS Secret**. Option **0** exits. Press Enter only when you intend to launch read-only Inventory.

The implementation is in `scripts/kubernetes/tls-secret-manager/`, preserving its original internal module paths and historical regression tests. The supported top-level launcher is `scripts/tls-secret-manager.sh`. No second Git checkout, runtime source download or `KAORI_LEGACY_DIR` is required.

## Quick start (Ubuntu / WSL)

```bash
sudo apt update
sudo apt install -y git python3 openssl age ca-certificates
# Install kubectl separately for real cluster inventory (see kubernetes.io/docs/tasks/tools).

git clone https://github.com/OXY7O/kaori-tls-secret-manager.git
cd kaori-tls-secret-manager
git fetch origin
git switch --track origin/feat/crud-and-repo-migration

python3 -m unittest discover -s tests -v
bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh wizard --plain
```

**At the first menu**, use `9` for Help and `0` to exit. Avoid the default Enter shortcut until a DEV/UAT cluster context is ready.

For lower-level CLI usage:

```bash
bash scripts/tls-secret-manager.sh crud --help
bash scripts/tls-secret-manager.sh --help
```

The latter is the **original advanced renewal engine**. The former exposes explicit lifecycle commands, including `plan-create`, `create`, `inventory`, `inspect`, `plan-update`, `update`, `plan-delete` and `delete`.

## Security and capabilities

| Operation | Implementation |
| --- | --- |
| Read | Original Inventory, expiry, certificate families, diagnostics, Ingress/HTTPS checks, reports |
| Update / Renew | Original selective READY/HOLD/SKIPPED batch renewal, identity reviews, encrypted backups, journaling, HTTPS verification, guarded rollback |
| Create | New wizard menu 10; explicit namespace/name, source PEM/key checks, immutable plan, independent signed approval, atomic non-overwrite create and readback |
| Delete | New wizard menu 11; single-target dependency review, immutable plan, independent signed approval, age-encrypted backup, Kubernetes UID/resourceVersion deletion preconditions and verification |

The existing advanced renewal remains the default **Update** workflow. The standalone `crud update` is an additional single-target, same-SAN alternative, not a replacement for the original renewal engine.

**Mutation is never automatic.** Guided Create/Delete (menu 10/11) default to a **single-operator** read-only plan followed by exact action/target and Plan ID confirmations. Delete also requires the operator to confirm external consumers are absent; KAORI automatically uses or provisions a protected age recovery key, encrypts the original Secret and verifies backup decryptability **before** issuing a guarded Delete. No approval JSON, detached signature or root-owned approver trust key is needed for the interactive single-operator workflow. A separate signed-approval path remains available for non-interactive/enterprise clients. No blind retry, forced Delete or automatic rollback.

For laptop usage and non-mutating checks, see [LOCAL-TEST.md](docs/LOCAL-TEST.md). For the simplified single-person Delete wizard see [DELETE-TLS-SECRET-SOP.md](docs/DELETE-TLS-SECRET-SOP.md). Advanced signed CLI usage remains in [OPERATOR-GUIDE.md](docs/OPERATOR-GUIDE.md). Review [SECURITY.md](SECURITY.md) and [RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) before any release.

## Maintenance and provenance

This public repo is now the only **maintained application source**. Historical Issue #67 and PR #68 remain available in the private `OXY7O/ops-runbooks` for traceability; that repository retains operational runbooks and links, not runtime code dependencies. The public migration uses sanitized file contents, **not the private Git history**.

Apache License 2.0 — see [LICENSE](LICENSE).

**Status of this branch:** source is testable locally but this Draft PR is not yet a tagged stable release or signed-off cluster UAT.
