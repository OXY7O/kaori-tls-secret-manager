# Local laptop test — original KAORI UI + full CRUD

## Requirements

Ubuntu/WSL (or Linux), Python 3.10+, git, OpenSSL, `age`. Install `kubectl` and an approved Kubernetes DEV/UAT context only when ready to test read-only Inventory.

**You only need this repository.** Do not clone `ops-runbooks`, use `KAORI_LEGACY_DIR`, copy PEM keys into the repository, or use private cluster evidence in GitHub.

## Clean installation from zero

```bash
sudo apt update
sudo apt install -y git python3 openssl age ca-certificates
mkdir -p ~/workspace
cd ~/workspace
git clone https://github.com/OXY7O/kaori-tls-secret-manager.git
cd kaori-tls-secret-manager
git fetch origin
git switch --track origin/feat/crud-and-repo-migration
```

A later update is just `git pull --ff-only origin feat/crud-and-repo-migration`. Do not use `--track` on an already-existing local branch.

## Offline validation — no Kubernetes connection

```bash
python3 --version
openssl version
age --version
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/tls_crud.py scripts/kubernetes/tls-secret-manager/tls_secret_manager.py scripts/kubernetes/tls-secret-manager/tls_secret_wizard.py scripts/kubernetes/tls-secret-manager/tls_inventory.py scripts/kubernetes/tls-secret-manager/tls_ops.py
bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh crud --help
bash scripts/tls-secret-manager.sh wizard --help
```

For the **same original KAORI menu**, run in an interactive terminal:

```bash
bash scripts/tls-secret-manager.sh wizard --plain
```

Review **Help** then **Exit** without starting Kubernetes discovery. The same guided utility includes Create, Delete, inventory, diagnostics and renewal without requiring separate applications.

### HTTPS checks when the workspace is empty

After resetting `~/k8s-tls-private/`, the wizard correctly shows **0 saved runs**.
Main-menu **Reverify HTTPS** is for a previously executed renewal run with
`renewal-plan.json`, `execution-journal.json` and saved endpoint mapping. It
cannot probe an arbitrary new endpoint without that evidence. When no run exists,
press **Enter** or type **0** (or **QUIT**) to return. A valid full path to an
older saved `renewal-plan.json` can still be entered.

To inspect a TLS Secret or HTTPS endpoint **without any previous run**, use
**TLS Toolbox → TLS Doctor**. After selecting context, namespace, and
Secret, leave the HTTPS hostname blank for stored-certificate checks only, or
enter a concrete approved hostname for a live SNI/trust/fingerprint probe.
This operation does not write Kubernetes Secrets. Read
[TOOLBOX-METRICS-DOCTOR.md](TOOLBOX-METRICS-DOCTOR.md) for details.

## Read-only Kubernetes checks (approved DEV/UAT only)

```bash
kubectl config get-contexts
kubectl --context APPROVED_DEV_CONTEXT auth can-i list secrets -n APPROVED_DEV_NAMESPACE
kubectl --context APPROVED_DEV_CONTEXT auth can-i get secrets -n APPROVED_DEV_NAMESPACE
bash scripts/tls-secret-manager.sh crud --context APPROVED_DEV_CONTEXT inventory --namespace APPROVED_DEV_NAMESPACE
```

Or launch original wizard and select Inventory. This reads Secrets and may produce private local reports; avoid pasting names, hostnames, private files or kubeconfig contents into public issues.

## Plan Create / Delete — no mutation

For approved test targets only, and private PEM files outside the repository:

```bash
umask 077
mkdir -p "$HOME/k8s-tls-private"
chmod 700 "$HOME/k8s-tls-private"
bash scripts/tls-secret-manager.sh crud --context APPROVED_DEV_CONTEXT plan-create \
  --namespace APPROVED_DEV_NAMESPACE --secret TEST_TLS_SECRET \
  --cert "$HOME/secure/fullchain.pem" --key "$HOME/secure/private.key" \
  --workspace "$HOME/k8s-tls-private"

bash scripts/tls-secret-manager.sh crud --context APPROVED_DEV_CONTEXT plan-delete \
  --namespace APPROVED_DEV_NAMESPACE --secret TEST_TLS_SECRET \
  --workspace "$HOME/k8s-tls-private"
```

`plan-delete` is **not** safe to assume PASS: known references, controllers, incomplete dependency visibility, and missing RBAC must STOP. For the interactive one-person Create/Delete trial, operator confirmations replace external signature files. Do not execute a real mutation until the approved DEV/UAT target is checked and—before Delete—encrypted recovery is ready. The optional non-interactive signed workflow retains stricter external signature/trust-anchor requirements.

## Operational update

```bash
cd ~/workspace/kaori-tls-secret-manager
git fetch origin
git pull --ff-only origin feat/crud-and-repo-migration
python3 -m unittest discover -s tests -v
```

The code remains on a Draft PR until security, end-to-end DEV/UAT and operator sign-off are complete.

## Simplified local Create/Delete workflow

Start the original menu with `bash scripts/tls-secret-manager.sh wizard`, select 10 (Create) or 11 (Delete), follow the on-screen context/namespace/Secret prompts, and review the read-only plan. Press Enter to keep a plan only, or type PROCEED to enter the guided confirmation phase. Delete auto-reuses or offers to generate a protected age recovery identity, then requires UNUSED and the exact DELETE namespace/secret phrase. The immutable Plan ID is checked automatically. Before deletion the original Secret is encrypted and the backup is verified by decrypting it locally. The optional signed CLI flow is not needed for single-operator interactive usage. See [DELETE-TLS-SECRET-SOP.md](DELETE-TLS-SECRET-SOP.md).
