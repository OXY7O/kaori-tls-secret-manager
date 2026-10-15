# Laptop testing: historical KAORI wizard + standalone CRUD

> **Development/UAT only.** Historical scripts are fetched **only to your laptop** from the private `ops-runbooks` archived work branch. They are never copied into this public repository. The temporary bridge restores the original nine-option wizard/Toolbox so that you can test the capabilities that existed before the repository migration. It does not mean the public source migration is complete.

## Requirements

- Ubuntu/WSL or Linux with `git`, Python 3.10+, `openssl`, `age`, and `kubectl` for read-only cluster tests.
- Access rights to private `OXY7O/ops-runbooks`. Never expose its code, output, private certificates, kubeconfig, or evidence in the public repo.
- Separate DEV/UAT Kubernetes context for any eventual cluster tests. **Do not run update/renew/delete in production.**

## 1. Sync both source trees

```bash
mkdir -p ~/workspace
cd ~/workspace/kaori-tls-secret-manager
git fetch origin
git switch feat/crud-and-repo-migration
git pull --ff-only origin feat/crud-and-repo-migration

# Check out the closed-unmerged PR #68 historical branch into a SEPARATE PRIVATE directory.
cd ~/workspace
git clone git@github.com:OXY7O/ops-runbooks.git ops-runbooks-tls-archive
cd ops-runbooks-tls-archive
git fetch origin feat/issue-67-k8s-tls-secret-manager
git switch --track origin/feat/issue-67-k8s-tls-secret-manager
```

If you use HTTPS Git credentials rather than SSH, replace the clone URL with `https://github.com/OXY7O/ops-runbooks.git`. If you already have the private checkout, omit `git clone` and just fetch/switch. The legacy branch was intentionally **closed without merge**; do not use the private repository's `main` branch for this test.

## 2. Explicitly select archived local source

```bash
cd ~/workspace/kaori-tls-secret-manager
export KAORI_LEGACY_DIR="$HOME/workspace/ops-runbooks-tls-archive/scripts/kubernetes/tls-secret-manager"

test -f "$KAORI_LEGACY_DIR/tls_secret_wizard.py"
test -f "$KAORI_LEGACY_DIR/tls_secret_manager.py"
bash scripts/kaori-tls-secret-manager.sh doctor
bash scripts/kaori-tls-secret-manager.sh --help
```

`KAORI_LEGACY_DIR` is opt-in and must be an absolute path. The old code runs from that private checkout. No symlink or source copy is committed to GitHub. If both modules are not present, the launcher stops rather than silently using an incomplete wizard.

## 3. Run all offline tests before connecting to a cluster

```bash
# New standalone public CRUD + launcher regression suite
cd ~/workspace/kaori-tls-secret-manager
python3 -m unittest discover -s tests -v

# Original historical wizard and advanced renewal helper regression suite
cd ~/workspace/ops-runbooks-tls-archive
python3 -m unittest discover -s tests -p 'test_tls_*.py' -v
```

Both suites should finish with `OK`. A successful offline test is not an authorization to write Kubernetes Secrets.

## 4. See the original KAORI interactive menu

```bash
cd ~/workspace/kaori-tls-secret-manager
export KAORI_LEGACY_DIR="$HOME/workspace/ops-runbooks-tls-archive/scripts/kubernetes/tls-secret-manager"

# Opens historical KAORI menu: Inventory, Expiry audit, Toolbox, HTTPS verify,
# Renew TLS, Review HOLD, Run history, Status guide, Help and Exit.
bash scripts/kaori-tls-secret-manager.sh wizard --plain
```

At this stage, choose **9 Help**, **8 Status guide**, then **0 Exit** before trying a real cluster. The CLI defaults to **Inventory** on Enter; it contacts Kubernetes. Do not press Enter if you just want to explore the menu offline.

## 5. Read-only DEV/UAT test (optional)

```bash
kubectl config get-contexts
kubectl --context YOUR_APPROVED_DEV_CONTEXT auth can-i list secrets -n YOUR_APPROVED_NAMESPACE

# Direct standalone CRUD inventory - NO Secret write, no key printed.
cd ~/workspace/kaori-tls-secret-manager
bash scripts/kaori-tls-secret-manager.sh crud --context YOUR_APPROVED_DEV_CONTEXT inventory --namespace YOUR_APPROVED_NAMESPACE

# Or select 1 Inventory in the historical wizard and follow read-only prompts.
bash scripts/kaori-tls-secret-manager.sh wizard --plain
```

Avoid sharing raw kubeconfig, Secret payloads, private evidence paths, or internal endpoints. Use scoped credentials; `--plain` disables ANSI/Unicode embellishments. Do not enter Renewal Wizard's approval/write steps without a formally approved change.

## 6. Stay synchronized

```bash
cd ~/workspace/kaori-tls-secret-manager
git pull --ff-only origin feat/crud-and-repo-migration

# Historical reference branch is an archived baseline; updating it is not needed for routine development.
# Only refresh explicitly if a migration repair is made there.
```

## Important limitation

The full historical source is not yet published to the standalone public repository. This **local-only, user-authorized bridge** lets you test the real historical implementation today, and the new Create/Read/Update/Delete commands in the same launcher. The eventual validated public release will contain a fully sanitized port and will no longer require the archived private repository. Until then, do not describe this as a completed public-source cutover or production release.
