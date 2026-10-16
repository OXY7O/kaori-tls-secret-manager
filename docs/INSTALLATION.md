# Installation and verification

KAORI TLS Secret Manager is distributed as source code through [versioned GitHub Releases](https://github.com/OXY7O/kaori-tls-secret-manager/releases). No separate Python package or container image is required.

## Requirements

- Linux / WSL2, Bash, Python 3.10+, Git, OpenSSL and age.
- kubectl and a Kubernetes context with appropriate RBAC for cluster operations.
- Certificate files and encryption identities stored securely **outside** the repository.

On Ubuntu/WSL:

~~~bash
sudo apt update
sudo apt install -y git python3 openssl age ca-certificates
# Install kubectl following https://kubernetes.io/docs/tasks/tools/
~~~

## Install a versioned release

~~~bash
mkdir -p ~/workspace
cd ~/workspace
git clone --branch v0.2.7 --depth 1 https://github.com/OXY7O/kaori-tls-secret-manager.git
cd kaori-tls-secret-manager
bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh wizard --plain
~~~

For a source archive, download the .tar.gz and SHA256SUMS from the release page, verify with **sha256sum -c SHA256SUMS**, then extract the archive. The SHA-256 file verifies integrity, not publisher identity.

To use the latest source rather than a fixed release, clone the default **main** branch. For an existing main checkout, run **git pull --ff-only origin main**. Version tags are immutable.

## Verify the utility

These checks do not access Kubernetes:

~~~bash
python3 --version
openssl version
age --version
python3 -m unittest discover -s tests -v
bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh --help
bash scripts/tls-secret-manager.sh crud --help
bash scripts/tls-secret-manager.sh wizard --help
~~~

Run **bash scripts/tls-secret-manager.sh wizard --plain** in an interactive terminal. Select **Help** to inspect the interface or **Exit** to leave without inspecting a cluster. Inventory uses your selected Kubernetes context.

## Read-only Kubernetes operations

Substitute your own authorized context and namespace. The following queries do not change Kubernetes Secrets:

~~~bash
kubectl config get-contexts
kubectl --context APPROVED_CONTEXT auth can-i list secrets -n APPROVED_NAMESPACE
kubectl --context APPROVED_CONTEXT auth can-i get secrets -n APPROVED_NAMESPACE
bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT inventory --namespace APPROVED_NAMESPACE
~~~

For diagnostics of stored certificate material and live HTTPS endpoints, use **TLS Toolbox → TLS Doctor**. **Reverify HTTPS** requires evidence from a previous renewal run, not an arbitrary endpoint.

## Read-only lifecycle planning

Plans inspect the selected Kubernetes target; planning alone does not write a Secret. Place certificate sources and private workspaces outside the repository:

~~~bash
umask 077
mkdir -p "$HOME/k8s-tls-private"
chmod 700 "$HOME/k8s-tls-private"

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT plan-create \
  --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET \
  --cert "$HOME/secure/fullchain.pem" --key "$HOME/secure/private.key" \
  --workspace "$HOME/k8s-tls-private"

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT plan-delete \
  --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET \
  --workspace "$HOME/k8s-tls-private"
~~~

A Delete plan may return **HOLD** for active consumers, controller-managed objects or incomplete dependency visibility. This must not be overridden. For an authorized mutation, use the guided **Create TLS Secret** or **Delete TLS Secret** operation, review the exact target and plan, and follow its confirmation and encrypted recovery steps. See the [operator guide](OPERATOR-GUIDE.md), [safe Delete procedure](DELETE-TLS-SECRET-SOP.md) and [security policy](../SECURITY.md).

Never publish kubeconfigs, TLS private keys, recovery identities, raw journal files or sensitive cluster evidence.
