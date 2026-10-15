<p align="center">
  <img src="assets/kaori-logo.png" width="660" alt="KAORI TLS Certificate Manager — Kubernetes TLS management utility">
</p>

<p align="center">
  <strong>Safer Kubernetes TLS certificate management.</strong>
</p>

<p align="center">
  <a href="https://github.com/OXY7O/kaori-tls-secret-manager/actions/workflows/ci.yml"><img alt="Offline CI" src="https://github.com/OXY7O/kaori-tls-secret-manager/actions/workflows/ci.yml/badge.svg?branch=feat%2Fcrud-and-repo-migration"></a>
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <a href="#release-and-compatibility"><img alt="Preview" src="https://img.shields.io/badge/release-development%20preview-orange"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-you-can-do">Features</a> ·
  <a href="#commands-and-usage">Commands</a> ·
  <a href="docs/OPERATOR-GUIDE.md">Operator guide</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## Overview

**KAORI TLS Certificate Manager** is an open-source utility for managing Kubernetes Secrets of type **kubernetes.io/tls**. It brings together certificate inventory, expiry audits, trust and HTTPS diagnostics, guarded certificate renewal, and explicit Create/Delete lifecycles in one utility with a guided terminal interface.

Designed for **human-controlled infrastructure operations**: inspect before changing, bind every mutation to a reviewed target, preserve recovery evidence, and stop on unsafe or ambiguous state. Choose a guided terminal experience or script-oriented commands with JSON output.

> **Scope:** KAORI manages certificate/key material already issued by your CA or certificate provider. It does **not** issue certificates, run ACME challenges, or replace cert-manager.

## What you can do

| Capability | Operator experience | Safety behavior |
| :--- | :--- | :--- |
| **Inventory & expiry audit** | Browse TLS Secrets, certificate validity, fingerprints and grouped expiry status | Read-only Kubernetes inspection; no private key printed |
| **TLS Toolbox & Doctor** | Inspect stored certificates; compare live HTTPS hostname, SNI, CA trust and served fingerprint | Distinguishes Secret state from load-balancer/endpoint state |
| **Prometheus textfile metrics** | Export aggregate expiration/audit gauges to a local .prom file | Export only; does not configure or push into Prometheus |
| **Renew / Update** | Guided target discovery, selective READY/HOLD/SKIPPED review and renewal; optional single-target same-SAN CRUD Update | Fresh plans, authorized writes, encrypted backups, journaling, scoped recovery |
| **Create** | Guided Create or plan-create/create commands | Validates supplied PEM/key, checks target absence, never overwrites |
| **Delete / decommission** | Guided Delete or plan-delete/delete commands | **HOLD** when Ingress/Pod/Gateway references, ownership or visibility blocks safety; backup before deletion, API UID/resourceVersion preconditions |
| **Recovery & evidence** | Run history, HOLD review, HTTPS re-verification and guarded rollback flows | No blind retries after an uncertain mutation; private local artifacts |

This is not an unattended controller. In particular, a clean Kubernetes reference scan **does not prove** a Secret is unused by external load balancers, proxies or integrations; a human must confirm external dependencies before Delete.

## Quick start

### Requirements

- **Linux or WSL2**, Bash, Git and **Python 3.10+**. The source uses the Python standard library; no pip install is required.
- **OpenSSL** and **age** for certificate inspection and encrypted recovery.
- **kubectl** and an explicitly authorized kubeconfig context for cluster operations. You can run help, doctor and offline tests without cluster credentials.

Ubuntu / WSL example:

~~~bash
sudo apt update
sudo apt install -y git python3 openssl age ca-certificates
# Install kubectl for your environment from https://kubernetes.io/docs/tasks/tools/

git clone https://github.com/OXY7O/kaori-tls-secret-manager.git
cd kaori-tls-secret-manager

# Until the first verified release is merged to main, use the implementation branch:
git fetch origin
git switch --track origin/feat/crud-and-repo-migration

bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh wizard --plain
~~~

The guided interface starts automatically when you run the launcher without arguments. Select **Help** to explore features or **Exit** to leave. Accepting the default selection starts read-only Inventory, which accesses your selected Kubernetes context.

### First read-only commands

~~~bash
# List help before accessing any cluster
bash scripts/tls-secret-manager.sh --help
bash scripts/tls-secret-manager.sh crud --help

# Change these placeholders to your authorized Kubernetes context and namespace
bash scripts/tls-secret-manager.sh crud \
  --context APPROVED_CONTEXT inventory --namespace APPROVED_NAMESPACE

bash scripts/tls-secret-manager.sh crud \
  --context APPROVED_CONTEXT inspect \
  --namespace APPROVED_NAMESPACE --secret APPROVED_TLS_SECRET
~~~

Read-only CRUD results are JSON. The CRUD engine requires the global **--context** before the subcommand.

## Guided operations

The interactive interface groups **Inventory**, **Expiry Audit**, **TLS Toolbox**, **HTTPS Verification**, **Renewal**, **HOLD Review**, **Run History**, **Create**, and **Delete** in one place. Select the operation by its displayed name; numeric shortcuts can change between versions.

For a new TLS Secret or HTTPS endpoint, use **TLS Toolbox → TLS Doctor**. **Reverify HTTPS** examines evidence from a previously saved renewal run.

Interactive Create/Delete is optimized for a **single authorized operator**: select context, namespace and exact Secret; review the read-only plan; explicitly type **PROCEED** to continue. Delete also requires an **UNUSED** external-consumer attestation and exact target confirmation; KAORI provisions/reuses a protected age recovery identity and verifies its encrypted backup before the write. Optional **independently signed approvals** remain supported for advanced non-interactive workflows. There is no force-delete shortcut.

Read the [single-operator Delete walkthrough](docs/DELETE-TLS-SECRET-SOP.md) before using the Delete workflow.

## Commands and usage

All entrypoints use the same repository; no second checkout is required.

| Command | Purpose |
| :--- | :--- |
| `bash scripts/tls-secret-manager.sh` | Open the interactive wizard |
| `bash scripts/tls-secret-manager.sh wizard --plain` | Accessible plain-text wizard |
| `bash scripts/tls-secret-manager.sh doctor` | Check local dependencies; no Kubernetes API access |
| `bash scripts/tls-secret-manager.sh crud --help` | Guarded CRUD command help |
| `bash scripts/tls-secret-manager.sh --help` | Historical renewal-engine command help |

**Guarded lifecycle operations** (prefix: **bash scripts/tls-secret-manager.sh crud --context CONTEXT**):

| Subcommand | Use |
| :--- | :--- |
| **inventory** | List TLS Secret metadata in a namespace |
| **inspect** | Inspect one Secret's identity/fingerprint |
| **plan-create → create** | Plan then explicitly create a new TLS Secret |
| **plan-update → update** | Plan then rotate one existing TLS Secret with the same SAN set |
| **plan-delete → delete** | Scan dependencies, plan, then explicitly decommission one Secret |

The planning commands are read-only with respect to Kubernetes and store private plan/evidence files in **--workspace**, which must be outside the checkout. Mutation commands require a plan, exact Plan ID, target confirmation and either interactive operator-mode authorization or a signed approval record. Update and Delete require an age backup recipient. **Do not substitute a bare kubectl delete command for KAORI's guarded Delete workflow.**

**Advanced renewal operations:** `discover`, `reconcile`, `inspect`, `verify-source`, `plan`, `renew`, `verify`, `verify-endpoints`, `rollback`, `rollback-target`, `report`. For argument details, invoke **--help** and see the [operator guide](docs/OPERATOR-GUIDE.md) and [example target CSV files](scripts/kubernetes/tls-secret-manager/examples/).

**Toolbox:** [TLS Doctor and Prometheus metrics usage](docs/TOOLBOX-METRICS-DOCTOR.md) covers read-only standalone commands, metrics labels, private output directories and endpoint mismatches. [Local testing](docs/LOCAL-TEST.md) covers offline checks and trial contexts.

## Safety by design

- **Explicit scope:** operator-selected cluster context, namespace and Secret for writes.
- **Plan → confirm → act:** live revalidation, resource identity/version checks and fail-closed drift handling.
- **Dependency awareness:** block unsafe Delete attempts for observed consumers, controller-managed Secrets, ambiguous references or incomplete RBAC visibility.
- **Private recovery:** encrypted original Secret backup for destructive operations; protected local evidence and journal files. Never commit kubeconfigs, PEM keys, identities, plans, backups or real cluster output.
- **No automatic retry or rollback** on uncertain write outcomes. Reconcile the journal and current cluster state before requesting any new mutation.
- **Endpoint ≠ Secret:** a TLS Secret can be valid while an Ingress, load balancer or old cluster still serves another certificate.

See the [security policy](SECURITY.md) and [architecture](docs/ARCHITECTURE.md). Please report suspected vulnerabilities **privately**, not in public issues.

## Release and compatibility

**Current source version: 0.1.0-dev (development preview).** The implementation lives on the open feature branch / Draft PR; **main does not yet contain the complete utility**. The historical offline regression suite runs in GitHub Actions, but a successful CI badge is **not** evidence of real-cluster DEV/UAT acceptance, secure release signing, or authorization for production changes.

Use the documented Linux/WSL source workflow for evaluation. There is **no published standalone binary, Homebrew package, container image, or supported production release** to install today. See the [release checklist](docs/RELEASE-CHECKLIST.md) for acceptance criteria and [changelog](CHANGELOG.md) for work delivered to the development branch.

## Documentation & community

- **Users:** [Local installation and tests](docs/LOCAL-TEST.md) · [Operator guide](docs/OPERATOR-GUIDE.md) · [Safe Delete SOP](docs/DELETE-TLS-SECRET-SOP.md) · [Toolbox & metrics](docs/TOOLBOX-METRICS-DOCTOR.md)
- **Maintainers:** [Architecture](docs/ARCHITECTURE.md) · [Release checklist](docs/RELEASE-CHECKLIST.md) · [Changelog](CHANGELOG.md)
- **Community:** [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Support](SUPPORT.md) · [Security policy](SECURITY.md) · [Issues](https://github.com/OXY7O/kaori-tls-secret-manager/issues) · [Pull requests](https://github.com/OXY7O/kaori-tls-secret-manager/pulls)

Contributions, bug reports, accessibility improvements and sanitized synthetic regression cases are welcome. **Never attach internal hostnames, raw TLS material or production evidence to public issues.**

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

The PNG [wordmark](assets/kaori-logo.png) and [shield mark](assets/kaori-mark.png) are project identity assets. The utility renders the PNG in supported terminals and a matching text-safe shield elsewhere, respecting plain-text mode.
