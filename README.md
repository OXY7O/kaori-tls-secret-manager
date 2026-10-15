# KAORI TLS Secret Manager

**Status: public development-branch prototype; NOT merged or accepted for DEV/UAT. Never use write actions on production clusters.**

A vendor-neutral Kubernetes `kubernetes.io/tls` Secret lifecycle manager. This independent bootstrap package now contains guarded **Create**, metadata-only **Read** (Inventory/Inspect), **single-target same-SAN Update**, and governed **Delete**. The previous multi-namespace Renewal/Toolbox/terminal wizard remain in historical private work pending audited, sanitized migration; **this is not yet a complete released application**.

## Current capabilities

| Feature | Status |
| --- | --- |
| Create: plan + signed approval + atomic Secret create + readback verification | Offline prototype, not DEV/UAT accepted |
| Read: namespace TLS inventory and metadata / SHA256 inspect | Offline prototype |
| Update: single-target same-SAN rotation + encrypted backup + RV/CAS update + readback | Offline prototype; historical batch/wave renewal not yet migrated |
| Delete: dependency scan + signed approval + age-encrypted backup + API DeleteOptions UID/RV preconditions + readback | Offline prototype, not DEV/UAT accepted |
| Public installer / versioned release | Not available |

The prototype requires Python 3.10+, `kubectl`, OpenSSL and `age`. No third-party Python modules or private CA certificates are bundled.

## Safe local commands

```
python3 scripts/tls_crud.py --help
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/tls_crud.py
python3 scripts/tls_crud.py --context approved-dev-context inventory --namespace example-namespace
```

**Do not execute the commands below against a cluster until permissions, live API compatibility, operator acceptance, and recovery have been validated in an isolated DEV/UAT environment.** They are templates for the eventual workflow, not authorizations:

```sh
CTX=approved-dev-cluster
NS=example-namespace
SECRET=example-tls
WORKSPACE="$HOME/.local/share/kaori-tls-private"
CERT="$HOME/secure/fullchain.pem"
KEY="$HOME/secure/private.key"

python3 scripts/tls_crud.py --context "$CTX" plan-create \
  --namespace "$NS" --secret "$SECRET" \
  --cert "$CERT" --key "$KEY" --workspace "$WORKSPACE"

python3 scripts/tls_crud.py --context "$CTX" plan-update \
  --namespace "$NS" --secret "$SECRET" \
  --cert "$CERT" --key "$KEY" --workspace "$WORKSPACE"

python3 scripts/tls_crud.py --context "$CTX" plan-delete \
  --namespace "$NS" --secret "$SECRET" --workspace "$WORKSPACE"
```

Plan files are stored with mode `0600` and exclude raw certificate keys. A separate authorized approver must sign the approval JSON. Neither `--approve` alone nor merely knowing the plan ID can authorize a mutation. See [operator workflow](docs/OPERATOR-GUIDE.md).

## Repository migration

Source of truth target: [OXY7O/kaori-tls-secret-manager](https://github.com/OXY7O/kaori-tls-secret-manager). The private `ops-runbooks` repository will ultimately keep the internal SOP and a pinned public-release reference, **not a second active copy of source code**. Prior Git history, cluster references and environment-specific test fixtures must not be copied publicly. Original private GitHub issue/PR history remains archived in its original repository; this package does not include it.

The source currently tracked privately has **not** been moved into this starter. See [migration checklist](docs/MIGRATION.md).

## Security

- Explicit context, target name/namespace, independent approval and immutable plan.
- No Secret private keys or kubeconfig contents printed.
- Create never overwrites an existing Secret. Update requires an existing non-controller-managed TLS Secret with the **same SAN identity**; broader identity changes are not automatically authorized.
- Delete is blocked by known Kubernetes dependencies, unknown permissions, controllers or finalizers; requires signed owner attestation and an encrypted backup.
- The Kubernetes DeleteOptions request uses server-side UID/resourceVersion preconditions; the write-ahead journal prevents blind retries after uncertain outcomes.
- No automatic rollback or write retries; uncertain operations require a separate recovery workflow.

**Limitations:** Kubernetes dependencies may exist outside visible Pods, Ingresses and Gateway API resources. Dependency scanning cannot prove there are no external consumers. Actual API behavior, backup restoration and approvals have not been tested against a real cluster. Do not infer production readiness from offline CI.

## License

Apache License 2.0; see [LICENSE](LICENSE). Maintainers and contributors should retain required attribution and notices. SPDX identifier: `Apache-2.0`.
