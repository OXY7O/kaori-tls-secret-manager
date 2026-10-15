# Operator guide: prototype, NOT authorized for production

The normal **one-person interactive** operation is documented in [Single-Operator Delete SOP](DELETE-TLS-SECRET-SOP.md): launch the wizard, review plan, type PROCEED, confirm UNUSED, exact action/target and Plan ID, and let KAORI handle encrypted backup/verification automatically.

**The signed-approval examples below document an optional advanced/non-interactive workflow only.** They are not a prerequisite for guided Create or guided Delete in the interactive wizard. No role handoff or signature files are required in the one-person workflow.


## Read-only / create plan / update plan / delete plan

Prerequisites for any future DEV/UAT: approved namespace, scoped Kubernetes RBAC, trust anchor installed by separate administrator, private workstation with `age`, test certificate/key pair, documented change ticket, and restoration exercise.

The CLI is text-first; no color, icons or interactive TTY is required for read-only planning. Run `python3 scripts/tls_crud.py --help` to inspect supported command arguments. `--context` must precede the subcommand.

**Read:** `python3 scripts/tls_crud.py --context DEV inventory --namespace demo` (all TLS Secret metadata only), or `python3 scripts/tls_crud.py --context DEV inspect --namespace demo --secret demo-tls` (single Secret fingerprint; never includes tls.key).

**Create plan:** `python3 scripts/tls_crud.py --context DEV plan-create --namespace demo --secret demo-tls --cert /private/chain.pem --key /private/key.pem --workspace /private/evidence`.

**Update plan:** `python3 scripts/tls_crud.py --context DEV plan-update --namespace demo --secret demo-tls --cert /private/chain.pem --key /private/key.pem --workspace /private/evidence` (same SAN set only; no change yet).

**Delete plan:** `python3 scripts/tls_crud.py --context DEV plan-delete --namespace demo --secret demo-tls --workspace /private/evidence`.

These commands read cluster state. The preflight must fail on insufficient permissions. `plan-delete` blocks observed Ingress, Pod and Gateway API references, finalizers, ownerReferences, and known cert-manager ownership. It **cannot detect every external dependency**; an authorized owner must independently attest to this.

## Independent signed approval

Produce a JSON approval document such as:

```json
{
  "action": "DELETE",
  "plan_id": "EXACT_PLAN_ID",
  "context": "DEV",
  "cluster_uid": "EXACT_CLUSTER_UID_FROM_PLAN",
  "target": "demo/demo-tls",
  "approver": "INDEPENDENT_AUTHORIZED_APPROVER",
  "change_reference": "APPROVED_CHANGE_TICKET",
  "external_consumer_attested": true,
  "approved_utc": "2026-10-15T09:00:00+00:00",
  "expires_utc": "2026-10-15T09:30:00+00:00"
}
```

The timestamp values above are **illustrative and not valid for future approvals**. The final approved document must be signed *after* the plan is reviewed. Sign with the approver's securely managed private key:

```sh
openssl dgst -sha256 -sign /secure/authorized-approver.key \
  -out /private/approval.sig /private/approval.json
```

An independent administrator installs the corresponding trusted **public** key, root-owned and not group/world writable, at `/etc/kaori/tls-approval-public.pem`. This trust key must not be chosen or replaced by the requester as a way to approve their own mutation.

## Create, Update and Delete execution (DEV/UAT acceptance required first)

```sh
python3 scripts/tls_crud.py --context DEV create \
  --namespace demo --secret demo-tls \
  --cert /private/chain.pem --key /private/key.pem \
  --plan /private/evidence/create-EXACT_PLAN_ID-plan.json \
  --approve EXACT_PLAN_ID --confirm-target demo/demo-tls \
  --approval-record /private/approval.json \
  --approval-signature /private/approval.sig

python3 scripts/tls_crud.py --context DEV update \
  --namespace demo --secret demo-tls \
  --cert /private/chain.pem --key /private/key.pem \
  --plan /private/evidence/update-EXACT_PLAN_ID-plan.json \
  --approve EXACT_PLAN_ID --confirm-target demo/demo-tls \
  --approval-record /private/approval.json \
  --approval-signature /private/approval.sig \
  --backup-recipient age1YOUR_AUTHORIZED_RECOVERY_PUBLIC_KEY

python3 scripts/tls_crud.py --context DEV delete \
  --namespace demo --secret demo-tls \
  --plan /private/evidence/delete-EXACT_PLAN_ID-plan.json \
  --approve EXACT_PLAN_ID --confirm-target demo/demo-tls \
  --approval-record /private/approval.json \
  --approval-signature /private/approval.sig \
  --backup-recipient age1YOUR_AUTHORIZED_RECOVERY_PUBLIC_KEY
```

Create requires that the Secret is absent; Kubernetes `AlreadyExists` is STOP, not update. Update requires existing TLS Secret UID/resourceVersion, same SAN set, existing fingerprint change, fresh source PEM/key, non-controller-managed object, encrypted backup and server-side resourceVersion CAS via `kubectl replace -f -`; any conflict is STOP, no retries. Delete requires that the original Secret can be encrypted with `age` and saved securely **before** a delete request. The server enforces the UID/resourceVersion preconditions and the tool verifies absence afterward. Any failure or uncertain response leaves a journal: **do not retry**. A successful delete is not an application health check. Readiness requires an isolated test with real API and backup restore acceptance.

## Mandatory acceptance evidence

- Valid and invalid PEM/key tests, certificate chain trust, SAN coverage and current validity.
- RBAC-denied scans; controller- and Ingress/Gateway/Pod-referenced target blocking.
- Signed approval validation, tampered record/signature, stale plan, nonexistent approver trust key.
- Race: Secret created between plan/execute; update/delete with changed UID/resourceVersion; failed/timeout API request, journal uncertainty.
- Rotation with same SAN and changed fingerprint, rejection of SAN identity change, immutable/managed Secret, backup failure and mismatched command/plan target.
- Encrypted backup restore, journal reconcile, no raw TLS keys in terminal logs or public CI artifacts.
- Endpoints/app owner acceptance and sign-off for all operations before a public release.
