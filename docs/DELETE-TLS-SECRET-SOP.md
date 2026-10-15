# TLS Secret Delete — Operator SOP

**Status:** Development / approved DEV-UAT. This document does not authorize any actual change. Follow organizational change management. All CLI and UI prompts are in English.

## Overview

KAORI menu **11 — Delete TLS Secret** first creates an immutable, read-only deletion plan. A real deletion subsequently requires an independent, digitally signed approval, a trusted approver public key, a recoverable age-encrypted backup, and fresh Kubernetes state checks. The operation never silently forces deletion, retries uncertain writes, or cascades dependent resources.

**Important current UI limitation:** After choosing to leave the wizard with a saved plan, opening menu 11 again generates a *new plan ID*. To execute an already approved plan without recreating it, use the existing CRUD CLI as shown below. Plans expire **30 minutes** after creation; the approval validity window cannot exceed **one hour**.

### Roles

| Role | Responsible for | Frequency |
| --- | --- | --- |
| Platform administrator | Enroll the approver's trusted public verification key and provision scoped Kubernetes RBAC | Once per device / key rotation |
| Recovery custodian | Securely maintain age recovery identity; provide its public age1... recipient | Once per recovery policy / rotation |
| Application owner | Check Kubernetes and external consumers; attest approved decommission | Every deletion |
| Operator | Select target, make immutable plan, request approval, run authorized operation, retain evidence | Every deletion |
| Independent approver | Verify exact scope, change ticket and external-consumer attestation; sign approval JSON with their own secured signing key | Every deletion |

An operator's local sudo access does NOT replace an independent change approval.

## A. One-time prerequisites

**If the team has no enrolled signing identity yet**, the security administrator and independent approver must first establish one under the organization's key-management procedure. For an isolated approved DEV/UAT setup, a separate approver can generate an RSA-3072 keypair inside their controlled environment (not the requesting operator's laptop):

~~~bash
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /SECURE/APPROVER/approver-private-key.pem
openssl pkey -in /SECURE/APPROVER/approver-private-key.pem -pubout \
  -out /SECURE/HANDOFF/authorized-approver-public.pem
~~~

The approver retains sole control of the private key; an authorized administrator independently verifies the public key's identity/fingerprint before enrolling it as a trusted key. These key-provisioning commands are **not** instructions for the requesting operator to self-approve.

**Administrator:** install an *authenticated* public verification key belonging to the independent authorized approver. An authorized admin may run:

~~~bash
sudo install -d -o root -g root -m 0755 /etc/kaori
sudo install -o root -g root -m 0644 \
  /SECURE/HANDOFF/authorized-approver-public.pem \
  /etc/kaori/tls-approval-public.pem
stat -c '%U %a %n' /etc/kaori/tls-approval-public.pem
~~~

The file must be root-owned, must not be a symlink, and must not be group/world writable. Do **not** substitute an operator-created key to self-approve.

**Recovery custodian:** maintain a safely backed up age identity; only give the operator the *public recipient*:

~~~bash
age-keygen -y /SECURE/RECOVERY/identity.txt
# Returns a string starting with age1...
~~~

Do not send age private identities, signing private keys, unencrypted TLS Secret payloads, or private cluster evidence to GitHub, chat, or CI logs. Before starting a time-limited plan, operator should confirm that the required approver, owner evidence, enrolled public key and age public recipient are already available.

**Operator checks:**

~~~bash
cd ~/workspace/kaori-tls-secret-manager
bash scripts/tls-secret-manager.sh doctor
kubectl config get-contexts
# Substitute approved values:
CTX="APPROVED_CONTEXT"
NS="APPROVED_NAMESPACE"
SECRET="APPROVED_TLS_SECRET"
kubectl --context "$CTX" auth can-i get secrets -n "$NS"
kubectl --context "$CTX" auth can-i delete secrets -n "$NS"
test -f /etc/kaori/tls-approval-public.pem
~~~

RBAC permissions do not themselves constitute change authorization.

## B. Each deletion (the plan is valid for under 30 minutes)

### Step 1 — Validate service ownership and the change

The service owner checks all known Ingress, Gateway, Pod, controller and out-of-band consumers (external LB/proxy, monitoring integrations and manually mounted secrets). Obtain a real change ticket and an owner attestation before the delete window. A zero-result dependency scan does not prove the Secret is unused.

### Step 2 — Create a read-only plan

~~~bash
bash scripts/tls-secret-manager.sh wizard
# Choose: 11. Delete TLS Secret
# Select approved context, namespace and exact Secret name.
# Use private evidence storage outside the Git checkout.
# At "Continue to approval and execution? Type EXECUTE; Enter leaves plan only":
# Press ENTER to save the plan only and return. No delete occurs.
~~~

KAORI prints a private JSON path of the form:

~~~text
~/k8s-tls-private/crud-runs/delete-EXACT_PLAN_ID-plan.json
~~~

Record the **exact** path; do not choose an arbitrary older plan or modify its contents.

Review the plan metadata without printing private keys:

~~~bash
PLAN="$HOME/k8s-tls-private/crud-runs/delete-EXACT_PLAN_ID-plan.json"
python3 - "$PLAN" <<'PY'
import json,sys
from pathlib import Path
p = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for key in ("action","plan_id","created_utc","context","cluster_uid",
            "namespace","secret","dependencies","requires_external_owner_attestation"):
    print(key, ":", p.get(key))
PY
~~~

**STOP** if the context, Secret, cluster UID, owner attestation or action differs from the approved change.

### Step 3 — Independent approver creates and signs the approval

An independent approver reviews the immutable plan and owner evidence. The final approval JSON requires these **exact keys**, replacing placeholders with values from the *actual* plan and approved change:

~~~json
{
  "action": "DELETE",
  "plan_id": "EXACT_PLAN_ID_FROM_PLAN",
  "context": "APPROVED_CONTEXT",
  "cluster_uid": "EXACT_CLUSTER_UID_FROM_PLAN",
  "target": "APPROVED_NAMESPACE/APPROVED_TLS_SECRET",
  "approver": "REAL_INDEPENDENT_APPROVER",
  "change_reference": "APPROVED_CHANGE_TICKET",
  "external_consumer_attested": true,
  "approved_utc": "CURRENT_ISO8601_TIME_WITH_TIMEZONE",
  "expires_utc": "ISO8601_TIME_WITH_TIMEZONE_LESS_THAN_ONE_HOUR_LATER"
}
~~~

The external-consumer attestation must be **true only after actual owner verification**. Approval timestamps must be timezone-aware, current and less than or equal to 60 minutes apart; the expiry is in the future. The immutable plan itself is valid for less than 30 minutes. If it expires, obtain a **new plan and freshly signed approval**, not a timestamp edit.

Only the independent approver signs the exact finalized approval JSON, using a securely managed private signing key:

~~~bash
# Run by the APPROVER on the approved signing environment:
openssl dgst -sha256 \
  -sign /SECURE/APPROVER/approver-private-key.pem \
  -out /SECURE/HANDOFF/delete-approval.sig \
  /SECURE/HANDOFF/delete-approval.json
~~~

Send the signed JSON and detached signature to the operator through an approved channel. The operator must not edit the signed JSON afterward.

Operator: verify against the **pre-enrolled** public key:

~~~bash
APPROVAL="$HOME/k8s-tls-private/approvals/delete-approval.json"
SIG="$HOME/k8s-tls-private/approvals/delete-approval.sig"
TRUST="/etc/kaori/tls-approval-public.pem"
openssl dgst -sha256 -verify "$TRUST" -signature "$SIG" "$APPROVAL"
# Expected: Verified OK
~~~

A cryptographically valid signature does not bypass plan freshness, Kubernetes preconditions or owner checks.

### Step 4 — Execute exactly the already-approved plan

**Option A — Same wizard session:** If the approver and files are ready while menu 11 is still open, type EXECUTE and enter the approved JSON path, detached signature path, installed trusted public key path, public age1... recovery recipient, then AUTHORIZED, exact Plan ID and exact namespace/Secret.

**Option B — Resume a saved plan using the existing CLI:** If the operator left the wizard after planning, do NOT reopen menu 11 just to execute that plan; that creates a new plan ID. Run this from the existing checkout:

~~~bash
cd ~/workspace/kaori-tls-secret-manager
CTX="APPROVED_CONTEXT"
NS="APPROVED_NAMESPACE"
SECRET="APPROVED_TLS_SECRET"
PLAN="$HOME/k8s-tls-private/crud-runs/delete-EXACT_PLAN_ID-plan.json"
APPROVAL="$HOME/k8s-tls-private/approvals/delete-approval.json"
SIG="$HOME/k8s-tls-private/approvals/delete-approval.sig"
TRUST="/etc/kaori/tls-approval-public.pem"
AGE_RECIPIENT="age1PUBLIC_RECOVERY_RECIPIENT_FROM_CUSTODIAN"

PLAN_ID=$(python3 - "$PLAN" <<'PY'
import json,sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["plan_id"])
PY
)

# MUTATING COMMAND — run ONLY when genuinely independently authorized:
bash scripts/tls-secret-manager.sh crud --context "$CTX" delete \
  --namespace "$NS" --secret "$SECRET" \
  --plan "$PLAN" --approve "$PLAN_ID" \
  --confirm-target "$NS/$SECRET" \
  --approval-record "$APPROVAL" \
  --approval-signature "$SIG" \
  --approval-trust-key "$TRUST" \
  --backup-recipient "$AGE_RECIPIENT"
~~~

KAORI validates the signed approval and trust anchor; checks current cluster UID, exact Secret UID/resourceVersion, stored certificate fingerprint, ownership and dependencies; creates an age-encrypted full-object backup; writes an execution journal *before* mutation; deletes through the Kubernetes API with UID/RV preconditions; and re-reads the cluster to verify absence.

Never replace the guarded deletion with an unreviewed manual kubectl delete.

### Step 5 — Confirm result and preserve evidence

The tool returns the execution status and journal path. Successful deletion must be:

~~~text
COMPLETE_ABSENCE_VERIFIED
~~~

Verify the Secret is absent, not merely inaccessible:

~~~bash
kubectl --context "$CTX" -n "$NS" get secret "$SECRET"
# Expected for verified deletion: Kubernetes NotFound
# Forbidden or a network error do NOT prove deletion.
~~~

Review the private backup and journal (the actual filenames share the plan ID):

~~~bash
# Build names using Python to avoid guesswork.
python3 - "$PLAN" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
stem = p.name.removesuffix("-plan.json")
for suffix in ("-backup.age", "-journal.json"):
    print(p.with_name(stem + suffix))
PY
~~~

The authorized recovery custodian should verify that the age backup is decryptable **without displaying raw Secret data or tls.key**:

~~~bash
# Run only in the custodian's approved secure environment with the recovery identity.
BACKUP="/SECURE/HANDOFF/delete-EXACT_PLAN_ID-backup.age"
RECOVERY_ID="/SECURE/RECOVERY/identity.txt"
set -o pipefail
age -d -i "$RECOVERY_ID" "$BACKUP" |
  python3 -c 'import json,sys; s=json.load(sys.stdin); print("Backup target:", s["metadata"]["namespace"] + "/" + s["metadata"]["name"]); print("Type:", s["type"]); print("Decryption: PASS")'
~~~

The command prints target metadata only. Do not redirect plaintext backup to disk or paste decrypted Secret data into logs. Decryption success is not equivalent to a full restore drill: any reconstruction after deletion is a separate controlled change.

Preserve the plan, final signed approval, signature, journal, encrypted backup, change ticket and acceptance evidence in restricted storage. Do not publish them or delete the workspace.

## C. Failure handling

| Situation | Correct behavior |
| --- | --- |
| Plan expired | Regenerate a fresh plan; obtain new approval and signature. |
| Signature fails / trust anchor missing | STOP. Contact independent approver or administrator; do not self-enroll a substitute key. |
| Backup recipient missing or encryption fails | STOP; do not delete without recoverable encrypted backup. |
| New consumer, controller, Secret UID/RV or fingerprint drift | STOP; review current cluster evidence and owner scope. |
| API request timeout, partial result or journal MUTATION_UNCERTAIN | STOP. Inspect journal and live Kubernetes state. **Do not blindly retry**. |
| Delete succeeds but consumer fails | Treat as an incident; use separately approved recovery runbook and custodian. There is no automatic Delete rollback. |

## D. Operator acceptance checklist

- [ ] Service owner confirms no Kubernetes or external dependency on this exact Secret.
- [ ] Cluster context, namespace, target and approved change ticket match.
- [ ] Fresh immutable plan is reviewed and unmodified (under 30 minutes old).
- [ ] Approval is signed by a genuinely independent authorized approver.
- [ ] Signature is valid against the pre-enrolled trusted public key.
- [ ] Valid age public recipient and independently recoverable age identity exist.
- [ ] Only one authorized Delete execution occurs; no force or automatic retry.
- [ ] Journal shows COMPLETE_ABSENCE_VERIFIED and live Secret is NotFound.
- [ ] Encrypted backup is retained; custodian verifies it can be decrypted.
- [ ] Evidence is archived securely and the service owner accepts the outcome.

## E. Recommended wizard UX improvements (not implemented yet)

- Readiness checklist BEFORE a time-limited plan starts.
- Save plan / resume the same approved plan directly inside the original KAORI wizard.
- Generate unsigned approval-request JSON from plan metadata, without generating the approval or private signing key.
- Display plan expiry, approval verification, exact target and backup prerequisites before final execution.
- Show final recovery evidence and an explicit STOP/reconciliation guide for uncertain results.

Do not remove independent approvals, root-owned trust anchors, recovery requirements, Kubernetes preconditions, or journal guards to simplify UX.

Related: [Operator Guide](OPERATOR-GUIDE.md) · [Security](../SECURITY.md) · [Release Checklist](RELEASE-CHECKLIST.md).
