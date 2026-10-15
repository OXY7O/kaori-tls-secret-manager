# KAORI — Single-Operator Delete TLS Secret

**Audience:** one authorized operator using the original KAORI interactive terminal menu.

**Safety:** Follow your organization’s Kubernetes authorization, dependency verification and change-management requirements before any deletion. There are no external approval JSON files, signature files, trusted approver key installation, or separate role handoffs in the **interactive single-operator workflow**.

## One-time setup

Install Git, Python 3.10+, kubectl, OpenSSL and age. Use an authorized Kubernetes context and scoped permissions. Run:

~~~bash
cd ~/workspace/kaori-tls-secret-manager
bash scripts/tls-secret-manager.sh doctor
kubectl config get-contexts
~~~

**Recovery key (once):** for Delete, KAORI automatically detects an existing protected recovery identity at ~/.config/age/k8s-tls-recovery.txt or ~/.config/kaori-tls/recovery.agekey.

If neither exists, the wizard offers to create one. Type SETUP once, then RECOVERY to acknowledge custody of the private key. Future deletions reuse this identity automatically. **Keep a separate secured copy** outside the laptop; losing the identity means the encrypted backups may be impossible to restore. Key files must be private (0600), and the generated key directory must be private (0700). No age private key is printed or uploaded.

## Each deletion — from one menu

1. Start: bash scripts/tls-secret-manager.sh wizard
2. Choose **Delete TLS Secret** from the guided operations.
3. Select the intended **Kubernetes context** and **namespace**; type the **exact Secret name**.
4. Accept the private evidence directory under ~/k8s-tls-private/crud-runs/ (or choose another directory outside the Git checkout). Recovery-key setup is requested later, only if the Secret is eligible and you confirm a real Delete. HOLD and plan-only leave the local recovery setup untouched.
5. **Step 1/3 (read-only preflight):** KAORI checks controller ownership, Ingress TLS references, Pod Secret mounts/env/imagePullSecrets and Gateway TLS certificateRefs. If a consumer is detected, KAORI immediately shows **DELETE ON HOLD / READ ONLY**, the names of detected resources, and the local HOLD evidence file; **no executable plan, recovery-key setup, or Kubernetes write occurs**. If discovery fails due to RBAC or API errors, KAORI shows **DEPENDENCY_SCAN_INCOMPLETE** and also holds. Only an eligible target receives an immutable delete plan, valid for under 30 minutes.
6. Press **Enter** to keep the plan only, or type **PROCEED** if you intend to continue to the guided deletion in this same session.
7. **Step 2/3 (human confirmation):** KAORI asks for UNUSED to confirm you have assessed possible **external** consumers (monitoring, external LB, proxy, integrations, manual mounts). Then type the exact string shown on-screen, such as DELETE namespace/secret. KAORI binds and validates the immutable Plan ID internally; you do not need to copy it. These are the operator's own confirmations, not external approval artifacts.
8. **Step 3/3 (one attempted write):** KAORI validates the still-current plan and Kubernetes UID/resourceVersion, rechecks consumers/ownership/fingerprint, automatically produces an age-encrypted backup, **decrypts it locally and checks it matches the original Secret before deleting**, writes an execution journal, performs Kubernetes DELETE with API preconditions, and verifies the Secret is absent.
9. Read the final status and preserve the output paths. Success is **COMPLETE_ABSENCE_VERIFIED**, not merely a successful kubectl return code.

The terminal never displays TLS private-key bytes. The tool never performs bulk Delete, bypasses dependency checks, retries uncertain writes automatically, or silently restores a deleted Secret.

### Successful result

Expected result/status on-screen:

~~~text
DELETE: COMPLETE_ABSENCE_VERIFIED
Lifecycle journal: .../delete-<PLAN_ID>-journal.json
Encrypted recovery backup: .../delete-<PLAN_ID>-backup.age
~~~

To verify the resource is absent, use the exact context/namespace/name displayed by KAORI:

~~~bash
kubectl --context "APPROVED_CONTEXT" -n "APPROVED_NAMESPACE" \
  get secret "APPROVED_TLS_SECRET"
# Expected only after a completed deletion: NotFound
~~~

Do NOT interpret Forbidden, network failures or API timeouts as proof of successful deletion. The journal and encrypted backup are sensitive recovery evidence; do not delete the evidence directory.

### Example: Secret still in use

~~~text
DELETE ON HOLD / READ ONLY

Target: sandbox/web-tls
Reason: SECRET_IN_USE

Detected blockers:
- Ingress TLS reference: sandbox/frontend
- Pod dependency: sandbox/web-0

Delete is BLOCKED. No executable plan or Kubernetes write was created.
Read-only HOLD evidence: .../delete-hold-....json
~~~

HOLD is not a pause button that can be overridden to force deletion. Resolve the references through the normal operational process, then rerun the wizard from the beginning. The resulting scan may become eligible only if Kubernetes and external consumer evidence is clear. **A clean scan does not prove that an external LB, proxy or application is not using the Secret.** KAORI still asks the operator to type UNUSED before an actual Delete.

### What if I only want to check the target?

On the Step 1 prompt, press **Enter** rather than typing PROCEED. That creates a safe, read-only plan. In the current version, opening the Delete operation again creates a **new plan**; do not assume the old plan is resumed. The normal one-person full flow is designed to complete the checks and confirmations in **one menu session**.

### What if the operation stops?

| Warning / status | Required action |
| --- | --- |
| Kubernetes references or owner/controller detected | Stop; validate live consumers. Never force Delete. |
| Recovery key missing or backup cannot be decrypted | Stop; repair recovery readiness. No write should be sent. |
| Plan expired or UID/resourceVersion/fingerprint changed | Stop; start a fresh guided plan and review updated live state. |
| MUTATION_UNCERTAIN or unknown API outcome | **Do not retry**; inspect journal and real Kubernetes state. |
| Missing Secret but consumer health degraded | Escalate incident and follow separately approved recovery procedure using the encrypted backup. |

### Single-operator verification checklist

- [ ] Correct context, namespace and Secret name selected
- [ ] Kubernetes references and external consumers reviewed
- [ ] Read-only plan validated and fresh
- [ ] Protected recovery key exists and a separate secure copy is maintained
- [ ] UNUSED and exact action/target confirmed by operator; Plan ID verified automatically
- [ ] Encrypted backup roundtrip verified by KAORI before Delete
- [ ] Final status COMPLETE_ABSENCE_VERIFIED and actual Secret NotFound
- [ ] Plan, journal and encrypted backup retained securely

## Advanced backend mode (optional)

The lower-level non-interactive scripts/tls_crud.py retains signed-approval support for users with an organizational separation-of-duties requirement. **It is not the recommended/default single-operator experience** and should not be needed to use the guided Create/Delete operations. In that mode, a separate approver, signed JSON and registered trust key are intentionally still required. The original guided renewal engine may have additional review/signature policies for multi-target or externally terminated TLS changes.

See the [Operator guide](OPERATOR-GUIDE.md), [Security policy](../SECURITY.md) and [Installation guide](INSTALLATION.md).
