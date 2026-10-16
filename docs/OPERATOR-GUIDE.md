# Operator guide

Use KAORI TLS Secret Manager from an authorized Kubernetes context with credentials appropriate to the selected namespace and operation. The guided interface is designed for **one accountable operator**; optional signed approvals support independently governed automation.

## Guided operations

Launch the utility with:

~~~bash
bash scripts/tls-secret-manager.sh wizard
~~~

Use **Inventory**, **Expiry Audit**, **TLS Toolbox/Doctor**, **Create TLS Secret**, **Update TLS Secret**, **Renew TLS Secrets** or **Delete TLS Secret** by selecting their displayed names. The wizard reviews the selected context, namespace, Secret identity and read-only plan before any write. After a verified Delete, **Delete recovery / Restore** can reconcile the live state and offer a guarded create-only restore from the encrypted backup. An uncertain Delete journal, existing Secret or unpinned namespace identity is a hard HOLD; no blind retries. For guided Delete, see the complete [decommissioning procedure](DELETE-TLS-SECRET-SOP.md). For first-time Update/Delete key custody and recovery, read the [age guide](AGE-RECOVERY.md) or open the wizard's **Age setup / recovery help**.

For Create/Update/Delete, follow the prompts and explicitly type **PROCEED** to continue after planning. Delete additionally requires confirmation that external consumers are **UNUSED**, the exact target/action phrase and verified encrypted recovery backup. A separate signature file is not required for guided single-operator Create/Update/Delete. One-target guided renewal requires `AUTHORIZED` and exact Plan ID; multi-target or external-TLS-termination renewal additionally requires independent signed approval.

## Read-only inspection and plans

Prepare private certificate and evidence paths outside the source checkout, then use the CLI as follows:

~~~bash
bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  inventory --namespace APPROVED_NAMESPACE

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  inspect --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-create --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET \
  --cert /secure/chain.pem --key /secure/key.pem --workspace /secure/evidence

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-update --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET \
  --cert /secure/chain.pem --key /secure/key.pem --workspace /secure/evidence

bash scripts/tls-secret-manager.sh crud --context APPROVED_CONTEXT \
  plan-delete --namespace APPROVED_NAMESPACE --secret EXAMPLE_TLS_SECRET \
  --workspace /secure/evidence
~~~

These commands do not write Kubernetes Secrets. **HOLD** on insufficient RBAC, incomplete Ingress/Pod/Gateway/workload-template visibility, controller ownership or active consumers is an expected safety outcome, not a condition to override. Kubernetes reference discovery does not establish the absence of external consumers.

## Optional independent signed approvals

For organizations requiring separation of duties, non-interactive Create/Update/Delete can use a reviewed approval record signed by an independent approver. A representative JSON record is:

~~~json
{
  "action": "DELETE",
  "plan_id": "EXACT_PLAN_ID",
  "context": "APPROVED_CONTEXT",
  "cluster_uid": "EXACT_CLUSTER_UID_FROM_PLAN",
  "target": "APPROVED_NAMESPACE/EXAMPLE_TLS_SECRET",
  "approver": "AUTHORIZED_APPROVER",
  "change_reference": "APPROVED_CHANGE_REFERENCE",
  "external_consumer_attested": true,
  "approved_utc": "REPLACE_WITH_CURRENT_UTC_TIME",
  "expires_utc": "REPLACE_WITH_VALID_EXPIRY_UTC_TIME"
}
~~~

The example is a template, not an executable authorization. Once the exact plan is reviewed, sign the completed record using an independently controlled key:

~~~bash
openssl dgst -sha256 -sign /secure/authorized-approver.key \
  -out /secure/approval.sig /secure/approval.json
~~~

The corresponding approver public key must be installed as a protected trust anchor according to your organization's authorization policy. The requester must not replace the trust key to approve their own change. Refer to **bash scripts/tls-secret-manager.sh crud --help** for supported approval and backup arguments.

## Execution safeguards

- **Create:** fail closed if the Secret already exists; never silently switch to Update.
- **Update:** require a matching SAN identity and exact UID/resourceVersion, approval, encrypted backup and verification. Conflicts stop the write.
- **Delete:** require complete dependency inspection, external-consumer attestation, original Secret backup verified by decryption and API deletion preconditions.
- **All writes:** journal results; do not assume success after timeouts or blindly retry uncertain requests. Verify HTTPS endpoint identity separately from stored Secret state.

The accountable operator must maintain Kubernetes authorization, recovery identity custody, change evidence and application-owner verification for their environment. See [Security](../SECURITY.md) and [release quality policy](RELEASE-POLICY.md).

## Inventory ALL read failures

Inventory is read-only. It must LIST Ingress and Secret resources and GET each TLS Secret across every selected namespace. Default request timeout is 90 seconds, LIST pagination uses 100 objects, and transient network/API errors are retried at most twice. Adjust via `wizard --inventory-read-timeout-seconds 120` or direct `discover --read-timeout-seconds 120`. Any failed read produces `INVENTORY_INCOMPLETE` and no final inventory CSV. See [Inventory troubleshooting](INVENTORY-TROUBLESHOOTING.md). A bare `kubectl auth can-i` is invalid; provide both a verb and resource.
