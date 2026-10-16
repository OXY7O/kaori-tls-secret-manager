# KAORI TLS Secret Manager — isolated Kubernetes operator UAT

**Status:** test specification, **not execution evidence**. Do not mark PASS until a human operator runs each scenario against an explicitly authorized disposable Kubernetes environment and retains sanitized results. GitHub synthetic CI never mutates a real cluster.

## Preconditions

- Use an isolated **non-production** cluster with one disposable namespace; record exact kubecontext and cluster UID before testing.
- Generate **synthetic** certificate/key fixtures for a hostname such as `web.example.test`; use a dedicated trusted test CA. Never attach real TLS keys, kubeconfig or unredacted operational evidence to a public PR.
- Install Bash, Python 3.10+, kubectl, OpenSSL, age, age-keygen. Run `bash scripts/tls-secret-manager.sh doctor`.
- Prepare an age recovery identity using [the guide](AGE-RECOVERY.md), and protect its second copy. Ensure local evidence directories are private.
- Run `bash scripts/tls-secret-manager.sh wizard --plain` from this PR branch. For Create/Update/Delete choose **plan-only** first, then authorize an actual non-production mutation only after verifying the selected namespace and Secret.
- If Gateway API or cert-manager is not installed, mark corresponding cases **NOT RUN** with reason; never claim PASS for missing coverage.

## Acceptance matrix

| ID | Scenario | Expected outcome / evidence |
| --- | --- | --- |
| UAT-01 | Inventory / Expiry Audit / Toolbox Health with valid, expiring and malformed TLS Secret fixtures | Correct independent statuses, no TLS private key in output, no Secret mutation |
| UAT-02 | Create valid synthetic TLS Secret; repeat Create against same exact name | First `COMPLETE_SECRET_VERIFIED`; second STOP/AlreadyExists without overwrite |
| UAT-03 | Update same SAN with matching key; attempt mismatch SAN/key or mutated PEM between plan and write | Verified update and encrypted backup; invalid or drifted request STOP with old Secret unchanged |
| UAT-04 | Delete Secret referenced by active Ingress or Pod | `HOLD/SECRET_IN_USE`, named consumer shown, no executable plan or backup setup |
| UAT-05 | Delete Secret referenced only by Deployment scaled to zero or suspended CronJob | `HOLD/SECRET_IN_USE`; workload template named even with zero Pods |
| UAT-06 | Delete when listed workload or Gateway references are unreadable due to restricted RBAC | `HOLD/DEPENDENCY_SCAN_INCOMPLETE` or fail-closed STOP; never declare Secret UNUSED |
| UAT-07 | Delete when a cross-namespace Gateway certificateRef targets the Secret | `HOLD/SECRET_IN_USE`, gateway identified |
| UAT-08 | Delete controller-owned, cert-manager annotated or finalizer-bearing Secret | `HOLD/CONTROLLER_MANAGED` |
| UAT-09 | Delete truly isolated Secret, all lists accessible, external consumers checked and operator types UNUSED and exact DELETE target | age backup locally decrypted and compared **before** write, UID/RV precondition sent, journal `COMPLETE_ABSENCE_VERIFIED`, Secret actually absent |
| UAT-10 | Simulated timeout / unknown result during a write; rerun old plan | `MUTATION_UNCERTAIN`, no automatic retry; reconciliation reports original/current observation without claiming write success |
| UAT-11 | Recovery from verified Delete with original plan, backup, journal and matching age identity | Read-only reconciliation first, exact RESTORE confirmation; create-only Restore verifies restored data/fingerprint and new UID |
| UAT-12 | Recovery with missing/wrong age identity, uncertain journal, replaced namespace UID or already-existing Secret | STOP / HOLD; absolutely no Kubernetes write |
| UAT-13 | DNS resolves to previous cluster's LB, explicit connect IP selects new cluster LB | TLS Doctor retains hostname and SNI, displays each connect target and independent fingerprint; no automatic rotation/rollback |
| UAT-14 | Cancel wizard or choose plan-only; invalid command, missing tools, or unsafe evidence key permissions | No Kubernetes mutation and clear operator guidance |
| UAT-15 | Inspect generated plan/journal/evidence | Files private, no cleartext `tls.key` or age identity, correct context/namespace/plan ID |

## Human execution sequence

1. **Read-only:** UAT-01, UAT-04 through UAT-08, UAT-13, UAT-14.
2. **Non-destructive lifecycle:** UAT-02, UAT-03 (using disposable material).
3. **Destructive/recovery drill:** UAT-09, UAT-11 and UAT-12, only after verifying backups and authorization.
4. **Failure injection:** UAT-10 using a disposable mocked API/proxy or controlled test cluster, **never** by interrupting a live production write.
5. **Evidence:** UAT-15; compare Kubernetes UID/resourceVersion and TLS fingerprints while keeping private data out of exported evidence.

For each scenario record: date/time, test operator, isolated kubecontext, test fixture reference, commit SHA, expected result, observed status, sanitized evidence path, verdict (`PASS`, `FAIL`, `HOLD`, `NOT RUN`) and any issue created. Do not change application configurations or strip security checks merely to obtain a PASS.

**Operational acceptance criterion:** all applicable P0 safety scenarios PASS, and any HOLD/NOT RUN is reviewed explicitly before **production use**. A versioned public **source release** may be published after offline quality/security checks, but this is not evidence of cluster UAT acceptance. Synthetic GitHub Actions checks are a prerequisite, **not** UAT completion.
