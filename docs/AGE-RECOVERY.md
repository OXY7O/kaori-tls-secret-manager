# age — encrypted recovery key setup and safe custody

**Audience:** one authorized operator using the KAORI terminal wizard. age encrypts the **original Kubernetes Secret snapshot** before an Update/Delete; it does not issue TLS certificates or replace cluster backups.

## Install age (Ubuntu / WSL2)

```bash
sudo apt update
sudo apt install -y age
command -v age
command -v age-keygen
age --version
bash scripts/tls-secret-manager.sh doctor
```

The supported runtime also needs Bash, Python 3.10+, OpenSSL and kubectl with an explicitly authorized context.

## Recommended: let the wizard set up your recovery identity

1. Launch `bash scripts/tls-secret-manager.sh wizard --plain`.
2. Select **Age setup / recovery help** for a read-only explanation (no cluster access).
3. Choose **Update TLS Secret** or **Delete TLS Secret**. The wizard scans the target and generates a read-only plan first. **HOLD or plan-only never creates an identity.**
4. If all checks pass, type **PROCEED** followed by the exact requested action/target.
5. If no protected identity exists, the wizard offers to create `~/.config/kaori-tls/recovery.agekey`. Type **SETUP**, then **RECOVERY** to acknowledge secure key custody. This is a one-time step; later operations reuse it.
6. KAORI derives the public age recipient, encrypts the original Secret in `*-backup.age`, decrypts it **in memory** to prove the backup matches the original, then and only then sends the requested Kubernetes write. The terminal does not print the decrypted payload or private key.
7. Preserve the journal, plan and `*.age` backup together in a private evidence store. Keep a **separate protected copy** of the age identity in a secured offline/vault location. If the identity is lost, those backups can become permanently unreadable.

Identity lookup order:
- `~/.config/age/k8s-tls-recovery.txt` — pre-existing legacy identity
- `~/.config/kaori-tls/recovery.agekey` — wizard-generated identity

Identity must be a regular non-symlink file with **0600** permissions; its directory should be **0700**.

## Optional: create the identity yourself before running KAORI

```bash
umask 077
install -d -m 700 "$HOME/.config/kaori-tls"
age-keygen -o "$HOME/.config/kaori-tls/recovery.agekey"
chmod 600 "$HOME/.config/kaori-tls/recovery.agekey"
age-keygen -y "$HOME/.config/kaori-tls/recovery.agekey"
```

The last command outputs a **public** recipient of the form `age1...`. It is safe to use as an encryption destination, but the private `recovery.agekey` must **never** be pasted into tickets, logs, chat messages or Git. Protect the second copy with organization-approved key custody controls. This is not a password-resettable service; KAORI does not escrow the key.

## What each file is for

| File | Purpose |
| --- | --- |
| `recovery.agekey` | Confidential age private identity used to decrypt a backup |
| `*-backup.age` | Encrypted original Secret (includes TLS private-key material inside the ciphertext) |
| `*-plan.json` | Original operation's immutable target and fingerprint evidence |
| `*-journal.json` | Write outcome, including whether an API result was uncertain |

**Successful Delete** ends in `COMPLETE_ABSENCE_VERIFIED`, not just a successful kubectl exit code. **MUTATION_UNCERTAIN** is neither success nor proof of failure. Never retry automatically or assume a deleted Secret is safe to recreate without checking current UID/resourceVersion and dependent workloads. A restore creates a new Kubernetes UID and can affect live consumers.

The wizard includes **Delete recovery / Restore**. Supply the original Delete plan path, context, namespace and Secret. It first runs **read-only** reconciliation of the live Secret UID, saved Delete journal and encrypted backup. It offers a single explicit RESTORE only when the original journal says `COMPLETE_ABSENCE_VERIFIED`, the Secret remains absent, and the original plan contains a pinned namespace UID. Existing Secret, different UID, uncertainty, missing backup/identity or older unpinned plans **HOLD**; there is no override or replay. Before creating, the backend decrypts the saved backup in memory, verifies original cluster/namespace/Secret UID/fingerprint and refuses to overwrite a concurrent create. The restore journal begins as `MUTATION_UNCERTAIN`; if write result is uncertain, stop and investigate instead of retrying. A successful restore creates a new Kubernetes UID and requires separate HTTPS and consumer checks. Never redirect decrypted Secret material to an unprotected file or terminal. Run a synthetic end-to-end restore drill on a disposable namespace before production use.

## Common troubleshooting

- `age-keygen: command not found`: install `age`, then run `doctor`.
- `Local recovery identity missing or unsafe`: check symlinks, directory permissions and 0600 key file mode.
- `Encrypted backup recovery verification failed`: **STOP**, no Kubernetes write should proceed.
- `MUTATION_UNCERTAIN`: do not retry. Inspect the journal and live target with a read-only reconciliation.
- `HOLD` during Delete: a Kubernetes dependency or insufficient RBAC must be resolved independently of age.

Read [Delete SOP](DELETE-TLS-SECRET-SOP.md), [Operator guide](OPERATOR-GUIDE.md), and [Security policy](../SECURITY.md) before production use.
