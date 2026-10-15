# Security Policy

KAORI TLS Certificate Manager operates on sensitive Kubernetes TLS Secret material. Please treat credentials, kubeconfigs, certificate private keys, approval evidence, recovery identities and operational plans as confidential.

## Supported versions

| Source | Security support |
| --- | --- |
| Development preview (**0.1.0-dev**) | Best-effort review only; **no production security assurance** |
| Published stable releases | None yet; supported versions will be listed here when released |

Offline tests do not establish real-cluster acceptance. There is currently **no guaranteed security response SLA, embargo policy or production support window**.

## Report a vulnerability privately

**Do not open a public issue or pull request that discloses an exploitable weakness, real cluster identifiers, PEM private keys or attack evidence.**

1. If GitHub **private vulnerability reporting** is enabled for this repository, use **Security → Advisories → Report a vulnerability** on the [repository](https://github.com/OXY7O/kaori-tls-secret-manager) and submit a minimal sanitized reproduction.
2. If that feature is unavailable, contact a repository maintainer **through a private method listed on their GitHub profile** before sharing details. Do not publish an exploit just because a private channel is temporarily unavailable.
3. Describe the affected version/commit, preconditions, impact and expected behavior, and use synthetic fixtures wherever possible. **Never transmit a real recovery identity or private key.**

Maintainers will assess reports and coordinate a fix/disclosure when possible; no specific response time is promised.

## Operator security expectations

- Use only an authorized kubeconfig context and minimum required namespace-scoped RBAC.
- Do not store private evidence, Kubernetes Secret data, age recovery identities, signed approvals, kubeconfig or real PEM material in the repository or public CI artifacts.
- Keep private workspaces outside the source checkout, with restrictive permissions. Backups encrypted with age are not recoverable if the necessary identity is lost; maintain independent secure custody.
- The normal **single-operator interactive wizard** uses deliberate, local human confirmation. Create and Delete do **not** require separate detached signature files in this mode.
- The **non-interactive enterprise workflow** supports independent signed approval and a protected approver public trust anchor; do not bypass its trust boundary.
- Treat unknown API results, context or resource identity drift, RBAC gaps, failed backups and uncertain dependency scans as **STOP/HOLD**. Reconcile before taking further action; never blindly retry a mutation.
- Delete requires live API UID/resourceVersion preconditions plus dependency/owner checks. Ingress, Pod and Gateway scans do **not** prove that external consumers are absent; the operator must review them separately and explicitly attest to their absence.
- A successful readback of stored TLS Secret material does **not** prove that an endpoint or old load balancer presents that certificate. Confirm SNI, trust and the served fingerprint separately.

## Current limitations

- The complete application is on a development branch and has not completed independent security/privacy review and real DEV/UAT acceptance after transfer.
- Encrypted backup **restore on real infrastructure** and compatibility across kubectl/Kubernetes combinations are not yet release-accepted.
- No automated bulk Delete, force-delete mode, ACME issuance, unattended writes or automatic rollback.
- The advanced renewal workflow and single-target CRUD Update have different operational interfaces; read the [operator guide](docs/OPERATOR-GUIDE.md) before using either.

For contribution rules and non-sensitive bug reports, see [CONTRIBUTING.md](CONTRIBUTING.md) and [SUPPORT.md](SUPPORT.md).
