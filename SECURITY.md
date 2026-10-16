# Security Policy

KAORI TLS Certificate Manager operates on sensitive Kubernetes TLS Secret material. Please treat credentials, kubeconfigs, certificate private keys, approval evidence, recovery identities and operational plans as confidential.

## Supported versions

| Source | Security support |
| --- | --- |
| **v0.2.1** | Current public source release; best-effort vulnerability handling |
| **v0.2.0** | Previous source release; upgrade to v0.2.1 |
| **v0.1.1** | Previous source release; upgrade to v0.2.1 |
| **v0.1.0** | Historical source release; upgrade to v0.2.0 |
| **v0.1.0-rc.1** | Historical release candidate; upgrade to v0.2.0 |

GitHub Actions validates source behavior with synthetic tests and does not assess infrastructure outside the repository. There is **no guaranteed security response SLA or vendor certification**.

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
- The normal **single-operator interactive wizard** uses deliberate, local human confirmation. Create, Update and Delete do **not** require separate detached signature files in this mode.
- The **non-interactive enterprise workflow** supports independent signed approval and a protected approver public trust anchor; do not bypass its trust boundary.
- Treat unknown API results, context or resource identity drift, RBAC gaps, failed backups and uncertain dependency scans as **STOP/HOLD**. Reconcile before taking further action; never blindly retry a mutation.
- Delete requires live API UID/resourceVersion preconditions plus dependency/owner checks. Ingress, Pod, standard workload-template and Gateway scans do **not** prove that external consumers are absent; the operator must review them separately and explicitly attest to their absence.
- A successful readback of stored TLS Secret material does **not** prove that an endpoint or old load balancer presents that certificate. Confirm SNI, trust and the served fingerprint separately.

## Current limitations

- The public source distribution does not include an independent infrastructure security certification. Apply your organization’s change authorization, certificate policy and least-privilege requirements.
- Confirm encrypted backup restoration and supported `kubectl`/Kubernetes behavior in the intended environment before destructive operations.
- No automated bulk Delete, force-delete mode, ACME issuance, unattended writes or automatic rollback.
- The advanced renewal workflow and single-target CRUD Update have different operational interfaces; read the [operator guide](docs/OPERATOR-GUIDE.md) before using either.

For contribution rules and non-sensitive bug reports, see [CONTRIBUTING.md](CONTRIBUTING.md) and [SUPPORT.md](SUPPORT.md).
