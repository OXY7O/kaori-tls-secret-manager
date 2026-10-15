# Frequently asked questions

### Does KAORI issue or renew a certificate with a CA?

No. KAORI manages existing **kubernetes.io/tls** Secret material, including replacing an old certificate with a supplied, validated new PEM/fullchain and matching private key. It is not a CA, ACME client or replacement for cert-manager.

### Why can a valid TLS Secret have a different HTTPS fingerprint?

The hostname may still resolve to an older Kubernetes cluster, a proxy or load balancer may terminate TLS, or a rollout may be incomplete. Use **TLS Toolbox → TLS Doctor** with the exact hostname, approved CA trust and correct endpoint mapping. Do not rotate or roll back based solely on an endpoint mismatch.

### Why is Delete on HOLD when I can run kubectl delete manually?

KAORI intentionally prevents destructive writes if it finds Ingress TLS, Pod, Gateway API or controller references, finalizers, incomplete dependency visibility or drift. A HOLD is an explicit safety outcome, **not** a failure to bypass. Confirm the owner and remove legitimate references through your ordinary change process; generate a **new** plan when the live system is ready.

### Is an empty dependency scan proof that a Secret is unused?

No. External consumers such as load balancers, reverse proxies, scripts, integrations and out-of-cluster services may not be visible to Kubernetes reference scanners. Interactive Delete requires the operator to assert **UNUSED** based on external verification.

### Do I need an approver JSON/signature for the interactive wizard?

No. The normal guided Create/Delete paths run under one authorized operator with exact typed target/action confirmations. The independent signed-approval flow is for advanced non-interactive/enterprise integration.

### Why does Delete ask about an age recovery identity?

Delete takes an **encrypted backup** and locally verifies that it can be decrypted before the Kubernetes write. The identity is required for later restore; keep it protected and maintain a secure second copy outside your laptop. Do not paste it into issues or upload it to GitHub.

### Why does Reverify HTTPS say there are no previous runs?

**Reverify HTTPS** uses saved renewal evidence. For a *new* Secret or endpoint, use **TLS Toolbox → TLS Doctor**. See the [installation and verification guide](INSTALLATION.md).

### Does exported Prometheus data automatically appear in Prometheus?

No. KAORI saves a local **.prom** textfile with aggregate audit counts. A separately approved textfile collector or equivalent component must ingest it and keep it refreshed.

### Can KAORI be used in a production environment?

KAORI `v0.1.0` is publicly released source code, not a managed service or certified deployment. Use it only with appropriate Kubernetes permissions and change authorization. Before write operations, verify dependency discovery, backup restoration, endpoint ownership and your environment’s security policy; see the [operator guide](OPERATOR-GUIDE.md) and [release policy](RELEASE-POLICY.md).

### Where is the full CLI argument list?

Run **bash scripts/tls-secret-manager.sh --help**, **... crud --help**, or **... wizard --help** locally, and refer to [COMMAND-REFERENCE.md](COMMAND-REFERENCE.md).
