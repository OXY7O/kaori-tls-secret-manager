# TLS Toolbox: Metrics export and TLS Doctor

This guide covers **read-only** diagnostics in the original KAORI terminal UI.
Neither menu writes Kubernetes Secrets. Both read existing Secret data
to inspect certificate health; outputs are saved privately on the operator laptop.

## Metrics export (Toolbox > 5)

1. Open the KAORI wizard: `bash scripts/tls-secret-manager.sh wizard`.
2. Select **TLS Toolbox**, then **Metrics export**.
3. Select an approved Kubernetes context and one or more namespaces.
4. Press Enter for the default certificate expiration warning threshold (**30 days**) or enter another integer (0–3650).
5. Review **Prometheus cluster label**. When context is `admin@k8s-dev`,
   the suggested label is `k8s-dev`. Accept it with Enter or type a deliberate
   custom value using only `A-Z`, `a-z`, `0-9`, `_`, `.`, or `-`.
   The metric label is metadata **only**; it does not change the selected context.
6. KAORI writes a local `kaori_tls.prom` file plus `results.json` inside a
   unique directory under `~/k8s-tls-private/wizard-runs/toolkit-reports/`.
   The terminal prints the actual file paths.

Example generated text (illustrative counts only):

```prometheus
# HELP kaori_tls_secret_audit_status TLS Secret inventory by storage validity (not HTTPS availability).
# TYPE kaori_tls_secret_audit_status gauge
kaori_tls_secret_audit_status{cluster="k8s-dev",status="VALID"} 1
kaori_tls_secret_audit_status{cluster="k8s-dev",status="EXPIRING"} 0
kaori_tls_secret_audit_status{cluster="k8s-dev",status="EXPIRED"} 0
kaori_tls_secret_audit_status{cluster="k8s-dev",status="NOT_YET_VALID"} 0
kaori_tls_secret_audit_status{cluster="k8s-dev",status="INVALID"} 0
```

The output also contains `kaori_tls_secret_audit_timestamp_seconds`.
Metrics are **aggregate counts**, not per-Secret labels. `VALID` means stored
certificate validity, **not** healthy served HTTPS, matching keys, or CA trust.
Avoid sharing `results.json` from real internal clusters publicly.

KAORI does **not** push the file to Prometheus, enable scraping, or modify
Node Exporter. To ingest it, have the monitoring owner configure the approved
Node Exporter textfile collector (or equivalent exporter/collector) to pick up
an appropriate `.prom` file, and ensure the old file is refreshed on schedule.
Do not point Prometheus directly at the file path on your laptop.

### Equivalent read-only CLI

```bash
python3 scripts/kubernetes/tls-secret-manager/tls_ops.py \
  --context 'admin@k8s-dev' \
  --namespaces APPROVED_NAMESPACE \
  --output-dir "$HOME/k8s-tls-private/toolkit-reports" \
  metrics --cluster-label k8s-dev --warn-days 30
```

The explicit `--cluster-label` is optional on updated KAORI: the CLI also
derives a safe default from the selected context. On older commits, supply
`--cluster-label k8s-dev` to avoid `Invalid cluster label` with `@` in
the context name.

## TLS Doctor (Toolbox > 4)

1. Select **TLS Toolbox**, then **TLS Doctor**.
2. Choose the approved Kubernetes context and namespace(s).
3. Use the default expiry warning threshold (30 days) or enter a custom value.
4. Select **one TLS Secret** from the displayed list.
5. At **HTTPS hostname to check**, either:
   - press Enter: inspect the stored Secret only (no external HTTPS connection);
   - enter an approved concrete hostname: probe live HTTPS with SNI,
     hostname validation, certificate trust, and fingerprint comparison.
6. For a hostname probe, optionally provide the approved internal **CA bundle**
   path. Enter uses system trust only. The wizard can also accept a specific
   approved LB IP/host as the **connect target**. TLS SNI and hostname trust
   verification still use the original hostname, not the override.
   This is useful during migration while DNS points to the old cluster.
7. Review **Stored**, **HTTPS** and diagnosis lines. A JSON evidence file is
   written beneath `~/k8s-tls-private/wizard-runs/toolkit-reports/`.

Possible HTTPS states include `NOT_TESTED`, `MATCH`,
`FINGERPRINT_MISMATCH`, or `TLS_HANDSHAKE_OR_TRUST_FAILURE`.
A fingerprint mismatch can be legitimate if an external load balancer
terminates TLS; investigate ownership and endpoint mapping rather than
automatically renewing or rolling back.

### Equivalent read-only CLI

```bash
# Stored TLS Secret inspection only:
python3 scripts/kubernetes/tls-secret-manager/tls_ops.py \
  --context 'admin@k8s-dev' \
  --output-dir "$HOME/k8s-tls-private/toolkit-reports" \
  doctor --namespace APPROVED_NAMESPACE --secret APPROVED_TLS_SECRET

# Add --hostname and optionally --ca-bundle for a live HTTPS probe.
```

## Troubleshooting

- **`Invalid cluster label`** on Metrics export: use a recent commit, or
  supply an explicit `--cluster-label` matching `[A-Za-z0-9_.-]{1,100}`.
- **No Secrets found**: verify namespace selection, scoped RBAC, context and
  Secret type `kubernetes.io/tls`. Do not expand permissions automatically.
- **Trust or fingerprint mismatch** in TLS Doctor: confirm hostname, SNI,
  CA bundle and termination path; the tool does not auto-rotate certificates.
- **Missing Prometheus series**: file creation alone is not Prometheus
  ingestion. Check the approved collector configuration and scrape health.
