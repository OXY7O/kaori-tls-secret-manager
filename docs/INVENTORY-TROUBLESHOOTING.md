# Inventory ALL troubleshooting (read-only)

## Meaning of INVENTORY_INCOMPLETE

KAORI manages Kubernetes **TLS Secrets** only, but Inventory ALL needs to inspect **Ingress and Secret objects in every selected namespace**. The read-only API operations are namespace LIST, Ingress LIST, Secret LIST metadata, and TLS Secret GET (followed by local certificate/key validation).

Any failed LIST/GET causes `INVENTORY_INCOMPLETE` and **no completed inventory report is created**. An API timeout is **not** a malformed TLS certificate. An `INVALID` inventory row means the stored certificate/key failed local validation after successful API retrieval.

The previous default `--request-timeout=20s` could be too short on larger clusters. Starting in v0.2.8, Inventory reads use:

| Setting | Default | Allowed |
| --- | ---: | ---: |
| Kubernetes API read timeout | 90 seconds | 20–300 |
| LIST chunk size | 100 objects | 10–500 |
| Extra retries for transient GET/LIST failures | 2 | 0–2 |

Retrials apply **only to Inventory GET/LIST** and are limited to timeout, interrupted response and known transient API errors. Access denial and non-transient failures stop immediately. TLS Secret **writes are never retried** by this feature.

## Adjust the Inventory wizard

The normal wizard requires no new prompts. For an unusually slow API server, start with:

```bash
bash scripts/tls-secret-manager.sh wizard --inventory-read-timeout-seconds 120
```

For a larger/unstable cluster:

```bash
bash scripts/tls-secret-manager.sh wizard \
  --inventory-read-timeout-seconds 120 \
  --inventory-chunk-size 100 \
  --inventory-read-retries 2
```

The direct read-only discovery command offers corresponding `--read-timeout-seconds`, `--chunk-size`, and `--read-retries` flags.

## Diagnose the exact failure (no write)

Use the **same context selected inside KAORI**, not blindly the shell's default:

```bash
CTX="CONTEXT_SELECTED_IN_KAORI"
kubectl --context "$CTX" auth can-i list namespaces
kubectl --context "$CTX" auth can-i list secrets --all-namespaces
kubectl --context "$CTX" auth can-i get secrets --all-namespaces
kubectl --context "$CTX" auth can-i list ingresses.networking.k8s.io --all-namespaces
```

A bare `kubectl auth can-i` is invalid: it needs **VERB RESOURCE**. All four `yes` results prove basic authorization, not that an actual API response will arrive before timeout.

For a namespace named in the KAORI error:

```bash
NS="NAMESPACE_FROM_ERROR"
kubectl --context "$CTX" --request-timeout=120s -n "$NS" \
  get secrets --chunk-size=100 -o name >/dev/null
kubectl --context "$CTX" --request-timeout=120s -n "$NS" \
  get ingresses.networking.k8s.io --chunk-size=100 -o name >/dev/null
```

Do not display full Kubernetes Secret JSON or share private key data. For repeat timeouts, review API-server responsiveness, network interruptions, API rate limits and response size. Do **not** widen RBAC for a proven timeout.

## Safe errors

Inventory errors identify **context, namespace, GET/LIST, resource, cause category, attempts**. Raw `kubectl` stderr is not forwarded, because it can contain sensitive cluster details. Causes include `TIMEOUT`, `TRANSIENT_API`, `ACCESS_DENIED`, `API_ERROR`, and `INVALID_API_RESPONSE`.

**No Secret changes, backups, rollbacks or retry of a write** occur as part of Inventory ALL. Failures are not treated as successful partial inventory. If your failed run already created private workspace folders, those directories are not evidence that an Inventory CSV is complete.
