#!/usr/bin/env python3
"""KAORI TLS Ops Toolkit: read-only Kubernetes TLS audit and diagnostics.

All commands only perform kubectl GET/LIST, TLS handshakes, and write local
metadata-only reports. They never print, export, or store TLS private keys.
"""
import argparse
import base64
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import uuid

from tls_secret_manager import (
    Stop, check, kube_json, ingress_references, old_info, cert_details,
    covers, probe_https_endpoint, secret, plan_id, run, tls_secret_names,
)

UTC = timezone.utc


def atomic_evidence(root, stem, rows, *, fields=None):
    root = Path(root).expanduser()
    check(not root.is_symlink(), "Output directory cannot be symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = stem + "-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    location = root / name
    location.mkdir(mode=0o700)
    path = location / ("results.csv" if fields else "results.json")
    # The evidence directory is private; create each file private as well,
    # even if the caller's umask is unexpectedly permissive.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as stream:
        if fields:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        else:
            json.dump(rows, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    return path


def validate_stored_tls(obj, warn_days=30, now=None, ca_bundle=None):
    """Accurate leaf/key check. Trust/served HTTPS is a separate concern."""
    now = now or datetime.now(UTC)
    metadata = obj.get("metadata") or {}
    output = {
        "namespace": metadata.get("namespace", ""),
        "secret_name": metadata.get("name", ""),
        "uid": metadata.get("uid", ""),
        "resource_version": metadata.get("resourceVersion", ""),
        "status": "INVALID", "key_match": "UNKNOWN",
        "trust_status": "NOT_CHECKED", "endpoint_status": "NOT_CHECKED",
        "not_before": "", "not_after": "", "days_remaining": "",
        "subject": "", "issuer": "", "san": "", "fingerprint_sha256": "",
        "reason": "",
    }
    if obj.get("type") != "kubernetes.io/tls":
        output["reason"] = "Not a kubernetes.io/tls Secret"
        return output
    try:
        data = obj.get("data") or {}
        check("tls.crt" in data and "tls.key" in data, "Missing tls.crt or tls.key")
        leaf = base64.b64decode(data["tls.crt"], validate=True)
        key = base64.b64decode(data["tls.key"], validate=True)
        cert = cert_details(leaf)
        output.update({
            "subject": cert["subject"], "issuer": cert["issuer"],
            "san": ";".join(cert["sans"]),
            "fingerprint_sha256": cert["fingerprint"],
            "not_before": cert["not_before"], "not_after": cert["not_after"],
        })
        remaining = datetime.fromisoformat(cert["not_after"]) - now
        # Whole days remaining: floor, but expired is established by instant not integer.
        output["days_remaining"] = max(0, int(remaining.total_seconds() // 86400)) if remaining.total_seconds() >= 0 else -1
        check(key, "Empty TLS private key")
        # Never place key on disk. openssl CLI only receives it through stdin.
        public = run(["openssl", "pkey", "-inform", "PEM", "-pubout", "-passin", "pass:"], payload=key)
        from tls_secret_manager import digest
        output["key_match"] = "MATCH" if digest(public) == cert["public_key_hash"] else "MISMATCH"
        if ca_bundle:
            from tls_secret_manager import pem_leaves
            try:
                check(Path(ca_bundle).is_file(), "Approved CA bundle missing")
                with tempfile.TemporaryDirectory() as tmp:
                    leaf_parts = pem_leaves(leaf)
                    path = Path(tmp) / "leaf.pem"
                    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                        stream.write(leaf_parts[0])
                    command = ["openssl", "verify", "-CAfile", str(ca_bundle)]
                    if len(leaf_parts) > 1:
                        intermediate = Path(tmp) / "untrusted-chain.pem"
                        with os.fdopen(os.open(intermediate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                            stream.write(b"".join(leaf_parts[1:]))
                        command.extend(["-untrusted", str(intermediate)])
                    run([*command, str(path)])
                output["trust_status"] = "TRUSTED"
            except (OSError, Stop, ValueError):
                output["trust_status"] = "UNTRUSTED_OR_INCOMPLETE"
                output["reason"] = "Certificate chain does not verify with approved CA"
        if output["key_match"] != "MATCH":
            output["status"] = "INVALID"
            output["reason"] = "Stored certificate and private key do not match"
        elif now < datetime.fromisoformat(cert["not_before"]):
            output["status"] = "NOT_YET_VALID"
            output["reason"] = "Certificate notBefore is in the future"
        elif now >= datetime.fromisoformat(cert["not_after"]):
            output["status"] = "EXPIRED"
            output["reason"] = "Certificate expired (notAfter in the past)"
        elif remaining.total_seconds() <= warn_days * 86400:
            output["status"] = "EXPIRING"
            output["reason"] = f"Certificate expires within {warn_days} days"
        else:
            output["status"] = "VALID"
            output["reason"] = "Stored leaf valid at current time and TLS key matches"
    except (Stop, ValueError, TypeError, KeyError, OSError) as exc:
        output["status"] = "INVALID"
        output["reason"] = "Malformed Secret TLS data or inaccessible public key"  # no key/PEM error dump
    return output


def inventory(ctx, namespaces, warn_days=30, ca_bundle=None):
    rows = []
    for ns in namespaces:
        refs = ingress_references(ctx, ns)
        for name in tls_secret_names(ctx, ns):
            obj = secret(ctx, ns, name)
            state = validate_stored_tls(obj, warn_days, ca_bundle=ca_bundle)
            hosts = [x["host"] for x in refs.get(obj["metadata"]["name"], [])]
            state["ingress_refs"] = len(hosts)
            sans = state["san"].split(";") if state["san"] else []
            state["ingress_san_status"] = (
                "NO_INGRESS" if not hosts else
                "MATCH" if all(any(covers(san, h) for san in sans) for h in hosts) else
                "MISMATCH"
            )
            rows.append(state)
    return sorted(rows, key=lambda x: (x["namespace"], x["secret_name"]))


def normalize_namespaces(ctx, text):
    ns = [x.strip() for x in re.split(r"[,\s]+", text or "") if x.strip()]
    check(bool(ns), "Supply at least one namespace")
    if ns == ["ALL"]:
        return sorted(x["metadata"]["name"] for x in kube_json(ctx, "get", "namespaces")["items"])
    check(len(ns) == len(set(ns)), "Duplicate namespaces")
    return ns


def owners_from_pods(ctx, ns, secret_name):
    """Read pod references only; does not inspect Secret contents."""
    consumers = []
    data = kube_json(ctx, "-n", ns, "get", "pods")
    for pod in data["items"]:
        spec = pod.get("spec") or {}
        name = pod["metadata"]["name"]
        for volume in spec.get("volumes") or []:
            src = volume.get("secret") or {}
            if src.get("secretName") == secret_name:
                consumers.append({"kind": "Pod", "name": name, "route": "volume/" + volume["name"]})
            projected = (volume.get("projected") or {}).get("sources") or []
            if any((p.get("secret") or {}).get("name") == secret_name for p in projected):
                consumers.append({"kind": "Pod", "name": name, "route": "projected/" + volume["name"]})
        for container in (spec.get("containers") or []) + (spec.get("initContainers") or []) + (spec.get("ephemeralContainers") or []):
            cname = container.get("name", "")
            if any((ref.get("secretRef") or {}).get("name") == secret_name for ref in container.get("envFrom") or []):
                consumers.append({"kind": "Pod", "name": name, "route": "envFrom/" + cname})
            if any(((ref.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name") == secret_name
                   for ref in container.get("env") or []):
                consumers.append({"kind": "Pod", "name": name, "route": "envSecret/" + cname})
        for ref in spec.get("imagePullSecrets") or []:
            if ref.get("name") == secret_name:
                consumers.append({"kind": "Pod", "name": name, "route": "imagePullSecret"})
    return consumers


def owners_from_workloads(ctx, ns, secret_name):
    """Include dormant workloads whose Pod templates still reference TLS Secrets."""
    data = kube_json(ctx, "-n", ns, "get",
                     "deployments.apps,statefulsets.apps,daemonsets.apps,"
                     "replicasets.apps,jobs.batch,cronjobs.batch")
    check(isinstance(data.get("items"), list), "Workload scan incomplete")
    results = []
    for workload in data["items"]:
        kind = workload.get("kind")
        check(kind in ("Deployment", "StatefulSet", "DaemonSet",
                       "ReplicaSet", "Job", "CronJob"), "Unexpected workload type")
        spec = workload.get("spec") or {}
        if kind == "CronJob":
            spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        pod_spec = (spec.get("template") or {}).get("spec")
        check(isinstance(pod_spec, dict), "Workload template missing PodSpec")
        refs = []
        for volume in pod_spec.get("volumes") or []:
            refs.append((volume.get("secret") or {}).get("secretName"))
            refs.extend((x.get("secret") or {}).get("name") for x in
                        (volume.get("projected") or {}).get("sources") or [])
        refs.extend(x.get("name") for x in pod_spec.get("imagePullSecrets") or [])
        for group in ("containers", "initContainers", "ephemeralContainers"):
            for container in pod_spec.get(group) or []:
                refs.extend((x.get("secretRef") or {}).get("name")
                            for x in container.get("envFrom") or [])
                refs.extend(((x.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
                            for x in container.get("env") or [])
        if secret_name in refs:
            results.append({"kind": kind, "name": workload["metadata"]["name"],
                            "route": "Pod template (may be scaled to zero)"})
    return results


def discover_gateways(ctx, ns, secret_name):
    # Discovery first distinguishes CRD-not-installed from request/RBAC errors.
    types = run(["kubectl", "--context", ctx, "--request-timeout=20s",
                 "api-resources", "-o", "name"]).decode().splitlines()
    if "gateways.gateway.networking.k8s.io" not in types:
        return [], "NOT_INSTALLED"
    # Cross-namespace Gateway certificateRefs may target this namespace.
    objects = kube_json(ctx, "get", "gateways.gateway.networking.k8s.io", "-A")["items"]
    usages = []
    for g in objects:
        for listener in g.get("spec", {}).get("listeners") or []:
            tls = listener.get("tls") or {}
            for ref in tls.get("certificateRefs") or []:
                if (ref.get("name") == secret_name and
                    ref.get("kind", "Secret") == "Secret" and
                    ref.get("group", "") == "" and
                    ref.get("group", "") == "" and
                    ref.get("namespace", g["metadata"]["namespace"]) == ns):
                    usages.append({
                        "kind": "Gateway", "name": g["metadata"]["name"],
                        "route": "listener/" + listener.get("name", "?") +
                                 "/tls-mode-" + tls.get("mode", "Terminate"),
                    })
    return usages, "CHECKED"


def dependency_report(ctx, ns, name):
    obj = secret(ctx, ns, name)
    refs = ingress_references(ctx, ns).get(name, [])
    consumers = [{"kind": "Ingress", "name": ref["ingress"],
                  "route": "tls-host/" + ref["host"]} for ref in refs]
    checks = {"ingress": "CHECKED", "pods": "CHECKED",
              "workloads": "CHECKED", "gateway": "CHECKED"}
    # Fail closed for RBAC and failed API operations: do not label unused.
    consumers.extend(owners_from_pods(ctx, ns, name))
    consumers.extend(owners_from_workloads(ctx, ns, name))
    gateways, checks["gateway"] = discover_gateways(ctx, ns, name)
    consumers.extend(gateways)
    return {
        "namespace": ns, "secret_name": name, "uid": obj["metadata"]["uid"],
        "owner_references": [x.get("kind", "") + "/" + x.get("name", "")
                             for x in obj["metadata"].get("ownerReferences") or []],
        "cert_manager_annotation": (obj["metadata"].get("annotations") or {}).get(
            "cert-manager.io/certificate-name", ""),
        "known_consumers": consumers,
        "check_coverage": checks,
        "consumer_count": len(consumers),
        "limitation": "Observed Ingress, Gateway, Pod and standard workload templates checked. "
                      "Custom controllers, external LB, CSI and non-K8s consumers may exist.",
    }


def analyze_families(rows):
    groups = {}
    for r in rows:
        if r["status"] == "INVALID":
            continue
        key = r["san"]
        groups.setdefault(key, []).append(r)
    output = []
    for sans, group in sorted(groups.items()):
        fps = sorted({r["fingerprint_sha256"] for r in group})
        output.append({
            "san": sans, "secret_count": len(group),
            "fingerprint_variants": len(fps),
            "issuer_variants": len({r["issuer"] for r in group}),
            "namespaces": sorted({r["namespace"] for r in group}),
            "secrets": [r["namespace"] + "/" + r["secret_name"] for r in group],
            "fingerprints": fps,
            "status": "REVIEW_MIXED_ISSUANCE" if len(fps) > 1 else "ONE_ISSUANCE_LEAF",
            "note": "A matching SAN alone does not establish common certificate ownership.",
        })
    return output


def doctor(ctx, ns, name, hostname=None, port=443, connect_host=None, ca_bundle=None):
    obj = secret(ctx, ns, name)
    stored = validate_stored_tls(obj)
    refs = ingress_references(ctx, ns).get(name, [])
    check(not hostname or (isinstance(hostname, str) and
          bool(re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", hostname))),
          "Doctor hostname invalid")
    report = {
        "namespace": ns, "secret_name": name, "stored": stored,
        "ingress_hosts": [r["host"] for r in refs],
        "endpoint": {"status": "NOT_TESTED"},
        "diagnosis": [],
    }
    if stored["status"] in ("EXPIRED", "INVALID", "NOT_YET_VALID"):
        report["diagnosis"].append("Stored Secret certificate requires attention")
    if stored["key_match"] == "MISMATCH":
        report["diagnosis"].append("Stored tls.key does not match tls.crt")
    if hostname:
        # SSL context performs SNI, hostname and chain verification. A failure is not disguised as OK.
        try:
            live = probe_https_endpoint(hostname, connect_host or hostname, int(port), ca_bundle)
            same = live["fingerprint"] == stored["fingerprint_sha256"]
            report["endpoint"] = {"status": "MATCH" if same else "FINGERPRINT_MISMATCH",
                                  "hostname": hostname, "port": int(port),
                                  "connect_host": connect_host or hostname,
                                  "fingerprint": live["fingerprint"],
                                  "tls_version": live["tls_version"],
                                  "chain_hostname_verified": True}
            if not same:
                report["diagnosis"].append(
                    "HTTPS uses a different leaf from Kubernetes Secret. "
                    "Review Ingress controller or external TLS terminator; do not blindly renew.")
            if not any(covers(x["host"], hostname) for x in refs):
                report["diagnosis"].append(
                    "HTTPS hostname not found in this Secret's Ingress TLS references; "
                    "external consumer or wrong mapping is possible.")
        except (Stop, ssl.SSLError, OSError) as exc:
            report["endpoint"] = {"status": "TLS_HANDSHAKE_OR_TRUST_FAILURE",
                                  "hostname": hostname, "port": int(port),
                                  "error_type": type(exc).__name__}
            report["diagnosis"].append(
                "HTTPS handshake, SNI hostname or trust verification failed. "
                "Check DNS, chain, CA bundle, LB/proxy and endpoint reachability.")
    return report


def drift_report(ctx, namespaces, max_ips=4, ca_bundle=None):
    """Compare each concrete Ingress host with stored Secret and DNS A/AAAA targets.

    This is a live service probe, not just a Kubernetes Secret audit. It does not
    override externally-terminated TLS exceptions or assert they are harmless.
    """
    check(1 <= max_ips <= 16, "max_ips must be 1..16")
    results = []
    for ns in namespaces:
        mapped = ingress_references(ctx, ns)
        for secret_name, host_refs in sorted(mapped.items()):
            if not secret_name:
                continue
            obj = secret(ctx, ns, secret_name)
            stored = validate_stored_tls(obj)
            for ref in host_refs:
                host = ref["host"]
                base = {"namespace": ns, "secret_name": secret_name,
                        "ingress": ref["ingress"], "hostname": host,
                        "stored_fingerprint": stored["fingerprint_sha256"],
                        "stored_status": stored["status"]}
                if "*" in host or not host:
                    results.append({**base, "status": "WILDCARD_NEEDS_REAL_HOSTNAME",
                                    "connect_ip": "", "endpoint_fingerprint": ""})
                    continue
                try:
                    addresses = sorted({x[4][0] for x in socket.getaddrinfo(
                        host, 443, type=socket.SOCK_STREAM)})
                    check(bool(addresses), "No resolved DNS addresses")
                except (OSError, Stop):
                    results.append({**base, "status": "DNS_LOOKUP_FAILED",
                                    "connect_ip": "", "endpoint_fingerprint": ""})
                    continue
                for ip in addresses[:max_ips]:
                    try:
                        observed = probe_https_endpoint(host, ip, 443, ca_bundle)
                        matching = observed["fingerprint"] == stored["fingerprint_sha256"]
                        results.append({**base, "status": "MATCH" if matching else "MISMATCH",
                                        "connect_ip": ip, "endpoint_fingerprint": observed["fingerprint"]})
                    except (OSError, Stop, ssl.SSLError):
                        results.append({**base, "status": "HTTPS_VALIDATION_FAILED",
                                        "connect_ip": ip, "endpoint_fingerprint": ""})
                if len(addresses) > max_ips:
                    results.append({**base, "status": "DNS_IPS_NOT_ALL_TESTED",
                                    "connect_ip": "", "endpoint_fingerprint": ""})
    return {"context": ctx, "results": results,
            "safety": "READ_ONLY: mismatch may be legitimate external TLS termination; "
                      "review ownership before renewal or rollback."}


def check_run(ctx, plan_path):
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    check(plan_id(plan) == plan.get("plan_id"), "Plan identity mismatch")
    check(ctx == plan["context"], "Context different from original run")
    from tls_secret_manager import cluster_id
    check(cluster_id(ctx) == plan["cluster_uid"], "Cluster UID changed")
    journal_path = Path(plan_path).parent / "execution-journal.json"
    check(journal_path.is_file(), "No journal; renewal not executed")
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    check(journal.get("plan_id") == plan["plan_id"], "Journal differs from plan")
    items = {(i["namespace"], i["secret_name"]): i for i in journal.get("items", [])}
    rows = []
    for entry in plan["entries"]:
        key = (entry["namespace"], entry["secret_name"])
        obj = secret(ctx, *key)
        current = validate_stored_tls(obj)
        expected = plan["new_fingerprint"] if entry["status"] in ("READY", "SKIPPED") else entry["old_fingerprint"]
        post = items.get(key, {})
        same_uid = obj["metadata"]["uid"] == entry["uid"]
        fp_matches = current["fingerprint_sha256"] == expected
        if not same_uid:
            result = "UID_CHANGED"
        elif not fp_matches:
            result = "FINGERPRINT_DRIFT"
        elif entry["status"] == "READY" and not post.get("post_resource_version"):
            result = "UNCERTAIN_AFTER_WRITE"
        elif entry["status"] == "READY" and post.get("post_resource_version") != obj["metadata"]["resourceVersion"]:
            result = "RESOURCE_VERSION_CHANGED"
        else:
            result = "STORED_FINGERPRINT_MATCH"
        rows.append({"namespace": key[0], "secret_name": key[1],
                     "plan_status": entry["status"], "journal_status": post.get("status", "NOT_APPLICABLE"),
                     "check": result, "live_fingerprint": current["fingerprint_sha256"],
                     "expected_fingerprint": expected, "resource_version": obj["metadata"]["resourceVersion"]})
    return {"plan_id": plan["plan_id"], "journal_status": journal.get("status"),
            "checks": rows, "read_only": True,
            "next_step": "If uncertain or drift, stop; reconcile actual Secret state. "
                         "Never blindly replay renew or rollback."}


def default_metrics_cluster_label(context):
    """Make a Prometheus-safe, readable default from a kubectl context name.

    For common user@cluster names, use the cluster suffix rather than leaking
    the operator username into Prometheus labels. Nonstandard names are
    sanitized and get a deterministic suffix if truncation is necessary.
    Explicit --cluster-label always overrides this suggestion.
    """
    check(isinstance(context, str) and bool(context.strip()),
          "A Kubernetes context is required for the default metrics label")
    candidate = context.rsplit("@", 1)[-1] if "@" in context else context
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", candidate).strip("_.-")
    check(bool(safe), "Cannot derive a safe metrics label; specify --cluster-label")
    if len(safe) > 100:
        import hashlib
        safe = safe[:91].rstrip("_.-") + "-" + hashlib.sha256(
            context.encode("utf-8")).hexdigest()[:8]
    return safe


def prometheus_metrics(rows, cluster="unknown"):
    """Aggregates only; bounded cardinality, no secret values or private material."""
    check(bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", cluster)),
          "Invalid cluster label; use 1-100 letters, digits, dots, dashes or underscores")
    counter = {}
    for item in rows:
        state = item.get("status", "INVALID")
        check(state in ("VALID", "EXPIRING", "EXPIRED", "INVALID", "NOT_YET_VALID"),
              "Invalid inventory status")
        counter[state] = counter.get(state, 0) + 1
    escaped = cluster.replace("\\", "\\\\").replace('"', '\\"')
    lines = [
        "# HELP kaori_tls_secret_audit_status TLS Secret inventory by storage validity (not HTTPS availability).",
        "# TYPE kaori_tls_secret_audit_status gauge",
    ]
    for state in ("VALID", "EXPIRING", "EXPIRED", "NOT_YET_VALID", "INVALID"):
        lines.append(f'kaori_tls_secret_audit_status{{cluster="{escaped}",status="{state}"}} {counter.get(state,0)}')
    lines += [
        "# HELP kaori_tls_secret_audit_timestamp_seconds Epoch of last successful audit.",
        "# TYPE kaori_tls_secret_audit_timestamp_seconds gauge",
        f'kaori_tls_secret_audit_timestamp_seconds{{cluster="{escaped}"}} {int(datetime.now(UTC).timestamp())}',
    ]
    return "\n".join(lines) + "\n"


def cli():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--context", help="Explicit kubectl context for live read-only operations")
    p.add_argument("--namespaces", help="Comma-separated namespaces, or ALL (requires list namespaces permission)")
    p.add_argument("--output-dir", default=str(Path.home() / "k8s-tls-private" / "toolkit-reports"))
    sp = p.add_subparsers(dest="command", required=True)
    a = sp.add_parser("health")
    a.add_argument("--warn-days", type=int, default=30)
    a = sp.add_parser("families")
    a.add_argument("--warn-days", type=int, default=30)
    a = sp.add_parser("drift")
    a.add_argument("--max-ips", type=int, default=4)
    a.add_argument("--ca-bundle")
    a = sp.add_parser("dependencies")
    a.add_argument("--namespace", required=True)
    a.add_argument("--secret", required=True)
    a = sp.add_parser("doctor")
    a.add_argument("--namespace", required=True)
    a.add_argument("--secret", required=True)
    a.add_argument("--hostname")
    a.add_argument("--port", type=int, default=443)
    a.add_argument("--connect-host")
    a.add_argument("--ca-bundle")
    a = sp.add_parser("reconcile-run")
    a.add_argument("--plan", required=True)
    a = sp.add_parser("metrics")
    a.add_argument("--warn-days", type=int, default=30)
    a.add_argument("--cluster-label", help="Safe cluster metric label; defaults to context")
    args = p.parse_args()
    try:
        ctx = args.context
        if args.command in ("health", "families", "metrics"):
            check(ctx and args.namespaces, "--context and --namespaces required")
            names = normalize_namespaces(ctx, args.namespaces)
            check(0 <= args.warn_days <= 3650, "--warn-days outside 0..3650")
            rows = inventory(ctx, names, args.warn_days)
        else:
            check(ctx, "--context required for live diagnostics")
        if args.command == "drift":
            check(ctx and args.namespaces, "--context and --namespaces required")
            result = drift_report(ctx, normalize_namespaces(ctx, args.namespaces),
                                  args.max_ips, args.ca_bundle)
        elif args.command == "health":
            result = {"context": ctx, "namespaces": names, "targets": rows,
                      "scope": "stored-leaf-validity-and-private-key-only"}
        elif args.command == "families":
            result = {"context": ctx, "families": analyze_families(rows)}
        elif args.command == "dependencies":
            result = dependency_report(ctx, args.namespace, args.secret)
        elif args.command == "doctor":
            check(1 <= args.port <= 65535, "Invalid port")
            result = doctor(ctx, args.namespace, args.secret, args.hostname,
                            args.port, args.connect_host, args.ca_bundle)
        elif args.command == "reconcile-run":
            result = check_run(ctx, args.plan)
        elif args.command == "metrics":
            text = prometheus_metrics(rows, args.cluster_label or default_metrics_cluster_label(ctx))
            path = atomic_evidence(args.output_dir, "tls-metrics",
                                   {"metrics": text, "audit_source": "LIVE_KUBERNETES",
                                    "context": ctx, "namespaces": names,
                                    "scanned_utc": datetime.now(UTC).isoformat()})
            # Offline inventory replay is intentionally unsupported: it could
            # mint a misleading fresh audit timestamp for stale data.
            prom = path.with_name("kaori_tls.prom")
            with os.fdopen(os.open(prom, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
                f.write(text)
            print(f"METRICS: {prom}")
            print(f"EVIDENCE: {path}")
            return 0
        path = atomic_evidence(args.output_dir, args.command, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"EVIDENCE: {path}")
        return 0
    except (Stop, OSError, ValueError, KeyError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli())
