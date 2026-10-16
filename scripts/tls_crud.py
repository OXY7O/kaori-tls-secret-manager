#!/usr/bin/env python3
"""KAORI TLS Secret Manager: guarded Create, Read, Update and Delete.

Standalone Python stdlib + kubectl + openssl + age. No automatic writes:
plan -> interactive operator confirmation OR signed approval -> encrypted recovery -> API preconditions.
Single-target same-SAN Update is a guarded additional path; original batch renewal lives in the KAORI wizard.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

UTC = timezone.utc
TYPE = "kubernetes.io/tls"
DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?\Z")
DNS_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?\Z")


class Stop(Exception):
    """Fail closed; never render secret material in the exception message."""


class DeleteHold(Stop):
    """Read-only refusal with actionable, non-sensitive dependency evidence."""

    def __init__(self, reason, details):
        self.reason = reason
        self.details = sorted(set(details))
        super().__init__(f"Delete on HOLD: {reason}")


def require(condition: bool, message: str):
    if not condition:
        raise Stop(message)


def valid_target(namespace: str, name: str):
    require(bool(DNS_LABEL.fullmatch(namespace)) and len(namespace) <= 63,
            "Invalid namespace; expected DNS label")
    require(bool(DNS_NAME.fullmatch(name)) and len(name) <= 253
            and all(0 < len(label) <= 63 for label in name.split(".")),
            "Invalid Secret name; expected DNS subdomain")


def call(argv, *, payload=None, timeout=45):
    """No shell. Never print command output, stderr, PEM material or tokens."""
    try:
        result = subprocess.run([str(x) for x in argv], input=payload,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Stop(f"{argv[0]} failed or timed out; reconcile before retrying") from exc
    require(result.returncode == 0,
            f"{argv[0]} returned failure ({result.returncode}); reconcile before retrying")
    return result.stdout


def kube(context, *args, payload=None):
    require(bool(context) and context.strip() == context and
            not context.startswith("-") and not any(ch.isspace() for ch in context),
            "Explicit safe context name required")
    return call(["kubectl", "--context", context, "--request-timeout=20s", *args],
                payload=payload)


def kube_json(context, *args):
    try:
        return json.loads(kube(context, *args))
    except (UnicodeError, ValueError) as exc:
        raise Stop("Malformed Kubernetes API response") from exc


def private_workspace(root):
    path = Path(root).expanduser()
    require(not path.is_symlink(), "Workspace cannot be a symlink")
    path = path.resolve()
    repository = Path(__file__).resolve().parents[1]
    require(path != repository and repository not in path.parents,
            "Private evidence must remain outside the source repository")
    if path.exists():
        require(path.is_dir() and path.stat().st_mode & 0o077 == 0,
                "Existing workspace must be a private 0700 directory")
    else:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
    require(path.is_dir() and not path.is_symlink(),
            "Workspace must be a regular directory")
    return path


def atomic_json(path: Path, document: dict, *, replace=False):
    """0600 write in parent dir; no symlink target or outside path traversal."""
    require(not path.is_symlink(), "Refuse symlink output")
    if not replace:
        require(not path.exists(), "Refuse overwrite of prior plan or journal")
    contents = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex[:12])
    descriptor = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if not replace:
            # Exclusive destination creation guards accidental reuse of plan IDs.
            os.link(tmp, path)
        else:
            require(path.exists() and not path.is_symlink(),
                    "Journal missing or replaced with symlink")
            os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint_from_der_or_pem(cert: bytes):
    out = call(["openssl", "x509", "-inform", "PEM", "-outform", "DER"], payload=cert)
    return digest(out)


def validate_source(cert_path, key_path, ca_bundle=None):
    """Private PEM never lands in a log, JSON plan or subprocess arguments."""
    cert_file, key_file = Path(cert_path), Path(key_path)
    require(cert_file.is_file() and key_file.is_file() and not key_file.is_symlink(),
            "Certificate/key inputs must be regular files")
    require(not key_file.stat().st_mode & 0o077, "Private key permissions must be 0600")
    cert, key = cert_file.read_bytes(), key_file.read_bytes()
    require(b"-----BEGIN CERTIFICATE-----" in cert and b"-----BEGIN" in key,
            "Invalid PEM input")
    require(len(cert) <= 1_000_000 and len(key) <= 200_000,
            "Oversized certificate/key input")
    with tempfile.TemporaryDirectory(prefix="kaori-cert-") as directory:
        leaf = Path(directory) / "leaf.pem"
        leaf.write_bytes(cert)
        leaf.chmod(0o600)
        key_pub = call(["openssl", "pkey", "-pubout", "-passin", "pass:"], payload=key)
        cert_pub = call(["openssl", "x509", "-pubkey", "-noout"], payload=cert)
        require(digest(key_pub) == digest(cert_pub), "TLS certificate/private key mismatch")
        dates = call(["openssl", "x509", "-dates", "-noout"], payload=cert).decode("ascii")
        attrs = dict(line.split("=", 1) for line in dates.splitlines() if "=" in line)
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            before = datetime.strptime(attrs["notBefore"], fmt).replace(tzinfo=UTC)
            after = datetime.strptime(attrs["notAfter"], fmt).replace(tzinfo=UTC)
        except (KeyError, ValueError) as exc:
            raise Stop("Unparseable certificate validity") from exc
        require(before <= datetime.now(UTC) < after, "TLS certificate not currently valid")
        # A strict system/local CA check is a preflight guard; never bypass silently.
        verify = ["openssl", "verify", "-purpose", "sslserver"]
        blocks = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                            cert, flags=re.DOTALL)
        if len(blocks) > 1:
            intermediates = Path(directory) / "intermediates.pem"
            intermediates.write_bytes(b"\n".join(blocks[1:]) + b"\n")
            intermediates.chmod(0o600)
            verify += ["-untrusted", str(intermediates)]
        if ca_bundle:
            verify += ["-CAfile", str(Path(ca_bundle).expanduser().resolve())]
        verify.append(str(leaf))
        call(verify)
        santext = call(["openssl", "x509", "-noout", "-ext", "subjectAltName"],
                       payload=cert).decode("ascii")
        sans = sorted(set(re.findall(r"DNS:([^,\s]+)", santext)))
        require(bool(sans), "Missing DNS SAN in TLS certificate")
    return cert, key, {"fingerprint": fingerprint_from_der_or_pem(cert),
                       "sans": sans, "not_after": after.isoformat()}


def context_uid(context):
    node = kube_json(context, "get", "namespace", "kube-system", "-o", "json")
    uid = node.get("metadata", {}).get("uid", "")
    require(bool(uid), "Cannot establish cluster UID")
    return uid


def find_target(context, namespace, name):
    """List with field selector: fail on forbidden/RBAC; don't confuse it with NotFound."""
    payload = kube_json(context, "-n", namespace, "get", "secrets",
                        "--field-selector", f"metadata.name={name}", "-o", "json")
    entries = payload.get("items")
    require(isinstance(entries, list) and len(entries) <= 1,
            "Unexpected Secret list response")
    return entries[0] if entries else None


def list_tls_metadata(context, namespace):
    """Only X.509 metadata, not tls.key, is returned from the inspected list."""
    valid_target(namespace, "valid-name")
    listing = kube_json(context, "-n", namespace, "get", "secrets", "-o", "json")
    rows = []
    for entry in listing.get("items", []):
        if entry.get("type") != TYPE:
            continue
        meta = entry.get("metadata") or {}
        cert_b64 = (entry.get("data") or {}).get("tls.crt")
        status, fingerprint = "INVALID", None
        if cert_b64:
            try:
                certificate = base64.b64decode(cert_b64, validate=True)
                fingerprint = fingerprint_from_der_or_pem(certificate)
                status = "PARSED"
            except (Stop, ValueError, TypeError):
                pass
        rows.append({"namespace": namespace, "secret": meta.get("name"),
                     "uid": meta.get("uid"), "resource_version": meta.get("resourceVersion"),
                     "certificate_status": status, "fingerprint": fingerprint})
    return sorted(rows, key=lambda r: r["secret"] or "")


def assert_unmanaged(obj):
    meta = obj.get("metadata") or {}
    annotations = meta.get("annotations") or {}
    labels = meta.get("labels") or {}
    require(not meta.get("ownerReferences") and not meta.get("finalizers"),
            "Owner references/finalizers block decommission")
    require(not annotations.get("cert-manager.io/certificate-name"),
            "cert-manager controlled Secret must not be deleted")
    require(not labels.get("app.kubernetes.io/managed-by") or
            labels.get("app.kubernetes.io/managed-by") in ("manual", "Manual"),
            "Managed Secret requires controller review")


def owner_blockers(obj):
    """Explain managed ownership without displaying any Secret payload."""
    meta = obj.get("metadata") or {}
    annotations = meta.get("annotations") or {}
    labels = meta.get("labels") or {}
    blocked = []
    for ref in meta.get("ownerReferences") or []:
        blocked.append("Controller owner: " + str(ref.get("kind") or "unknown")
                       + "/" + str(ref.get("name") or "unknown"))
    for entry in meta.get("finalizers") or []:
        blocked.append("Finalizer: " + str(entry))
    if annotations.get("cert-manager.io/certificate-name"):
        blocked.append("cert-manager Certificate: "
                       + str(annotations["cert-manager.io/certificate-name"]))
    manager = labels.get("app.kubernetes.io/managed-by")
    if manager and manager not in ("manual", "Manual"):
        blocked.append("Managed by: " + str(manager))
    return sorted(set(blocked))


def pod_spec_references_secret(spec, secret_name):
    """Inspect all standard PodSpec paths without accessing Secret values."""
    require(isinstance(spec, dict), "Malformed Pod/workload spec in dependency scan")
    names = []
    for volume in spec.get("volumes") or []:
        names.append((volume.get("secret") or {}).get("secretName"))
        for projection in (volume.get("projected") or {}).get("sources") or []:
            names.append((projection.get("secret") or {}).get("name"))
    names.extend(ref.get("name") for ref in spec.get("imagePullSecrets") or [])
    for container_kind in ("containers", "initContainers", "ephemeralContainers"):
        for container in spec.get(container_kind) or []:
            names.extend((v.get("secretRef") or {}).get("name")
                         for v in container.get("envFrom") or [])
            names.extend(((v.get("valueFrom") or {}).get("secretKeyRef") or {}).get("name")
                         for v in container.get("env") or [])
    return secret_name in names


def workload_template(item):
    """Return PodSpec from workload templates, including dormant CronJobs."""
    kind = item.get("kind")
    spec = item.get("spec") or {}
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    require(kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"),
            "Unknown workload type in dependency scan")
    template = (spec.get("template") or {})
    require(isinstance(template.get("spec"), dict),
            "Malformed workload Pod template in dependency scan")
    return template["spec"]


def dependency_evidence(context, namespace, name, *, detailed=False):
    """Find Kubernetes Secret consumers; fail closed on incomplete API visibility."""
    ingress = kube_json(context, "-n", namespace, "get", "ingresses.networking.k8s.io", "-o", "json")
    pods = kube_json(context, "-n", namespace, "get", "pods", "-o", "json")
    blockers = []

    def found(kind, item, generic):
        if detailed:
            meta = item.get("metadata") or {}
            item_namespace = meta.get("namespace") or namespace
            item_name = meta.get("name") or "(unknown)"
            blockers.append(f"{kind}: {item_namespace}/{item_name}")
        else:
            blockers.append(generic)

    for item in ingress.get("items", []):
        if any(e.get("secretName") == name for e in item.get("spec", {}).get("tls", [])):
            found("Ingress TLS reference", item, "Ingress TLS reference")
    for pod in pods.get("items", []):
        if pod_spec_references_secret(pod.get("spec"), name):
            found("Pod dependency", pod, "Pod dependency")

    # A scale-to-zero Deployment, suspended CronJob or future ReplicaSet may
    # reference this Secret while currently having zero Pods. Never infer unused
    # from an empty Pod list. Missing list/RBAC visibility must fail closed.
    workloads = kube_json(context, "-n", namespace, "get",
                          "deployments.apps,statefulsets.apps,daemonsets.apps,"
                          "replicasets.apps,jobs.batch,cronjobs.batch", "-o", "json")
    require(isinstance(workloads.get("items"), list),
            "Incomplete workload template listing")
    for item in workloads["items"]:
        if pod_spec_references_secret(workload_template(item), name):
            found(str(item["kind"]) + " template reference", item,
                  "Workload template reference")

    resources = kube(context, "api-resources", "--api-group=gateway.networking.k8s.io",
                     "-o", "name").decode("utf-8")
    # Match an entire API resource name; prefix/substrings are not valid CRDs.
    if any(resource == "gateways.gateway.networking.k8s.io"
           for resource in resources.splitlines()):
        gateways = kube_json(context, "get", "gateways.gateway.networking.k8s.io", "-A", "-o", "json")
        for gw in gateways.get("items", []):
            for listener in (gw.get("spec", {}).get("listeners") or []):
                for ref in (listener.get("tls", {}).get("certificateRefs") or []):
                    if (ref.get("name") == name and
                        (ref.get("namespace") or gw["metadata"]["namespace"]) == namespace and
                        ref.get("kind", "Secret") == "Secret" and
                        ref.get("group", "") == ""):
                        found("Gateway TLS certificateRef", gw, "Gateway TLS certificateRef")
    return sorted(set(blockers))


def read_plan(path):
    source = Path(path).expanduser()
    require(not source.is_symlink(), "Refuse symlink plan")
    planfile = source.resolve()
    require(planfile.is_file() and planfile.name.endswith("-plan.json"), "Invalid plan path")
    plan = json.loads(planfile.read_text(encoding="utf-8"))
    require(plan.get("schema_version") == 1 and plan.get("plan_id") ==
            digest(canonical({k: v for k, v in plan.items() if k != "plan_id"}))[:24],
            "Plan integrity mismatch")
    created = datetime.fromisoformat(plan["created_utc"])
    require(timedelta(0) <= datetime.now(UTC) - created < timedelta(minutes=30),
            "Plan expired or clock skew detected")
    return planfile, plan


def write_plan(root, obj):
    obj["schema_version"] = 1
    obj["created_utc"] = datetime.now(UTC).isoformat()
    obj["plan_id"] = digest(canonical(obj))[:24]
    directory = private_workspace(root)
    path = directory / f"{obj['action'].lower()}-{obj['plan_id']}-plan.json"
    atomic_json(path, obj)
    return path, obj


def ingress_hosts(context, namespace, name):
    ing = kube_json(context, "-n", namespace, "get", "ingresses.networking.k8s.io", "-o", "json")
    return sorted({host for item in ing.get("items", [])
                   for entry in item.get("spec", {}).get("tls", [])
                   if entry.get("secretName") == name
                   for host in entry.get("hosts", [])})


def san_covers(san, host):
    """X.509 DNS wildcard matches exactly one left-most label."""
    pat, name = san.lower().rstrip("."), host.lower().rstrip(".")
    if pat.startswith("*."):
        return name.endswith(pat[1:]) and name.count(".") == pat.count(".")
    return pat == name


def certificate_sans(cert):
    text = call(["openssl", "x509", "-noout", "-ext", "subjectAltName"], payload=cert)
    return sorted(set(re.findall(r"DNS:([^,\s]+)", text.decode("ascii"))))


def plan_update(args):
    """Single-target certificate rotation, preserving exact SAN identity by default."""
    valid_target(args.namespace, args.secret)
    _, _, info = validate_source(args.cert, args.key, args.ca_bundle)
    original = find_target(args.context, args.namespace, args.secret)
    require(original is not None and original.get("type") == TYPE,
            "Update requires an existing Kubernetes TLS Secret")
    assert_unmanaged(original)
    require(original.get("immutable") is not True, "Immutable Secret cannot be updated")
    meta = original.get("metadata") or {}
    uid, rv = meta.get("uid"), meta.get("resourceVersion")
    require(bool(uid and rv), "Existing target UID/resourceVersion missing")
    cert_old = base64.b64decode((original.get("data") or {}).get("tls.crt", ""), validate=True)
    require(sorted(info["sans"]) == certificate_sans(cert_old),
            "Update refuses SAN identity change; use a separate reviewed workflow")
    hosts = ingress_hosts(args.context, args.namespace, args.secret)
    require(all(any(san_covers(san, h) for san in info["sans"]) for h in hosts),
            "Replacement certificate does not cover configured Ingress hostname")
    old_fp = fingerprint_from_der_or_pem(cert_old)
    require(old_fp != info["fingerprint"],
            "TLS Secret already presents replacement certificate; no update needed")
    return write_plan(args.workspace, {"action": "UPDATE", "context": args.context,
        "cluster_uid": context_uid(args.context), "namespace": args.namespace,
        "secret": args.secret, "uid": uid, "resource_version": rv,
        "old_fingerprint": old_fp, "new_fingerprint": info["fingerprint"],
        "cert_sha256": digest(Path(args.cert).read_bytes()),
        "key_sha256": digest(Path(args.key).read_bytes()),
        "ingress_hosts": hosts, "requires_encrypted_backup": True})


def plan_create(args):
    valid_target(args.namespace, args.secret)
    _, _, info = validate_source(args.cert, args.key, args.ca_bundle)
    uid = context_uid(args.context)
    require(find_target(args.context, args.namespace, args.secret) is None,
            "Target Secret already exists; Create never overwrites")
    # Verify namespace reads independently, but do not assume access implies creation rights.
    ns = kube_json(args.context, "get", "namespace", args.namespace, "-o", "json")
    require(ns.get("metadata", {}).get("name") == args.namespace, "Namespace missing")
    namespace_uid = ns.get("metadata", {}).get("uid")
    require(bool(namespace_uid), "Namespace UID missing")
    # Require configured Ingress TLS hostnames to be included in SAN.
    hosts = ingress_hosts(args.context, args.namespace, args.secret)
    for host in hosts:
        require(any(san_covers(san, host) for san in info["sans"]),
                "Certificate SAN does not cover configured Ingress hostname")
    return write_plan(args.workspace, {"action": "CREATE", "context": args.context,
                                       "cluster_uid": uid, "namespace": args.namespace,
                                       "secret": args.secret, "namespace_uid": namespace_uid,
                                       "new_fingerprint": info["fingerprint"],
                                       "cert_sha256": digest(Path(args.cert).read_bytes()),
                                       "key_sha256": digest(Path(args.key).read_bytes()),
                                       "ingress_hosts": hosts, "expires_at": info["not_after"]})


def plan_delete(args):
    valid_target(args.namespace, args.secret)
    obj = find_target(args.context, args.namespace, args.secret)
    require(obj is not None and obj.get("type") == TYPE,
            "Target TLS Secret absent or wrong type")
    owners = owner_blockers(obj)
    if owners:
        raise DeleteHold("CONTROLLER_MANAGED", owners)
    try:
        blocked = dependency_evidence(args.context, args.namespace, args.secret,
                                      detailed=True)
    except Stop:
        # Unknown status must NEVER be interpreted as free for deletion.
        raise DeleteHold("DEPENDENCY_SCAN_INCOMPLETE",
                         ["Cannot fully inspect cluster references with current RBAC/API access"])
    if blocked:
        raise DeleteHold("SECRET_IN_USE", blocked)
    meta = obj.get("metadata", {})
    uid, rv = meta.get("uid"), meta.get("resourceVersion")
    require(bool(uid and rv), "Secret UID or resourceVersion missing")
    pem = base64.b64decode(obj.get("data", {}).get("tls.crt", ""), validate=True)
    fp = fingerprint_from_der_or_pem(pem)
    return write_plan(args.workspace, {"action": "DELETE", "context": args.context,
                                       "cluster_uid": context_uid(args.context),
                                       "namespace": args.namespace, "secret": args.secret,
                                       "uid": uid, "resource_version": rv,
                                       "old_fingerprint": fp, "dependencies": "NONE_OBSERVED",
                                       "requires_external_owner_attestation": True})


def save_delete_hold(args, hold):
    """Save non-executable HOLD evidence, not a reusable deletion plan."""
    root = private_workspace(args.workspace)
    path = root / f"delete-hold-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid.uuid4().hex[:8]}.json"
    atomic_json(path, {"status": "HOLD", "reason": hold.reason,
                       "context": args.context, "namespace": args.namespace,
                       "secret": args.secret, "observed_utc": datetime.now(UTC).isoformat(),
                       "blockers": hold.details,
                       "note": "No deletion plan created. Re-run checks after resolving blockers."})
    return path


def validate_approval(args, plan):
    require(args.approve == plan["plan_id"], "Wrong PLAN ID")
    label = f"{plan['namespace']}/{plan['secret']}"
    require(args.confirm_target == label, "Target confirmation mismatch")
    if getattr(args, "operator_mode", False):
        # Explicit human-in-terminal workflow for a single authorized operator.
        # This is NEVER the default for machine-to-machine/automation calls.
        require(sys.stdin.isatty(), "Single-operator approval requires an interactive terminal")
        require(getattr(args, "operator_ack", None) == f"{plan['action']} {label}",
                "Exact typed operation/target confirmation is required")
        if plan["action"] == "DELETE":
            require(getattr(args, "operator_attested", False),
                    "Confirm there are no external consumers before Delete")
        return
    require(bool(getattr(args, "approval_record", None) and
                 getattr(args, "approval_signature", None) and
                 getattr(args, "approval_trust_key", None)),
            "Signed approval and anchored trust public key required")
    record = Path(args.approval_record)
    signature = Path(args.approval_signature)
    trust = Path(args.approval_trust_key)
    require(record.is_file() and signature.is_file() and trust.is_file() and not trust.is_symlink(),
            "Signed approval and anchored trust public key required")
    stat = trust.stat()
    require(stat.st_uid == 0 and (stat.st_mode & 0o022) == 0,
            "Approver public key must be root-owned and not writable by others")
    approval = json.loads(record.read_text(encoding="utf-8"))
    require(approval.get("action") == plan["action"] and
            approval.get("plan_id") == plan["plan_id"] and
            approval.get("context") == plan["context"] and
            approval.get("cluster_uid") == plan["cluster_uid"] and
            approval.get("target") == args.confirm_target and
            bool(approval.get("change_reference")) and
            bool(approval.get("approver")), "Signed approval scope mismatch")
    require(approval.get("external_consumer_attested") is True,
            "External consumer owner attestation is required")
    try:
        approved = datetime.fromisoformat(approval["approved_utc"])
        expires = datetime.fromisoformat(approval["expires_utc"])
        require(approved.tzinfo is not None and expires.tzinfo is not None and
                approved <= datetime.now(UTC) < expires and expires - approved <= timedelta(hours=1),
                "Approval expired, not current, or too long-lived")
    except (KeyError, TypeError, ValueError) as exc:
        raise Stop("Invalid approval validity") from exc
    call(["openssl", "dgst", "-sha256", "-verify", trust, "-signature", signature, record])


def ensure_same_target(plan):
    require(context_uid(plan["context"]) == plan["cluster_uid"],
            "Cluster UID changed")
    obj = find_target(plan["context"], plan["namespace"], plan["secret"])
    if plan["action"] == "CREATE":
        require(obj is None, "Target appeared since Create plan")
        namespace = kube_json(plan["context"], "get", "namespace",
                              plan["namespace"], "-o", "json")
        require(namespace.get("metadata", {}).get("uid") == plan["namespace_uid"],
                "Namespace identity changed since Create plan")
    else:
        require(obj is not None and obj.get("type") == TYPE,
                "Delete target disappeared or type changed")
        assert_unmanaged(obj)
        meta = obj.get("metadata", {})
        require(meta.get("uid") == plan["uid"] and
                meta.get("resourceVersion") == plan["resource_version"],
                "Delete target identity drifted")
        pem = base64.b64decode(obj.get("data", {}).get("tls.crt", ""), validate=True)
        require(fingerprint_from_der_or_pem(pem) == plan["old_fingerprint"],
                "Delete target certificate fingerprint changed")
        if plan["action"] == "DELETE":
            require(not dependency_evidence(plan["context"], plan["namespace"], plan["secret"]),
                    "New dependency appeared after plan")
        elif plan["action"] == "UPDATE":
            require(obj.get("immutable") is not True,
                    "Immutable Secret cannot be updated")
            require(ingress_hosts(plan["context"], plan["namespace"], plan["secret"]) ==
                    plan["ingress_hosts"], "Ingress references changed since Update plan")
    return obj


def age_backup(original, destination, recipient):
    require(recipient.startswith("age1") and len(recipient) > 20,
            "Invalid age backup recipient")
    require(not destination.exists() and not destination.is_symlink(),
            "Backup target exists or is symlink")
    content = canonical(original)  # Includes sensitive data, written only to encrypted backup.
    call(["age", "-r", recipient, "-o", destination], payload=content)
    require(destination.is_file() and destination.stat().st_size > 0,
            "Encrypted backup missing; STOP")
    destination.chmod(0o600)
    return destination


def apply(args):
    planfile, plan = read_plan(args.plan)
    require(plan["action"] == args.action, "Wrong plan operation")
    require(args.context == plan["context"] and args.namespace == plan["namespace"]
            and args.secret == plan["secret"],
            "Command target/context does not match immutable plan")
    valid_target(plan["namespace"], plan["secret"])
    directory = planfile.parent
    journal = directory / f"{plan['action'].lower()}-{plan['plan_id']}-journal.json"
    require(not journal.exists() and not journal.is_symlink(),
            "Prior execution journal exists; reconcile; never replay")
    validate_approval(args, plan)
    original = ensure_same_target(plan)
    cert, key = None, None
    if args.action in ("CREATE", "UPDATE"):
        require(args.cert and args.key, "Create/Update requires certificate and key files")
        cert, key, info = validate_source(args.cert, args.key, args.ca_bundle)
        require(info["fingerprint"] == plan["new_fingerprint"] and
                digest(cert) == plan["cert_sha256"] and digest(key) == plan["key_sha256"],
                "PEM inputs changed since operation plan")
        require(ingress_hosts(plan["context"], plan["namespace"], plan["secret"]) ==
                plan["ingress_hosts"], "Ingress references changed since plan")
    if args.action in ("UPDATE", "DELETE"):
        require(args.backup_recipient, "Update/Delete requires encrypted age backup recipient")
        encrypted = age_backup(
            original, directory / f"{plan['action'].lower()}-{plan['plan_id']}-backup.age",
            args.backup_recipient)
        if getattr(args, "operator_mode", False):
            recovery_identity = Path(getattr(args, "backup_identity", "") or "").expanduser()
            require(recovery_identity.is_file() and not recovery_identity.is_symlink() and
                    recovery_identity.stat().st_mode & 0o077 == 0,
                    "Protected local recovery identity required for backup verification")
            # Verify real decryptability BEFORE sending a Kubernetes write.
            # Decrypted Secret contents remain in memory, never in output logs.
            decrypted = call(["age", "-d", "-i", recovery_identity, encrypted])
            require(decrypted == canonical(original),
                    "Encrypted backup recovery verification failed; no Secret write attempted")
    audit = {"schema_version": 1, "action": args.action,
             "plan_id": plan["plan_id"], "target": f"{plan['namespace']}/{plan['secret']}",
             "created_utc": datetime.now(UTC).isoformat(), "status": "MUTATION_UNCERTAIN"}
    atomic_json(journal, audit)  # Write-ahead before API mutation; no retry after ambiguous outcome.
    try:
        if args.action == "CREATE":
            obj = {"apiVersion": "v1", "kind": "Secret",
                   "metadata": {"name": plan["secret"], "namespace": plan["namespace"]},
                   "type": TYPE, "data": {"tls.crt": base64.b64encode(cert).decode(),
                                            "tls.key": base64.b64encode(key).decode()}}
            kube(plan["context"], "-n", plan["namespace"], "create", "-f", "-",
                 payload=canonical(obj))  # atomic create: never overwrite
            observed = find_target(plan["context"], plan["namespace"], plan["secret"])
            require(observed is not None and observed.get("type") == TYPE,
                    "Create response unverified")
            require(base64.b64decode(observed["data"]["tls.key"], validate=True) == key,
                    "Stored TLS key does not match requested key")
            fp = fingerprint_from_der_or_pem(base64.b64decode(observed["data"]["tls.crt"], validate=True))
            require(fp == plan["new_fingerprint"], "Stored certificate fingerprint mismatch")
            result_uid = observed.get("metadata", {}).get("uid")
            result_rv = observed.get("metadata", {}).get("resourceVersion")
            require(bool(result_uid and result_rv), "Created Secret UID/RV missing")
            audit.update(status="COMPLETE_SECRET_VERIFIED", uid=result_uid,
                         resource_version=result_rv, fingerprint=fp)
        elif args.action == "UPDATE":
            changed = copy.deepcopy(original)
            changed["data"]["tls.crt"] = base64.b64encode(cert).decode("ascii")
            changed["data"]["tls.key"] = base64.b64encode(key).decode("ascii")
            # Kubernetes rejects stale resourceVersion updates server-side.
            changed["metadata"]["resourceVersion"] = plan["resource_version"]
            kube(plan["context"], "-n", plan["namespace"], "replace", "-f", "-",
                 payload=canonical(changed))
            observed = find_target(plan["context"], plan["namespace"], plan["secret"])
            require(observed is not None and observed.get("type") == TYPE,
                    "Update response unverified")
            meta = observed.get("metadata") or {}
            require(meta.get("uid") == plan["uid"] and
                    meta.get("resourceVersion") != plan["resource_version"],
                    "Updated Secret UID/RV verification failed")
            require(base64.b64decode(observed["data"]["tls.key"], validate=True) == key,
                    "Stored TLS key does not match requested key")
            fp = fingerprint_from_der_or_pem(base64.b64decode(
                observed["data"]["tls.crt"], validate=True))
            require(fp == plan["new_fingerprint"],
                    "Stored TLS certificate fingerprint mismatch")
            audit.update(status="COMPLETE_SECRET_VERIFIED", uid=meta["uid"],
                         resource_version=meta["resourceVersion"], fingerprint=fp)
        else:
            # kubectl delete --raw with local DeleteOptions file sends a Kubernetes
            # DELETE request body with API-enforced UID/RV preconditions.
            path = f"/api/v1/namespaces/{plan['namespace']}/secrets/{plan['secret']}"
            opts = directory / f"{plan['plan_id']}-delete-options.json"
            atomic_json(opts, {"apiVersion": "meta.k8s.io/v1", "kind": "DeleteOptions",
                               "preconditions": {"uid": plan["uid"],
                                                 "resourceVersion": plan["resource_version"]}})
            kube(plan["context"], "delete", f"--raw={path}", "-f", opts)
            remaining = find_target(plan["context"], plan["namespace"], plan["secret"])
            require(remaining is None, "Delete not verified; reconcile manually")
            audit.update(status="COMPLETE_ABSENCE_VERIFIED", prior_uid=plan["uid"])
        audit["completed_utc"] = datetime.now(UTC).isoformat()
        atomic_json(journal, audit, replace=True)
        return {"status": audit["status"], "journal": str(journal)}
    except Exception:
        # Journal remains MUTATION_UNCERTAIN; don't blindly replay operation.
        raise


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", help="Kubernetes context name; mandatory for all commands")
    parser.add_argument("--plain", action="store_true", help="Plain text; no ANSI or emoji are used")
    subs = parser.add_subparsers(dest="command", required=True)
    for cmd in ("inventory", "inspect", "plan-create", "create", "plan-update", "update", "plan-delete", "delete"):
        sub = subs.add_parser(cmd)
        sub.add_argument("--namespace", required=True)
        if cmd != "inventory":
            sub.add_argument("--secret", required=True)
        if cmd.startswith("plan-"):
            sub.add_argument("--workspace", required=True)
        if cmd in ("plan-create", "create", "plan-update", "update"):
            sub.add_argument("--cert", required=True)
            sub.add_argument("--key", required=True)
            sub.add_argument("--ca-bundle")
        if cmd in ("create", "update", "delete"):
            sub.add_argument("--plan", required=True)
            sub.add_argument("--approve", required=True, help="Exact immutable plan ID")
            sub.add_argument("--confirm-target", required=True, help="Exact namespace/secret")
            sub.add_argument("--approval-record",
                             help="Signed approval JSON for non-interactive/enterprise workflow")
            sub.add_argument("--approval-signature",
                             help="Detached signature for signed approval workflow")
            sub.add_argument("--approval-trust-key", default="/etc/kaori/tls-approval-public.pem")
            sub.add_argument("--operator-mode", action="store_true",
                             help="Single-operator interactive TTY confirmation (no external signature)")
            sub.add_argument("--operator-ack",
                             help="Exact action and target typed by the operator in wizard")
            sub.add_argument("--operator-attested", action="store_true",
                             help="Operator confirms no external consumers (Delete only)")
        if cmd in ("update", "delete"):
            sub.add_argument("--backup-recipient", required=True)
            sub.add_argument("--backup-identity",
                             help="Protected age identity; verifies local encrypted backup before write")
    args = parser.parse_args(argv)
    try:
        require(bool(args.context), "Explicit --context is required")
        if args.command == "inventory":
            print(json.dumps({"namespace": args.namespace,
                              "tls_secrets": list_tls_metadata(args.context, args.namespace)},
                             indent=2))
        elif args.command == "inspect":
            valid_target(args.namespace, args.secret)
            item = find_target(args.context, args.namespace, args.secret)
            require(item is not None, "Secret not found")
            require(item.get("type") == TYPE, "Not a TLS Secret")
            # Do not print private certificate or key bytes.
            cert = base64.b64decode(item["data"]["tls.crt"], validate=True)
            print(json.dumps({"namespace": args.namespace, "secret": args.secret,
                              "uid": item["metadata"].get("uid"),
                              "resource_version": item["metadata"].get("resourceVersion"),
                              "fingerprint": fingerprint_from_der_or_pem(cert)}, indent=2))
        elif args.command == "plan-create":
            path, plan = plan_create(args)
            print(json.dumps({"plan": str(path), "plan_id": plan["plan_id"],
                              "action": plan["action"]}, indent=2))
        elif args.command == "plan-update":
            path, plan = plan_update(args)
            print(json.dumps({"plan": str(path), "plan_id": plan["plan_id"],
                              "action": plan["action"]}, indent=2))
        elif args.command == "plan-delete":
            try:
                path, plan = plan_delete(args)
            except DeleteHold as hold:
                evidence = save_delete_hold(args, hold)
                print(json.dumps({"status": "HOLD", "action": "DELETE",
                                  "target": f"{args.namespace}/{args.secret}",
                                  "reason": hold.reason, "blockers": hold.details,
                                  "evidence": str(evidence)}, indent=2))
                return 0
            print(json.dumps({"plan": str(path), "plan_id": plan["plan_id"],
                              "action": plan["action"]}, indent=2))
        else:
            action = args.command.upper()
            result = apply(argparse.Namespace(**vars(args), action=action))
            print(json.dumps(result, indent=2))
        return 0
    except (Stop, OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
