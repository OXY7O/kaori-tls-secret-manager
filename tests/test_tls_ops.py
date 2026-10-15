"""Read-only KAORI TLS Ops toolkit; all Kubernetes/network I/O mocked."""
import base64
from datetime import datetime, timezone, timedelta
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("tls_ops_tests", ROOT / "tls_ops.py")
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)
import tls_secret_manager as helper

FP_A = "a" * 64
FP_B = "b" * 64


def secret(name="web-tls", ns="dev", key=b"private-key", cert=b"public-leaf"):
    return {"type": "kubernetes.io/tls", "metadata": {
        "namespace": ns, "name": name, "uid": "uid-web", "resourceVersion": "42"},
        "data": {"tls.crt": base64.b64encode(cert).decode(),
                 "tls.key": base64.b64encode(key).decode()}}


def details(start=None, end=None, public=b"public-pem"):
    now = datetime.now(timezone.utc)
    return {
        "not_before": (start or (now-timedelta(days=1))).isoformat(),
        "not_after": (end or (now+timedelta(days=45))).isoformat(),
        "subject": "CN=web.example.test", "issuer": "CN=OpsCA",
        "sans": ["web.example.test"], "fingerprint": FP_A,
        "public_key_hash": helper.digest(public)
    }


class TLSOpsTests(unittest.TestCase):
    def validate(self, desc=None, pub=b"public-pem", obj=None, ca=None):
        with patch.object(ops, "cert_details", return_value=desc or details()), \
             patch.object(ops, "run", return_value=pub):
            return ops.validate_stored_tls(obj or secret(), 30, ca_bundle=ca)

    def test_atomic_evidence_is_private_under_permissive_umask(self):
        import os
        import stat
        previous_umask = os.umask(0)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = ops.atomic_evidence(Path(tmp) / "private", "health",
                                           {"secret_name": "synthetic-web-tls"})
                mode = stat.S_IMODE(path.stat().st_mode)
                folder_mode = stat.S_IMODE(path.parent.stat().st_mode)
        finally:
            os.umask(previous_umask)
        self.assertEqual(mode, 0o600)
        self.assertEqual(folder_mode, 0o700)

    def test_valid_stored_key_not_endorsed_as_public_tls(self):
        out = self.validate()
        self.assertEqual(out["status"], "VALID")
        self.assertEqual(out["key_match"], "MATCH")
        self.assertEqual(out["trust_status"], "NOT_CHECKED")
        self.assertEqual(out["endpoint_status"], "NOT_CHECKED")

    def test_mismatched_private_key_fails_stored_health(self):
        out = self.validate(pub=b"different")
        self.assertEqual(out["status"], "INVALID")
        self.assertEqual(out["key_match"], "MISMATCH")

    def test_expired_by_one_minute_does_not_round_into_valid(self):
        out = self.validate(desc=details(end=datetime.now(timezone.utc)-timedelta(minutes=1)))
        self.assertEqual(out["status"], "EXPIRED")
        self.assertEqual(out["days_remaining"], -1)

    def test_future_not_before_is_not_valid(self):
        out = self.validate(desc=details(start=datetime.now(timezone.utc)+timedelta(hours=1)))
        self.assertEqual(out["status"], "NOT_YET_VALID")

    def test_warning_within_threshold_is_expiring(self):
        out = self.validate(desc=details(end=datetime.now(timezone.utc)+timedelta(days=3)))
        self.assertEqual(out["status"], "EXPIRING")

    def test_invalid_or_missing_key_never_prints_private_bytes(self):
        obj = secret(key=b"private-secret-nonpublic")
        obj["data"]["tls.key"] = "!!!BADBASE64"
        r = ops.validate_stored_tls(obj)
        self.assertEqual(r["status"], "INVALID")
        self.assertNotIn("private-secret", json.dumps(r))

    def test_inventory_ingress_san_coverage_check(self):
        obj = secret()
        with patch.object(ops, "tls_secret_names", return_value=["web-tls"]), \
             patch.object(ops, "secret", return_value=obj), \
             patch.object(ops, "ingress_references", return_value={
                 "web-tls": [{"host": "bad.example.org"}]
             }), patch.object(ops, "validate_stored_tls", return_value={
                 **self.validate(), "san": "web.example.test"
             }):
            records = ops.inventory("ctx", ["dev"])
        self.assertEqual(records[0]["ingress_san_status"], "MISMATCH")

    def test_dependency_includes_ingress_gateway_pod_with_coverage(self):
        obj = secret()
        gateway = [{"kind": "Gateway", "name": "edge", "route": "listener/https"}]
        pods = [{"kind": "Pod", "name": "app-1", "route": "volume/tls"}]
        with patch.object(ops, "secret", return_value=obj), \
             patch.object(ops, "ingress_references", return_value={
                 "web-tls": [{"ingress": "main", "host": "web.example.test"}]
             }), patch.object(ops, "owners_from_pods", return_value=pods), \
             patch.object(ops, "discover_gateways", return_value=(gateway, "CHECKED")):
            result = ops.dependency_report("ctx", "dev", "web-tls")
        self.assertEqual(result["consumer_count"], 3)
        self.assertIn("external", result["limitation"].lower())

    def test_dependency_rbac_failure_is_never_reported_unused(self):
        with patch.object(ops, "secret", return_value=secret()), \
             patch.object(ops, "ingress_references", return_value={}), \
             patch.object(ops, "owners_from_pods", side_effect=helper.Stop("RBAC denied")):
            with self.assertRaisesRegex(helper.Stop, "RBAC denied"):
                ops.dependency_report("ctx", "dev", "web-tls")

    def test_pod_dependency_volume_and_env_refs(self):
        data = {"items": [{"metadata": {"name": "worker"},
            "spec": {"volumes": [{"name": "tls", "secret": {"secretName": "web-tls"}}],
             "containers": [{"name": "app", "env": [{"name": "PASSWORD",
                 "valueFrom": {"secretKeyRef": {"name": "web-tls", "key": "k"}}}]}]}}]}
        with patch.object(ops, "kube_json", return_value=data):
            result = ops.owners_from_pods("ctx", "dev", "web-tls")
        self.assertEqual({r["route"] for r in result}, {"volume/tls", "envSecret/app"})

    def test_mixed_fingerprint_family_detected_without_false_ownership(self):
        rows = [
            {"status": "VALID", "namespace": "a", "secret_name": "secret-1",
             "san": "*.example.test", "fingerprint_sha256": FP_A, "issuer": "CA1"},
            {"status": "VALID", "namespace": "b", "secret_name": "secret-2",
             "san": "*.example.test", "fingerprint_sha256": FP_B, "issuer": "CA2"},
            {"status": "INVALID", "namespace": "c", "secret_name": "bad",
             "san": "", "fingerprint_sha256": "", "issuer": ""},
        ]
        groups = ops.analyze_families(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["status"], "REVIEW_MIXED_ISSUANCE")
        self.assertEqual(groups[0]["fingerprint_variants"], 2)

    def test_doctor_mismatch_is_warning_not_automated_rollback(self):
        with patch.object(ops, "secret", return_value=secret()), \
             patch.object(ops, "ingress_references", return_value={
                 "web-tls": [{"host": "web.example.test"}]
             }), patch.object(ops, "validate_stored_tls", return_value={
                 "status": "VALID", "key_match": "MATCH",
                 "fingerprint_sha256": FP_A
             }), patch.object(ops, "probe_https_endpoint", return_value={
                 "fingerprint": FP_B, "tls_version": "TLSv1.3"
             }):
            result = ops.doctor("ctx", "dev", "web-tls", "web.example.test")
        self.assertEqual(result["endpoint"]["status"], "FINGERPRINT_MISMATCH")
        self.assertIn("external TLS terminator", " ".join(result["diagnosis"]))

    def test_drift_scans_dns_ip_separately_and_flags_split_fingerprint(self):
        obj = secret()
        refs = {"web-tls": [{"ingress": "edge", "host": "web.example.test"}]}
        def probe(host, addr, port, ca):
            return {"fingerprint": FP_A if addr == "10.0.0.1" else FP_B,
                    "tls_version": "TLSv1.3"}
        with patch.object(ops, "ingress_references", return_value=refs), \
             patch.object(ops, "secret", return_value=obj), \
             patch.object(ops, "validate_stored_tls", return_value={
                 "status": "VALID", "fingerprint_sha256": FP_A
             }), patch.object(ops.socket, "getaddrinfo", return_value=[
                 (None, None, None, None, ("10.0.0.2", 443)),
                 (None, None, None, None, ("10.0.0.1", 443)),
             ]), patch.object(ops, "probe_https_endpoint", side_effect=probe):
            result = ops.drift_report("ctx", ["dev"])
        self.assertEqual([x["status"] for x in result["results"]], ["MATCH", "MISMATCH"])

    def test_default_metrics_label_from_kubernetes_context(self):
        self.assertEqual(ops.default_metrics_cluster_label("admin@k8s-dev"),
                         "k8s-dev")
        self.assertEqual(ops.default_metrics_cluster_label("k8s-uat"), "k8s-uat")
        self.assertEqual(ops.default_metrics_cluster_label("arn:aws:eks:dev/cluster"),
                         "arn_aws_eks_dev_cluster")
        self.assertRegex(ops.default_metrics_cluster_label("x" * 120),
                         r"^x{91}-[0-9a-f]{8}$")
        with self.assertRaisesRegex(helper.Stop, "required"):
            ops.default_metrics_cluster_label("")

    def test_prometheus_metrics_context_label_is_safe_and_correct(self):
        rows = [{"status": "VALID", "secret_name": "private-secret"},
                {"status": "EXPIRING", "secret_name": "other-secret"}]
        label = ops.default_metrics_cluster_label("admin@k8s-dev")
        output = ops.prometheus_metrics(rows, label)
        self.assertIn('cluster="k8s-dev",status="VALID"} 1', output)
        self.assertIn('cluster="k8s-dev",status="EXPIRING"} 1', output)
        self.assertNotIn("admin@", output)
        self.assertNotIn("private-secret", output)

    def test_prometheus_metrics_reject_unsafe_override(self):
        rows = [{"status": "VALID"}]
        with self.assertRaisesRegex(helper.Stop, "Invalid cluster label"):
            ops.prometheus_metrics(rows, 'bad"\\\\nmetric')
        with self.assertRaisesRegex(helper.Stop, "Invalid cluster label"):
            ops.prometheus_metrics(rows, "dev cluster")


    def test_aggregate_prometheus_metrics_do_not_expose_secret_names(self):
        data = [{"status": "EXPIRING", "secret_name": "secret-a"},
                {"status": "VALID", "secret_name": "secret-b"},
                {"status": "NOT_YET_VALID", "secret_name": "secret-c"}]
        txt = ops.prometheus_metrics(data, "dev-cluster")
        self.assertIn('status="EXPIRING"} 1', txt)
        self.assertIn('status="NOT_YET_VALID"} 1', txt)
        self.assertNotIn("secret-a", txt)

    def test_run_reconciliation_unknown_checkpoint_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = {"schema_version": 1, "context": "ctx", "cluster_uid": "uid",
                    "new_fingerprint": FP_B, "entries": [{
                        "status": "READY", "namespace": "dev", "secret_name": "web-tls",
                        "uid": "uid-web", "old_fingerprint": FP_A
                    }]}
            plan["plan_id"] = helper.plan_id(plan)
            root = Path(tmp)
            target = root / "renewal-plan.json"
            target.write_text(json.dumps(plan))
            (root / "execution-journal.json").write_text(json.dumps({
                "plan_id": plan["plan_id"], "status": "STOPPED", "items": [{
                    "namespace": "dev", "secret_name": "web-tls", "status": "UNKNOWN"
                }]
            }))
            with patch("tls_secret_manager.cluster_id", return_value="uid"), \
                 patch.object(ops, "secret", return_value=secret()), \
                 patch.object(ops, "validate_stored_tls", return_value={
                     "fingerprint_sha256": FP_B,
                 }):
                result = ops.check_run("ctx", target)
            self.assertEqual(result["checks"][0]["check"], "UNCERTAIN_AFTER_WRITE")


if __name__ == "__main__":
    unittest.main()
