"""Offline tests for fail-closed end-to-end TLS endpoint verification."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("tlsmanager_endpoint", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class EndpointValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.entry = {
            "namespace": "app-development", "secret_name": "web-tls",
            "status": "READY", "uid": "uid1", "resource_version": "1",
            "ingress_refs": [{"host": "www.example.test", "ingress": "web"}],
        }
        self.plan = {
            "schema_version": 1, "context": "test", "cluster_uid": "clusteruid",
            "new_sans": ["*.example.test"], "new_fingerprint": "b" * 64,
            "entries": [self.entry],
        }
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_path = self.dir / "renewal-plan.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.journal_path = self.dir / "execution-journal.json"
        self.journal = {
            "plan_id": self.plan["plan_id"],
            "status": "COMPLETE_ENDPOINT_UNVERIFIED",
            "items": [{
                "namespace": "app-development", "secret_name": "web-tls",
                "status": "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                "post_resource_version": "2",
            }]
        }
        self.journal_path.write_text(json.dumps(self.journal))
        self.csv = self.dir / "endpoints.csv"
        self.csv.write_text(
            "namespace,secret_name,hostname,port,connect_host\n"
            "app-development,web-tls,www.example.test,443,\n"
        )
        self.args = types.SimpleNamespace(
            context="test", plan=str(self.plan_path),
            endpoints=str(self.csv), ca_bundle=None
        )

    def test_read_endpoint_targets_requires_ingress_host_coverage(self):
        self.csv.write_text(
            "namespace,secret_name,hostname,port,connect_host\n"
            "app-development,web-tls,api.example.test,443,\n"
        )
        with self.assertRaisesRegex(m.Stop, "Ingress TLS hosts not fully covered"):
            m.read_endpoint_targets(self.csv, self.plan)

    def test_wildcard_ingress_ref_can_be_verified_by_concrete_sni(self):
        self.entry["ingress_refs"] = [{"host": "*.example.test", "ingress": "wildcard"}]
        result = m.read_endpoint_targets(self.csv, self.plan)
        self.assertEqual(result[0]["hostname"], "www.example.test")

    def test_read_endpoint_targets_rejects_duplicate_and_wrong_secret(self):
        original = self.csv.read_text()
        self.csv.write_text(original + "app-development,web-tls,www.example.test,443,\n")
        with self.assertRaisesRegex(m.Stop, "Duplicate endpoint"):
            m.read_endpoint_targets(self.csv, self.plan)
        self.csv.write_text(original.replace("web-tls", "wrong-tls"))
        with self.assertRaisesRegex(m.Stop, "Unexpected endpoint target"):
            m.read_endpoint_targets(self.csv, self.plan)

    def test_read_endpoint_targets_rejects_uncovered_san(self):
        self.csv.write_text(
            "namespace,secret_name,hostname,port,connect_host\n"
            "app-development,web-tls,v2.api.example.test,443,\n"
        )
        with self.assertRaisesRegex(m.Stop, "outside replacement SAN"):
            m.read_endpoint_targets(self.csv, self.plan)

    def test_read_endpoint_targets_rejects_empty(self):
        self.csv.write_text("namespace,secret_name,hostname,port,connect_host\n")
        with self.assertRaisesRegex(m.Stop, "Missing endpoint mapping"):
            m.read_endpoint_targets(self.csv, self.plan)

    def test_verify_endpoints_success_writes_evidence_and_final_status(self):
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "2"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={"web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint",
                          return_value={"fingerprint": "b" * 64, "tls_version": "TLSv1.3"}), \
             redirect_stdout(io.StringIO()) as stream:
            m.cmd_verify_endpoints(self.args)
        result = json.loads(self.journal_path.read_text())
        self.assertEqual(result["status"], "COMPLETE_ENDPOINT_VERIFIED")
        self.assertEqual(result["items"][0]["status"], "ENDPOINT_VERIFIED")
        evidence = json.loads((self.dir / "endpoint-verification.json").read_text())
        self.assertEqual(evidence["status"], "COMPLETE_ENDPOINT_VERIFIED")
        self.assertTrue(evidence["endpoints"][0]["chain_verified"])
        self.assertIn("ENDPOINT_VERIFIED: 1 HTTPS endpoint", stream.getvalue())
        with redirect_stdout(io.StringIO()) as report:
            m.cmd_report(self.args)
        self.assertEqual(json.loads(self.journal_path.read_text())["status"],
                         "COMPLETE_ENDPOINT_VERIFIED")
        self.assertIn("ENDPOINT_VERIFIED", (self.dir / "renewal-report.csv").read_text())
        self.assertIn("endpoint_evidence", report.getvalue())

    def test_reviewed_external_tls_has_distinct_verification_status(self):
        self.csv.write_text(
            "namespace,secret_name,hostname,port,connect_host,verification_mode,"
            "expected_endpoint_fingerprint,review_reference\n"
            "app-development,web-tls,www.example.test,443,,EXTERNAL_TERMINATION,"
            + "a" * 64 + ",Independent NGINX TLS certificate approved by service owner\n"
        )
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "2"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={
                 "web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint", return_value={
                 "fingerprint": "a" * 64, "tls_version": "TLSv1.3"}):
            m.cmd_verify_endpoints(self.args)
        journal = json.loads(self.journal_path.read_text())
        self.assertEqual(journal["status"], "COMPLETE_WITH_EXTERNAL_TLS")
        self.assertEqual(journal["items"][0]["status"], "EXTERNAL_TLS_VERIFIED")
        evidence = json.loads((self.dir / "endpoint-verification.json").read_text())
        self.assertEqual(evidence["endpoints"][0]["verification_status"],
                         "EXTERNAL_TLS_VERIFIED")
        with redirect_stdout(io.StringIO()):
            m.cmd_report(self.args)

    def test_failed_reverification_preserves_previous_successful_evidence(self):
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "2"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={
                 "web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint", return_value={
                 "fingerprint": "b" * 64, "tls_version": "TLSv1.3"}):
            m.cmd_verify_endpoints(self.args)
        previous = (self.dir / "endpoint-verification.json").read_text()
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={
                 "web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint", side_effect=m.Stop("TLS trust failed")):
            with self.assertRaises(m.Stop):
                m.cmd_verify_endpoints(self.args)
        history = list((self.dir / "verification-history").glob("*/outcome.json"))
        self.assertEqual(len(history), 2)
        failed = [x for x in history if json.loads(x.read_text())["status"] == "FAILED"]
        self.assertEqual(len(failed), 1)
        preserved = failed[0].parent / "previous-endpoint-evidence.json"
        self.assertTrue(preserved.exists())
        self.assertEqual(json.loads(preserved.read_text()), json.loads(previous))
        self.assertEqual(json.loads(self.journal_path.read_text())["status"],
                         "COMPLETE_ENDPOINT_UNVERIFIED")

    def test_fingerprint_mismatch_never_claims_pass(self):
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "2"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={"web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint",
                          return_value={"fingerprint": "a" * 64, "tls_version": "TLSv1.3"}):
            with self.assertRaisesRegex(m.Stop, "fingerprint mismatch"):
                m.cmd_verify_endpoints(self.args)
        result = json.loads(self.journal_path.read_text())
        self.assertEqual(result["status"], "COMPLETE_ENDPOINT_UNVERIFIED")
        self.assertFalse((self.dir / "endpoint-verification.json").exists())

    def test_reverification_failure_revokes_prior_verified_journal(self):
        self.journal["status"] = "COMPLETE_ENDPOINT_VERIFIED"
        self.journal["items"][0]["status"] = "ENDPOINT_VERIFIED"
        self.journal_path.write_text(json.dumps(self.journal))
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "2"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj), \
             patch.object(m, "old_info", return_value={"fingerprint": "b" * 64}), \
             patch.object(m, "ingress_references", return_value={"web-tls": [{"host": "www.example.test"}]}), \
             patch.object(m, "probe_https_endpoint", side_effect=m.Stop("Trust validation failed")):
            with self.assertRaises(m.Stop):
                m.cmd_verify_endpoints(self.args)
        self.assertEqual(json.loads(self.journal_path.read_text())["status"],
                         "COMPLETE_ENDPOINT_UNVERIFIED")

    def test_reverification_preflight_drift_revokes_old_pass(self):
        self.journal["status"] = "COMPLETE_ENDPOINT_VERIFIED"
        self.journal["items"][0]["status"] = "ENDPOINT_VERIFIED"
        self.journal_path.write_text(json.dumps(self.journal))
        obj = {"metadata": {"uid": "uid1", "resourceVersion": "CHANGED"}}
        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", return_value=obj):
            with self.assertRaisesRegex(m.Stop, "Secret changed since renewal"):
                m.cmd_verify_endpoints(self.args)
        self.assertEqual(json.loads(self.journal_path.read_text())["status"],
                         "COMPLETE_ENDPOINT_UNVERIFIED")

    def test_partial_execution_is_never_verified(self):
        self.journal["status"] = "STOPPED"
        self.journal_path.write_text(json.dumps(self.journal))
        with patch.object(m, "cluster_id", return_value="clusteruid"):
            with self.assertRaisesRegex(m.Stop, "Execution incomplete"):
                m.cmd_verify_endpoints(self.args)

    def test_tls_probe_binds_sni_and_ca(self):
        class FakeTLS:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def getpeercert(self, binary_form=False):
                self_binary = b"dummy-der"
                return self_binary if binary_form else {}
            def version(self): return "TLSv1.3"
        class FakeContext:
            def wrap_socket(self, raw, server_hostname=None):
                self.server_hostname = server_hostname
                return FakeTLS()
        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass
        tls_context = FakeContext()
        with patch.object(m.ssl, "create_default_context", return_value=tls_context) as factory, \
             patch.object(m.socket, "create_connection", return_value=FakeSocket()) as connect:
            value = m.probe_https_endpoint("www.example.test", "10.0.0.1", 8443,
                                          ca_bundle="/trusted/root.pem")
        self.assertEqual(tls_context.server_hostname, "www.example.test")
        connect.assert_called_once_with(("10.0.0.1", 8443), timeout=12)
        factory.assert_called_once_with(cafile="/trusted/root.pem")
        self.assertEqual(value["fingerprint"], m.digest(b"dummy-der"))


if __name__ == "__main__":
    unittest.main()
