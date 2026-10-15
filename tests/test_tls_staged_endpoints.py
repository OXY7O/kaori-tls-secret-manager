"""Offline contract tests for explicitly staged TLS Secrets with no Ingress."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("tlsmanager_staged", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class StagedSecretTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.active = {
            "namespace": "monitoring", "secret_name": "prometheus-tls",
            "status": "READY", "uid": "activeuid", "resource_version": "10",
            "ingress_refs": [{"host": "metrics.example.test", "ingress": "prometheus"}],
        }
        self.staged = {
            "namespace": "staging-development", "secret_name": "tls-secret",
            "status": "READY", "uid": "stageduid", "resource_version": "20",
            "ingress_refs": [],
        }
        self.plan = {
            "schema_version": 1, "context": "uat", "cluster_uid": "clusteruid",
            "new_sans": ["*.example.test"], "new_fingerprint": "c" * 64,
            "entries": [self.active, self.staged],
        }
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_path = self.root / "renewal-plan.json"
        self.plan_path.write_text(json.dumps(self.plan))
        self.journal_path = self.root / "execution-journal.json"
        self.journal = {
            "plan_id": self.plan["plan_id"],
            "status": "COMPLETE_ENDPOINT_UNVERIFIED",
            "items": [
                {
                    "namespace": "monitoring", "secret_name": "prometheus-tls",
                    "status": "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                    "post_resource_version": "11",
                },
                {
                    "namespace": "staging-development", "secret_name": "tls-secret",
                    "status": "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                    "post_resource_version": "21",
                },
            ],
        }
        self.journal_path.write_text(json.dumps(self.journal))
        self.endpoints = self.root / "endpoints.csv"
        self.endpoints.write_text(
            "namespace,secret_name,hostname,port,connect_host\n"
            "monitoring,prometheus-tls,metrics.example.test,443,\n"
        )
        self.staged_csv = self.root / "staged.csv"
        self.staged_csv.write_text(
            "namespace,secret_name,reason\n"
            "staging-development,tls-secret,Pre-provisioned before Ingress activation\n"
        )
        self.args = types.SimpleNamespace(
            context="uat", plan=str(self.plan_path), endpoints=str(self.endpoints),
            staged_targets=str(self.staged_csv), ca_bundle=None
        )

    def run_verifier(self, fingerprint=None, status=None):
        if status:
            self.journal["status"] = status
            self.journal_path.write_text(json.dumps(self.journal))

        def get_secret(ctx, ns, name):
            return {"metadata": {
                "uid": "activeuid" if ns == "monitoring" else "stageduid",
                "resourceVersion": "11" if ns == "monitoring" else "21",
            }}

        def get_ingress(ctx, ns):
            return {
                "prometheus-tls": [{"host": "metrics.example.test"}]
            } if ns == "monitoring" else {}

        with patch.object(m, "cluster_id", return_value="clusteruid"), \
             patch.object(m, "secret", side_effect=get_secret), \
             patch.object(m, "old_info", return_value={"fingerprint": "c" * 64}), \
             patch.object(m, "ingress_references", side_effect=get_ingress), \
             patch.object(m, "probe_https_endpoint", return_value={
                "fingerprint": fingerprint or "c" * 64,
                "tls_version": "TLSv1.3",
             }):
            m.cmd_verify_endpoints(self.args)

    def test_missing_endpoint_without_approved_staging_still_fails(self):
        self.args.staged_targets = None
        with self.assertRaisesRegex(m.Stop, "Missing endpoint mapping for staging-development/tls-secret"):
            m.read_endpoint_targets(self.endpoints, self.plan)

    def test_staging_requires_explicit_meaningful_reason(self):
        self.staged_csv.write_text(
            "namespace,secret_name,reason\nstaging-development,tls-secret,yes\n"
        )
        with self.assertRaisesRegex(m.Stop, "meaningful reason"):
            m.read_staged_targets(self.staged_csv, self.plan)

    def test_staged_exception_denied_if_ingress_references_target(self):
        self.staged["ingress_refs"] = [{"host": "app.example.test"}]
        with self.assertRaisesRegex(m.Stop, "forbidden for Ingress-referenced"):
            m.read_staged_targets(self.staged_csv, self.plan)

    def test_staged_target_must_be_ready_and_unique(self):
        text = self.staged_csv.read_text()
        self.staged_csv.write_text(text + "staging-development,tls-secret,duplicate intentionally staged secret\n")
        with self.assertRaisesRegex(m.Stop, "Duplicate staged target"):
            m.read_staged_targets(self.staged_csv, self.plan)
        self.staged_csv.write_text(
            "namespace,secret_name,reason\nother,tls-secret,preprovisioned external test staging\n"
        )
        with self.assertRaisesRegex(m.Stop, "not READY"):
            m.read_staged_targets(self.staged_csv, self.plan)

    def test_staged_target_cannot_be_marked_active_in_endpoint_csv(self):
        with self.endpoints.open("a") as f:
            f.write("staging-development,tls-secret,app.example.test,443,\n")
        staged = m.read_staged_targets(self.staged_csv, self.plan)
        with self.assertRaisesRegex(m.Stop, "must not be declared as active"):
            m.read_endpoint_targets(self.endpoints, self.plan, staged=staged)

    def test_mixed_batch_final_is_truthful_and_report_matches(self):
        self.run_verifier()
        journal = json.loads(self.journal_path.read_text())
        self.assertEqual(journal["status"], "COMPLETE_WITH_STAGED_SECRETS")
        self.assertEqual(journal["items"][0]["status"], "ENDPOINT_VERIFIED")
        self.assertEqual(journal["items"][1]["status"], "SECRET_VERIFIED_PENDING_ACTIVATION")
        evidence = json.loads((self.root / "endpoint-verification.json").read_text())
        self.assertEqual(evidence["status"], "COMPLETE_WITH_STAGED_SECRETS")
        self.assertEqual(len(evidence["endpoints"]), 1)
        self.assertEqual(len(evidence["staged_secrets"]), 1)
        m.cmd_report(self.args)
        report = (self.root / "renewal-report.csv").read_text()
        self.assertIn("SECRET_VERIFIED_PENDING_ACTIVATION", report)
        self.assertIn("ENDPOINT_VERIFIED", report)

    def test_mixed_failure_never_marks_staged_or_active_as_pass(self):
        with self.assertRaisesRegex(m.Stop, "fingerprint mismatch"):
            self.run_verifier(fingerprint="a" * 64)
        journal = json.loads(self.journal_path.read_text())
        self.assertEqual(journal["status"], "COMPLETE_ENDPOINT_UNVERIFIED")
        self.assertFalse((self.root / "endpoint-verification.json").exists())

    def test_all_staged_batch_allows_header_only_endpoints_but_not_full_verified(self):
        self.plan["entries"] = [self.staged]
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_path.write_text(json.dumps(self.plan))
        self.journal["plan_id"] = self.plan["plan_id"]
        self.journal["items"] = [self.journal["items"][1]]
        self.journal_path.write_text(json.dumps(self.journal))
        self.endpoints.write_text("namespace,secret_name,hostname,port,connect_host\n")
        self.run_verifier()
        journal = json.loads(self.journal_path.read_text())
        self.assertEqual(journal["status"], "COMPLETE_WITH_STAGED_SECRETS")
        self.assertEqual(journal["items"][0]["status"], "SECRET_VERIFIED_PENDING_ACTIVATION")
        evidence = json.loads((self.root / "endpoint-verification.json").read_text())
        self.assertEqual(evidence["endpoints"], [])

    def test_stale_verified_report_legacy_evidence_still_supported(self):
        self.plan["entries"] = [self.active]
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_path.write_text(json.dumps(self.plan))
        self.journal["plan_id"] = self.plan["plan_id"]
        self.journal["status"] = "COMPLETE_ENDPOINT_VERIFIED"
        self.journal["items"] = [self.journal["items"][0]]
        self.journal["items"][0]["status"] = "ENDPOINT_VERIFIED"
        self.journal_path.write_text(json.dumps(self.journal))
        (self.root / "endpoint-verification.json").write_text(json.dumps({
            "plan_id": self.plan["plan_id"], "status": "ENDPOINT_VERIFIED",
            "endpoints": [{
                "namespace": "monitoring", "secret_name": "prometheus-tls",
                "hostname": "metrics.example.test",
            }]
        }))
        m.cmd_report(self.args)
        self.assertIn("ENDPOINT_VERIFIED", (self.root / "renewal-report.csv").read_text())

    def test_report_rejects_forged_staged_status_missing_evidence(self):
        self.journal["status"] = "COMPLETE_WITH_STAGED_SECRETS"
        self.journal["items"][0]["status"] = "ENDPOINT_VERIFIED"
        self.journal["items"][1]["status"] = "SECRET_VERIFIED_PENDING_ACTIVATION"
        self.journal_path.write_text(json.dumps(self.journal))
        (self.root / "endpoint-verification.json").write_text(json.dumps({
            "plan_id": self.plan["plan_id"], "status": "COMPLETE_WITH_STAGED_SECRETS",
            "endpoints": [{"namespace": "monitoring", "secret_name": "prometheus-tls"}],
            "staged_secrets": [],
        }))
        with self.assertRaisesRegex(m.Stop, "evidence does not cover"):
            m.cmd_report(self.args)


if __name__ == "__main__":
    unittest.main()
