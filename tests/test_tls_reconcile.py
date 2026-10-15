"""Offline reconciliation checks: no real Kubernetes access or mutation."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("tlsmanager_reconcile", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ns = self.root / "namespaces.txt"
        self.ns.write_text("monitoring\n")
        self.targets = self.root / "targets.csv"
        self.targets.write_text(
            "namespace,secret_name,mode,reason\n"
            "monitoring,prometheus-tls,renew,\n"
            "monitoring,alertmanager-tls,renew,\n"
        )
        self.args = types.SimpleNamespace(
            context="dev", namespaces=str(self.ns),
            targets=str(self.targets), runs_dir=str(self.root / "runs")
        )
        self.present = {
            "metadata": {"name": "alertmanager-tls", "uid": "uid2"},
            "type": "kubernetes.io/tls",
            "data": {"tls.crt": "AA==", "tls.key": "AA=="},
        }

    def run_reconcile(self, secrets=None, refs=None, kube_error=None):
        objects = secrets if secrets is not None else [self.present]
        if kube_error:
            types_api = lambda *a: (_ for _ in ()).throw(m.Stop(kube_error))
        else:
            types_api = lambda *a: {o['metadata']['name']: o['type'] for o in objects}
        by_name = {o['metadata']['name']: o for o in objects}
        ingresses = refs if refs is not None else {
            "alertmanager-tls": [{"host": "alerts.example.test"}]
        }
        with patch.object(m, "cluster_id", return_value="cluster1"), \
             patch.object(m, "secret_type_index", side_effect=types_api), \
             patch.object(m, "secret", side_effect=lambda ctx, ns, name: by_name[name]), \
             patch.object(m, "ingress_references", return_value=ingresses), \
             patch.object(m, "change_secret", side_effect=AssertionError("no mutation allowed")):
            return m.cmd_reconcile(self.args)

    def one_output_dir(self):
        outputs = list((self.root / "runs").iterdir())
        self.assertEqual(len(outputs), 1)
        return outputs[0]

    def test_missing_target_excluded_but_live_target_retained(self):
        self.run_reconcile()
        root = self.one_output_dir()
        with (root / "target-reconciliation.csv").open(newline="") as f:
            items = list(csv.DictReader(f))
        self.assertEqual(items[0]["status"], "MISSING_REVIEW")
        self.assertEqual(items[1]["status"], "PRESENT_TLS")
        with (root / "targets-reconciled.csv").open(newline="") as f:
            candidates = list(csv.DictReader(f))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["secret_name"], "alertmanager-tls")
        summary = json.loads((root / "reconciliation-summary.json").read_text())
        self.assertEqual(summary["candidate_count"], 1)
        self.assertEqual(summary["counts"]["MISSING_REVIEW"], 1)
        self.assertTrue(summary["requires_operator_review"])
        self.assertEqual(summary["cluster_uid"], "cluster1")

    def test_missing_secret_still_referenced_blocks_batch(self):
        refs = {
            "prometheus-tls": [{"host": "prometheus.example.test"}],
            "alertmanager-tls": [{"host": "alerts.example.test"}]
        }
        with self.assertRaisesRegex(m.Stop, "unsafe target"):
            self.run_reconcile(refs=refs)
        root = self.one_output_dir()
        self.assertFalse((root / "targets-reconciled.csv").exists())
        report = (root / "target-reconciliation.csv").read_text()
        self.assertIn("BLOCKED_MISSING_REFERENCED", report)

    def test_rbac_failure_is_not_classified_missing(self):
        with self.assertRaisesRegex(m.Stop, "Cannot reconcile namespace monitoring"):
            self.run_reconcile(kube_error="kubectl operation failed (exit 1)")
        self.assertFalse((self.root / "runs").exists())

    def test_unreferenced_existing_secret_requires_explicit_review(self):
        self.run_reconcile(refs={})
        root = self.one_output_dir()
        report = (root / "target-reconciliation.csv").read_text()
        self.assertIn("PRESENT_REVIEW_NO_INGRESS", report)
        self.assertTrue((root / "targets-reconciled.csv").exists())

    def test_wrong_type_blocks_without_candidates(self):
        obj = {**self.present, "type": "Opaque"}
        with self.assertRaisesRegex(m.Stop, "unsafe target"):
            self.run_reconcile(secrets=[obj])
        root = self.one_output_dir()
        self.assertIn("BLOCKED_TYPE", (root / "target-reconciliation.csv").read_text())
        self.assertFalse((root / "targets-reconciled.csv").exists())

    def test_controller_managed_secret_blocks_without_candidates(self):
        obj = {**self.present, "metadata": {
            "name": "alertmanager-tls", "ownerReferences": [{"name": "cert-controller"}]
        }}
        with self.assertRaisesRegex(m.Stop, "unsafe target"):
            self.run_reconcile(secrets=[obj])
        root = self.one_output_dir()
        self.assertIn("BLOCKED_MANAGED", (root / "target-reconciliation.csv").read_text())
        self.assertFalse((root / "targets-reconciled.csv").exists())

    def test_no_remaining_secret_stops_without_approved_target_file(self):
        with self.assertRaisesRegex(m.Stop, "No live TLS Secret candidates"):
            self.run_reconcile(secrets=[], refs={})
        root = self.one_output_dir()
        self.assertFalse((root / "targets-reconciled.csv").exists())
        self.assertTrue((root / "target-reconciliation.csv").exists())


if __name__ == "__main__":
    unittest.main()
