"""Offline X.509 comparison tests. No Kubernetes mutations or real cert material."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
import io

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("tlsmanager_compare", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def cert(fp, *, sans=None, subject="CN=*.example.test",
         issuer="CN=Trusted CA", key="public-key-digest-1"):
    return {
        "fingerprint": fp,
        "sans": ["*.example.test"] if sans is None else sans,
        "subject": subject,
        "issuer": issuer,
        "public_key_hash": key,
    }


class CertificateComparisonTests(unittest.TestCase):
    def test_ordinary_renewal_change_is_info_not_block(self):
        result = m.compare_tls_identity(cert("old"), cert("new"), [{"host": "app.example.test"}])
        self.assertEqual(result["review_level"], "INFO")
        self.assertEqual(result["certificate_change"], "DIFFERENT")
        self.assertTrue(result["san_match"])
        self.assertTrue(result["issuer_match"])
        self.assertTrue(result["subject_match"])
        self.assertEqual(result["flags"], ["CERTIFICATE_FINGERPRINT_CHANGED"])

    def test_same_cert_is_not_claimed_changed(self):
        result = m.compare_tls_identity(cert("same"), cert("same"), [{"host": "app.example.test"}])
        self.assertEqual(result["certificate_change"], "SAME")
        self.assertEqual(result["flags"], [])

    def test_change_in_issuer_or_subject_is_warning_but_ready(self):
        old = cert("old")
        new = cert("new", issuer="CN=Other CA", subject="CN=new.example.test")
        result = m.compare_tls_identity(old, new, [{"host": "app.example.test"}])
        self.assertEqual(result["review_level"], "WARNING")
        self.assertIn("ISSUER_CHANGED", result["flags"])
        self.assertIn("SUBJECT_CHANGED", result["flags"])
        state, _ = m.assess({"metadata": {}}, old, new, [{"host": "app.example.test"}], "renew")
        self.assertEqual(state, "READY")

    def test_rekey_is_info_and_not_automatic_block(self):
        result = m.compare_tls_identity(
            cert("old"), cert("new", key="public-key-digest-2"), [{"host": "app.example.test"}])
        self.assertEqual(result["review_level"], "INFO")
        self.assertIn("PUBLIC_KEY_ROTATED", result["flags"])

    def test_changed_san_warning_and_existing_guardrail_still_blocks(self):
        old = cert("old")
        new = cert("new", sans=["*.other.test"])
        comparison = m.compare_tls_identity(old, new, [])
        self.assertIn("SAN_SET_CHANGED", comparison["flags"])
        self.assertEqual(comparison["review_level"], "WARNING")
        status, _ = m.assess({"metadata": {}}, old, new, [], "renew")
        self.assertEqual(status, "BLOCKED")

    def test_no_ingress_reference_warns_but_does_not_mark_unused(self):
        result = m.compare_tls_identity(cert("old"), cert("new"), [])
        self.assertEqual(result["review_level"], "WARNING")
        self.assertIn("NO_INGRESS_TLS_REFERENCE", result["flags"])

    def test_mixed_fingerprint_family_same_san_warns_all_targets(self):
        entries = [
            {"old_sans": ["*.example.test"], "old_fingerprint": "old-a",
             "certificate_comparison": m.compare_tls_identity(cert("old-a"), cert("new"), [{"host": "a.example.test"}])},
            {"old_sans": ["*.example.test"], "old_fingerprint": "old-b",
             "certificate_comparison": m.compare_tls_identity(cert("old-b"), cert("new"), [{"host": "b.example.test"}])},
            {"old_sans": ["*.other.test"], "old_fingerprint": "old-c",
             "certificate_comparison": m.compare_tls_identity(
                 cert("old-c", sans=["*.other.test"]), cert("new"), [])},
        ]
        m.classify_existing_certificate_families(entries)
        for e in entries[:2]:
            c = e["certificate_comparison"]
            self.assertEqual(c["existing_fingerprint_variants_same_san"], 2)
            self.assertIn("MIXED_EXISTING_CERTIFICATES_SAME_SAN", c["flags"])
            self.assertEqual(c["review_level"], "WARNING")
        self.assertEqual(entries[2]["certificate_comparison"]["existing_fingerprint_variants_same_san"], 1)

    def test_plan_generates_comparison_report_with_original_target_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ns_file = root / "namespaces.txt"
            ns_file.write_text("app\n")
            targets = root / "targets.csv"
            targets.write_text(
                "namespace,secret_name,mode,reason\n"
                "app,web-tls,renew,\n"
                "app,api-tls,renew,\n"
            )
            args = types.SimpleNamespace(
                context="uat", namespaces=str(ns_file), targets=str(targets),
                cert="dummy-fullchain", key="dummy-key", ca_bundle=None,
                runs_dir=str(root / "runs")
            )
            old_by_secret = {
                "web-tls": cert("old-a"),
                "api-tls": cert("old-b"),
            }
            def secret(ctx, ns, name):
                return {"metadata": {"uid": name + "-uid",
                                    "resourceVersion": "42"},
                        "data": {}, "type": "kubernetes.io/tls",
                        "fake_name": name}
            def old_info(obj):
                return old_by_secret[obj["fake_name"]]
            with patch.object(m, "verify_source", return_value=(b"cert", b"key", cert("new"))), \
                 patch.object(m, "secret", side_effect=secret), \
                 patch.object(m, "old_info", side_effect=old_info), \
                 patch.object(m, "verify_stored_pair", return_value=None), \
                 patch.object(m, "ingress_references", return_value={
                     "web-tls": [{"host": "web.example.test"}],
                     "api-tls": [{"host": "api.example.test"}],
                 }), \
                 patch.object(m, "cluster_id", return_value="uid-cluster"), \
                 redirect_stdout(io.StringIO()) as out:
                m.cmd_plan(args)
            runs = list((root / "runs").iterdir())
            self.assertEqual(len(runs), 1)
            with (runs[0] / "certificate-comparison.csv").open(newline="") as f:
                comparison = list(csv.DictReader(f))
            self.assertEqual(len(comparison), 2)
            self.assertTrue(all(r["plan_status"] == "HOLD" for r in comparison))
            self.assertTrue(all(r["comparison_level"] == "WARNING" for r in comparison))
            self.assertTrue(all(r["existing_fingerprint_variants_same_san"] == "2" for r in comparison))
            self.assertIn("CERTIFICATE COMPARISON", out.getvalue())
            self.assertTrue(out.getvalue().strip().splitlines()[-1].endswith(str(runs[0])))
            plan = json.loads((runs[0] / "renewal-plan.json").read_text())
            self.assertTrue(all("certificate_comparison" in e for e in plan["entries"]))
            self.assertTrue(all(e["status"] == "HOLD" for e in plan["entries"]))


if __name__ == "__main__":
    unittest.main()
