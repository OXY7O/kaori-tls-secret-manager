"""Selective READY/HOLD/SKIPPED regression tests without Kubernetes access."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / 'scripts/kubernetes/tls-secret-manager/tls_secret_manager.py'
spec = importlib.util.spec_from_file_location('tlsmanager_selective', CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

A = "a" * 64
B = "b" * 64
NEW = "f" * 64


def cert(fp, san=None, subject="CN=*.example.test", issuer="CN=Issuer", key="same-key"):
    return {"fingerprint": fp, "sans": san or ["*.example.test"],
            "subject": subject, "issuer": issuer, "public_key_hash": key}


def plan_entry(name, fp, *, issuer="CN=Issuer", san=None, refs=None,
               mode="renew", subject="CN=*.example.test", key="same-key"):
    old = cert(fp, san=san, issuer=issuer, subject=subject, key=key)
    new = cert(NEW)
    obj = {"metadata": {}}
    refs = [{"host": name + ".example.test"}] if refs is None else refs
    state, reason = m.assess(obj, old, new, refs, mode)
    return {"namespace": "dev", "secret_name": name, "old_fingerprint": fp,
            "old_sans": old["sans"], "status": state, "message": reason,
            "mode": mode, "ingress_refs": refs,
            "certificate_comparison": m.compare_tls_identity(old, new, refs)}


class SelectivePolicyTests(unittest.TestCase):
    def test_single_approved_baseline_ready_and_mismatched_hold(self):
        good = plan_entry("web", A)
        bad = plan_entry("api", B)
        rows = [good, bad]
        m.classify_existing_certificate_families(rows)
        m.selective_hold(rows, A, {})
        self.assertEqual(good["status"], "READY")
        self.assertEqual(bad["status"], "HOLD")
        self.assertIn("EXPECTED_OLD_FINGERPRINT_MISMATCH", bad["message"])

    def test_mixed_old_fingerprints_without_baseline_hold_both(self):
        entries = [plan_entry("web", A), plan_entry("api", B)]
        m.classify_existing_certificate_families(entries)
        m.selective_hold(entries, None, {})
        self.assertEqual([e["status"] for e in entries], ["HOLD", "HOLD"])

    def test_no_redeployment_when_installed_new_leaf_matches(self):
        entries = [plan_entry("web", NEW), plan_entry("api", A)]
        m.classify_existing_certificate_families(entries)
        m.selective_hold(entries, A, {})
        self.assertEqual([e["status"] for e in entries], ["SKIPPED", "READY"])

    def test_issuer_change_holds_unless_explicitly_reviewed(self):
        entry = plan_entry("web", A, issuer="CN=ExternalIssuer")
        m.classify_existing_certificate_families([entry])
        m.selective_hold([entry], A, {})
        self.assertEqual(entry["status"], "HOLD")
        self.assertIn("ISSUER_CHANGED", entry["message"])
        approved = {"old_fingerprint": A,
                    "reason": "Certificate owner explicitly approved changed issuance"}
        entry2 = plan_entry("web", A, issuer="CN=ExternalIssuer")
        m.classify_existing_certificate_families([entry2])
        m.selective_hold([entry2], A, {("dev", "web"): approved})
        self.assertEqual(entry2["status"], "READY")
        self.assertIn("Reviewed exception", entry2["message"])

    def test_public_key_rotation_is_info_and_does_not_hold_normal_renewal(self):
        entry = plan_entry("web", A, key="different-key")
        m.classify_existing_certificate_families([entry])
        m.selective_hold([entry], A, {})
        self.assertEqual(entry["status"], "READY")
        self.assertIn("PUBLIC_KEY_ROTATED", entry["certificate_comparison"]["flags"])
        self.assertNotIn("PUBLIC_KEY_ROTATED", entry["message"])

    def test_subject_only_requires_review_and_approves_only_exact_change(self):
        old_subject = "CN=original.example.test"
        entry = plan_entry("web", A, subject=old_subject)
        m.classify_existing_certificate_families([entry])
        m.selective_hold([entry], A, {})
        self.assertEqual(entry["status"], "HOLD")
        self.assertIn("SUBJECT_CHANGED", entry["message"])
        approved = {
            "approval_scope": "SUBJECT_ONLY", "old_fingerprint": A,
            "old_subject": old_subject, "new_subject": "CN=*.example.test",
            "reason": "Approved Subject-only certificate renewal for web application"
        }
        entry2 = plan_entry("web", A, subject=old_subject, key="old-public-key")
        m.classify_existing_certificate_families([entry2])
        m.selective_hold([entry2], A, {("dev", "web"): approved})
        self.assertEqual(entry2["status"], "READY")
        self.assertIn("SUBJECT_CHANGE_REVIEWED", entry2["certificate_comparison"]["flags"])
        self.assertIn("PUBLIC_KEY_ROTATED", entry2["certificate_comparison"]["flags"])

    def test_subject_only_approval_cannot_release_issuer_or_baseline_mismatch(self):
        approved = {"approval_scope": "SUBJECT_ONLY", "old_fingerprint": A,
                    "old_subject": "CN=other.example.test",
                    "new_subject": "CN=*.example.test",
                    "reason": "Owner reviewed a Subject-only change"}
        for old_issuer, baseline in [
            ("CN=DifferentIssuer", A), ("CN=Issuer", B)
        ]:
            entry = plan_entry("web", A, subject="CN=other.example.test",
                               issuer=old_issuer)
            m.classify_existing_certificate_families([entry])
            m.selective_hold([entry], baseline, {("dev", "web"): approved})
            self.assertEqual(entry["status"], "HOLD")
            self.assertNotIn("SUBJECT_CHANGE_REVIEWED", entry["certificate_comparison"]["flags"])

    def test_subject_only_approval_cannot_release_no_ingress_hold(self):
        entry = plan_entry("web", A, subject="CN=other.example.test", refs=[])
        m.classify_existing_certificate_families([entry])
        m.selective_hold([entry], A, {("dev", "web"): {
            "approval_scope": "SUBJECT_ONLY", "old_fingerprint": A,
            "reason": "Owner reviewed the planned Subject change"}})
        self.assertEqual(entry["status"], "HOLD")
        self.assertIn("NO_INGRESS_TLS_REFERENCE", entry["message"])


    def test_ingress_mismatch_becomes_hold_and_not_released(self):
        entry = plan_entry("web", A, san=["*.wrong.test"])
        self.assertEqual(entry["status"], "BLOCKED") # historical SAN differs
        m.classify_existing_certificate_families([entry])
        m.selective_hold([entry], A, {})
        self.assertEqual(entry["status"], "HOLD")
        blocked = plan_entry("web", A, refs=[{"host": "uncovered.other.test"}])
        self.assertEqual(blocked["status"], "BLOCKED")
        m.classify_existing_certificate_families([blocked])
        m.selective_hold([blocked], A, {})
        self.assertEqual(blocked["status"], "HOLD")
        self.assertIn("Underlying guardrail", blocked["message"])
        with self.assertRaises(m.Stop):
            other = plan_entry("web", A, refs=[{"host": "uncovered.other.test"}])
            m.classify_existing_certificate_families([other])
            m.selective_hold([other], A, {
                ("dev", "web"): {"old_fingerprint": A, "reason": "not safe to bypass"}
            })

    def test_staged_only_approval_releases_only_missing_ingress_hold(self):
        staged = plan_entry("unused", A, refs=[])
        m.classify_existing_certificate_families([staged])
        m.selective_hold([staged], A, {
            ("dev", "unused"): {
                "old_fingerprint": A, "approval_scope": "STAGED_ONLY",
                "reason": "Owner approved pre-provisioned future application Secret"
            }
        })
        self.assertEqual(staged["status"], "READY")
        self.assertIn("EXPLICITLY_REVIEWED_EXCEPTION",
                      staged["certificate_comparison"]["flags"])

    def test_staged_only_approval_cannot_bypass_changed_issuer(self):
        bad = plan_entry("unused", A, refs=[], issuer="CN=DifferentIssuer")
        m.classify_existing_certificate_families([bad])
        m.selective_hold([bad], A, {
            ("dev", "unused"): {
                "old_fingerprint": A, "approval_scope": "STAGED_ONLY",
                "reason": "Owner approved pre-provisioned future application Secret"
            }
        })
        self.assertEqual(bad["status"], "HOLD")
        self.assertIn("ISSUER_CHANGED", bad["message"])

    def test_missing_ingress_is_hold_by_default(self):
        e = plan_entry("staged", A, refs=[])
        m.classify_existing_certificate_families([e])
        m.selective_hold([e], A, {})
        self.assertEqual(e["status"], "HOLD")
        self.assertIn("NO_INGRESS_TLS_REFERENCE", e["message"])

    def test_subject_scoped_csv_is_pinned_to_both_subjects(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "subject-reviewed.csv"
            e = plan_entry("web", A, subject="CN=previous.example.test")
            row = ("context,cluster_uid,new_fingerprint,namespace,secret_name,"
                   "old_fingerprint,reason,approval_scope,old_subject,new_subject\n"
                   "uat,cluster-uid," + NEW + ",dev,web," + A +
                   ",Approved by service owner for same SAN, SUBJECT_ONLY,"
                   "CN=previous.example.test,CN=*.example.test\n")
            p.write_text(row)
            got = m.load_reviewed_holds(p, [e], context="uat",
                                        cluster_uid="cluster-uid", new_fingerprint=NEW)
            self.assertEqual(got[("dev", "web")]["approval_scope"], "SUBJECT_ONLY")
            p.write_text(row.replace("CN=previous.example.test,CN=*.example.test",
                                     "CN=wrong.example.test,CN=*.example.test"))
            with self.assertRaisesRegex(m.Stop, "subject evidence mismatch"):
                m.load_reviewed_holds(p, [e], context="uat",
                                      cluster_uid="cluster-uid", new_fingerprint=NEW)

    def test_reviewed_holds_file_is_pinned_to_secret_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "reviewed.csv"
            p.write_text(
                "context,cluster_uid,new_fingerprint,namespace,secret_name,old_fingerprint,reason\n"
                "uat,cluster-uid," + NEW + ",dev,web," + A + ",Approved existing web TLS issuance by application owner\n"
            )
            entry = plan_entry("web", A)
            got = m.load_reviewed_holds(p, [entry], context="uat",
                                        cluster_uid="cluster-uid", new_fingerprint=NEW)
            self.assertEqual(got[("dev", "web")]["old_fingerprint"], A)
            p.write_text(
                "context,cluster_uid,new_fingerprint,namespace,secret_name,old_fingerprint,reason\n"
                "uat,cluster-uid," + NEW + ",dev,web," + B + ",Approved existing web TLS issuance by application owner\n"
            )
            with self.assertRaisesRegex(m.Stop, "fingerprint mismatch"):
                m.load_reviewed_holds(p, [entry], context="uat",
                                      cluster_uid="cluster-uid", new_fingerprint=NEW)
            p.write_text(
                "context,cluster_uid,new_fingerprint,namespace,secret_name,old_fingerprint,reason\n"
                "uat,WRONG," + NEW + ",dev,web," + A + ",Approved existing web TLS issuance by application owner\n"
            )
            with self.assertRaisesRegex(m.Stop, "cluster/context"):
                m.load_reviewed_holds(p, [entry], context="uat",
                                      cluster_uid="cluster-uid", new_fingerprint=NEW)

    def test_report_lists_hold_and_skip_but_never_claims_endpoint_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = {"schema_version": 1, "entries": [
                {"namespace": "dev", "secret_name": "web", "status": "READY"},
                {"namespace": "dev", "secret_name": "held", "status": "HOLD"},
                {"namespace": "dev", "secret_name": "done", "status": "SKIPPED"}]}
            plan["plan_id"] = m.plan_id(plan)
            path = root / "renewal-plan.json"
            path.write_text(json.dumps(plan))
            journal = {"plan_id": plan["plan_id"], "status": "COMPLETE_ENDPOINT_UNVERIFIED",
                       "items": [{"namespace": "dev", "secret_name": "web",
                                  "status": "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                                  "post_resource_version": "10"}]}
            (root / "execution-journal.json").write_text(json.dumps(journal))
            m.cmd_report(types.SimpleNamespace(plan=str(path)))
            with (root / "renewal-report.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual([r["status"] for r in rows], [
                "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                "HOLD_IDENTITY_REVIEW", "SKIPPED_ALREADY_CURRENT"])

    def test_held_endpoint_run_gets_mixed_not_full_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = {
                "namespace": "dev", "secret_name": "web",
                "status": "READY", "uid": "uid", "ingress_refs": [{"host": "web.example.test"}]
            }
            held = {"namespace": "dev", "secret_name": "held", "status": "HOLD",
                    "message": "Certificate family mismatch"}
            plan = {"schema_version": 1, "context": "dev", "cluster_uid": "cluster",
                    "new_fingerprint": NEW, "new_sans": ["*.example.test"],
                    "entries": [entry, held]}
            plan["plan_id"] = m.plan_id(plan)
            path = root / "renewal-plan.json"
            path.write_text(json.dumps(plan))
            journal = {"plan_id": plan["plan_id"], "status": "COMPLETE_ENDPOINT_UNVERIFIED",
                       "items": [{"namespace": "dev", "secret_name": "web",
                                  "status": "SECRET_UPDATED_ENDPOINT_UNVERIFIED",
                                  "post_resource_version": "2"}]}
            (root / "execution-journal.json").write_text(json.dumps(journal))
            endpoints = root / "endpoints.csv"
            endpoints.write_text("namespace,secret_name,hostname\ndev,web,web.example.test\n")
            args = types.SimpleNamespace(
                context="dev", plan=str(path), endpoints=str(endpoints),
                ca_bundle=None, staged_targets=None)
            with patch.object(m, "cluster_id", return_value="cluster"), \
                 patch.object(m, "secret", return_value={
                     "metadata": {"uid": "uid", "resourceVersion": "2"}
                 }), \
                 patch.object(m, "old_info", return_value={"fingerprint": NEW}), \
                 patch.object(m, "ingress_references", return_value={
                     "web": [{"host": "web.example.test"}]
                 }), \
                 patch.object(m, "probe_https_endpoint", return_value={
                     "fingerprint": NEW, "tls_version": "TLSv1.3"
                 }):
                m.cmd_verify_endpoints(args)
            self.assertEqual(json.loads((root / "execution-journal.json").read_text())["status"],
                             "COMPLETE_WITH_HELD_TARGETS")
            m.cmd_report(args)
            text = (root / "renewal-report.csv").read_text()
            self.assertIn("HOLD_IDENTITY_REVIEW", text)
            self.assertIn("ENDPOINT_VERIFIED", text)


if __name__ == "__main__":
    unittest.main()
