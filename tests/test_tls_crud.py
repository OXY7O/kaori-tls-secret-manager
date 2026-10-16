"""Synthetic-only, no live cluster, no real secret material."""
import argparse
import base64
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import importlib.util
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "tls_crud.py"
spec = importlib.util.spec_from_file_location("tls_crud", SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def obj(name="demo-tls", cert=b"SYNTHETIC CERTIFICATE"):
    return {"metadata": {"name": name, "namespace": "demo", "uid": "uid-demo-1",
                         "resourceVersion": "20"}, "type": "kubernetes.io/tls",
            "data": {"tls.crt": base64.b64encode(cert).decode(),
                     "tls.key": base64.b64encode(b"SYNTHETIC SECRET MATERIAL").decode()}}


def args(**kw):
    defaults = dict(context="sandbox", namespace="demo", secret="demo-tls", cert="cert.pem",
                    key="key.pem", ca_bundle=None, workspace="/tmp/test-kaori")
    defaults.update(kw)
    return argparse.Namespace(**defaults)


class CrudSafetyTests(unittest.TestCase):
    def test_unsafe_resource_names_fail_closed(self):
        for ns, name in [("../demo", "demo"), ("demo", "-abc"), ("demo", "aaa/other"),
                         ("demo", "name\n--force"), ("", "demo")]:
            with self.subTest(ns=ns, name=name), self.assertRaises(m.Stop):
                m.valid_target(ns, name)

    def test_create_non_overwrite_blocks_before_plan(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(m, "validate_source", return_value=(b"cert", b"key", {"fingerprint": "f", "not_after": "later", "sans": ["site.example.test"]})), \
             patch.object(m, "context_uid", return_value="cluster-demo"), \
             patch.object(m, "find_target", return_value=obj()), \
             patch.object(m, "kube_json", side_effect=AssertionError("No further API")):
            with self.assertRaisesRegex(m.Stop, "already exists"):
                m.plan_create(args(workspace=tmp))

    def test_delete_plan_blocks_controller_ownership(self):
        target = obj()
        target["metadata"]["ownerReferences"] = [{"kind": "Certificate"}]
        with patch.object(m, "find_target", return_value=target), \
             patch.object(m, "dependency_evidence", side_effect=AssertionError("Should stop")):
            with self.assertRaisesRegex(m.DeleteHold, "CONTROLLER_MANAGED"):
                m.plan_delete(args())

    def test_delete_plan_blocks_live_references(self):
        with patch.object(m, "find_target", return_value=obj()), \
             patch.object(m, "dependency_evidence", return_value=["Ingress TLS reference"]), \
             patch.object(m, "fingerprint_from_der_or_pem", side_effect=AssertionError("Should stop")):
            with self.assertRaisesRegex(m.DeleteHold, "SECRET_IN_USE"):
                m.plan_delete(args())

    def test_dependency_scanner_fails_closed_on_missing_rbac(self):
        with patch.object(m, "kube_json", side_effect=m.Stop("kubectl returned failure (1)")):
            with self.assertRaises(m.Stop):
                m.dependency_evidence("sandbox", "demo", "demo-tls")

    def test_dependency_scanner_checks_ingress_pod_gateway(self):
        ing = {"items": [{"spec": {"tls": [{"secretName": "demo-tls"}]}}]}
        pods = {"items": [{"spec": {"volumes": [{"secret": {"secretName": "demo-tls"}}]}}]}
        gw = {"items": [{"metadata": {"namespace": "demo"}, "spec": {"listeners": [
            {"tls": {"certificateRefs": [{"name": "demo-tls"}]}}]}}]}
        with patch.object(m, "kube_json", side_effect=[ing, pods, {"items": []}, gw]), \
             patch.object(m, "kube", return_value=b"gateways.gateway.networking.k8s.io\n"):
            blockers = m.dependency_evidence("sandbox", "demo", "demo-tls")
        self.assertEqual(blockers, ["Gateway TLS certificateRef", "Ingress TLS reference", "Pod dependency"])

    def test_gateway_discovery_does_not_accept_similar_resource_names(self):
        # A similarly named CRD must never be treated as the Gateway API.
        ing = {"items": []}
        pods = {"items": []}
        similar = b"malicious-gateways.gateway.networking.k8s.io\n"
        with patch.object(m, "kube_json", side_effect=[ing, pods, {"items": []}]) as read, \
             patch.object(m, "kube", return_value=similar):
            self.assertEqual(m.dependency_evidence("sandbox", "demo", "demo-tls"), [])
        self.assertEqual(read.call_count, 3)

    def test_detailed_dependency_evidence_identifies_exact_consumers(self):
        ingress = {"items": [{"metadata": {"name": "web", "namespace": "demo"},
                              "spec": {"tls": [{"secretName": "demo-tls"}]}}]}
        pods = {"items": [{"metadata": {"name": "web-76c", "namespace": "demo"},
                           "spec": {"volumes": [{"secret": {"secretName": "demo-tls"}}]}}]}
        gateway = {"items": [{"metadata": {"name": "edge", "namespace": "demo"},
                              "spec": {"listeners": [
                                  {"tls": {"certificateRefs": [{"name": "demo-tls"}]}}]}}]}
        with patch.object(m, "kube_json", side_effect=[ingress, pods, {"items": []}, gateway]), \
             patch.object(m, "kube", return_value=b"gateways.gateway.networking.k8s.io\n"):
            found = m.dependency_evidence("sandbox", "demo", "demo-tls", detailed=True)
        self.assertEqual(found, ["Gateway TLS certificateRef: demo/edge",
                                 "Ingress TLS reference: demo/web",
                                 "Pod dependency: demo/web-76c"])

    def test_cross_namespace_gateway_reference_blocks_target_delete(self):
        gateway = {"metadata": {"namespace": "edge", "name": "edge-gw"},
                   "spec": {"listeners": [{"tls": {"certificateRefs": [
                       {"group": "", "kind": "Secret",
                        "name": "demo-tls", "namespace": "demo"}]}}]}}
        with patch.object(m, "kube_json", side_effect=[
                {"items": []}, {"items": []}, {"items": []}, {"items": [gateway]}]), \
             patch.object(m, "kube", return_value=b"gateways.gateway.networking.k8s.io\n"):
            refs = m.dependency_evidence("ctx", "demo", "demo-tls", detailed=True)
        self.assertEqual(refs, ["Gateway TLS certificateRef: edge/edge-gw"])

    def test_dormant_deployment_and_cronjob_hold_delete(self):
        # No active Pod exists; templates still guarantee future Secret use.
        deploy = {"kind": "Deployment", "metadata": {"name": "sleeping", "namespace": "demo"},
                  "spec": {"replicas": 0, "template": {"spec": {
                      "containers": [{"name": "web", "envFrom": [
                          {"secretRef": {"name": "demo-tls"}}]}]}}}}
        cron = {"kind": "CronJob", "metadata": {"name": "scheduled", "namespace": "demo"},
                "spec": {"suspend": True, "jobTemplate": {"spec": {"template": {
                    "spec": {"volumes": [{"secret": {"secretName": "demo-tls"}}]}}}}}}
        with patch.object(m, "kube_json", side_effect=[
                {"items": []}, {"items": []}, {"items": [deploy, cron]}]), \
             patch.object(m, "kube", return_value=b""):
            refs = m.dependency_evidence("sandbox", "demo", "demo-tls", detailed=True)
        self.assertEqual(refs, ["CronJob template reference: demo/scheduled",
                                "Deployment template reference: demo/sleeping"])

    def test_workload_scan_forbidden_or_malformed_fails_closed(self):
        with patch.object(m, "kube_json", side_effect=[
                {"items": []}, {"items": []}, m.Stop("RBAC denied")]):
            with self.assertRaisesRegex(m.Stop, "RBAC denied"):
                m.dependency_evidence("sandbox", "demo", "demo-tls")
        with patch.object(m, "kube_json", side_effect=[
                {"items": []}, {"items": []}, {"items": [
                    {"kind": "Deployment", "spec": {}}]}]):
            with self.assertRaisesRegex(m.Stop, "Malformed workload"):
                m.dependency_evidence("sandbox", "demo", "demo-tls")

    def test_delete_ownership_reports_a_named_hold(self):
        target = obj()
        target["metadata"]["ownerReferences"] = [
            {"kind": "Certificate", "name": "managed-demo"}]
        with patch.object(m, "find_target", return_value=target), \
             patch.object(m, "dependency_evidence",
                          side_effect=AssertionError("No scan for owned target")):
            with self.assertRaises(m.DeleteHold) as caught:
                m.plan_delete(args())
        self.assertEqual(caught.exception.reason, "CONTROLLER_MANAGED")
        self.assertIn("Controller owner: Certificate/managed-demo",
                      caught.exception.details)

    def test_incomplete_dependency_scan_holds_without_creating_plan(self):
        with patch.object(m, "find_target", return_value=obj()), \
             patch.object(m, "dependency_evidence",
                          side_effect=m.Stop("kubectl returned failure (1)")), \
             patch.object(m, "write_plan",
                          side_effect=AssertionError("No executable plan")):
            with self.assertRaises(m.DeleteHold) as caught:
                m.plan_delete(args())
        self.assertEqual(caught.exception.reason, "DEPENDENCY_SCAN_INCOMPLETE")

    def test_delete_hold_json_evidence_is_not_executable_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            hold = m.DeleteHold("SECRET_IN_USE", ["Ingress TLS reference: demo/web"])
            src = args(workspace=str(Path(tmp) / "private"),
                       context="sandbox", namespace="demo", secret="demo-tls")
            with patch.object(m, "plan_delete", side_effect=hold), \
                 redirect_stdout(StringIO()) as output:
                rc = m.main(["--context", "sandbox", "plan-delete",
                             "--namespace", "demo", "--secret", "demo-tls",
                             "--workspace", src.workspace])
            self.assertEqual(rc, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["reason"], "SECRET_IN_USE")
            self.assertTrue(Path(result["evidence"]).is_file())
            self.assertFalse(list(Path(src.workspace).glob("*-plan.json")))
            self.assertFalse(list(Path(src.workspace).glob("*-journal.json")))
            with self.assertRaisesRegex(m.Stop, "Invalid plan path"):
                m.read_plan(result["evidence"])

    def test_immutable_plan_id_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, plan = m.write_plan(tmp, {"action": "DELETE", "context": "sandbox", "cluster_uid": "demo"})
            _, recovered = m.read_plan(path)
            self.assertEqual(recovered["plan_id"], plan["plan_id"])
            altered = json.loads(path.read_text())
            altered["context"] = "another-cluster"
            path.write_text(json.dumps(altered))
            with self.assertRaisesRegex(m.Stop, "integrity mismatch"):
                m.read_plan(path)

    def test_preexisting_journal_blocks_write_before_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {"action": "DELETE", "context": "sandbox", "cluster_uid": "cluster",
                                                "namespace": "demo", "secret": "demo-tls"})
            journal = Path(tmp) / f"delete-{plan['plan_id']}-journal.json"
            journal.write_text("{}")
            with patch.object(m, "validate_approval", side_effect=AssertionError("Must not reapprove")):
                with self.assertRaisesRegex(m.Stop, "Prior execution journal"):
                    m.apply(args(action="DELETE", plan=str(planpath)))

    def test_delete_uses_server_side_uid_rv_preconditions_and_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {"action": "DELETE", "context": "sandbox", "cluster_uid": "cluster",
                                                "namespace": "demo", "secret": "demo-tls", "uid": "uid-demo-1",
                                                "resource_version": "20", "old_fingerprint": "f"})
            deletes = []
            def kube_call(ctx, *parts, **kwargs):
                deletes.append((ctx, parts))
                return b'{}'
            def backup(orig, target, recipient):
                target.write_text("FAKE ENCRYPTED BACKUP ONLY")
                return target
            with patch.object(m, "validate_approval"), \
                 patch.object(m, "ensure_same_target", return_value=obj()), \
                 patch.object(m, "age_backup", side_effect=backup), \
                 patch.object(m, "kube", side_effect=kube_call), \
                 patch.object(m, "find_target", return_value=None):
                result = m.apply(args(action="DELETE", plan=str(planpath), backup_recipient="age1example"))
            self.assertEqual(result["status"], "COMPLETE_ABSENCE_VERIFIED")
            self.assertEqual(deletes[0][1][0], "delete")
            self.assertIn("--raw=/api/v1/namespaces/demo/secrets/demo-tls", deletes[0][1])
            options = json.loads((Path(tmp) / f"{plan['plan_id']}-delete-options.json").read_text())
            self.assertEqual(options["preconditions"], {"uid": "uid-demo-1", "resourceVersion": "20"})
            journal = json.loads(Path(result["journal"]).read_text())
            self.assertNotIn("tls.key", json.dumps(journal))

    def test_failed_delete_keeps_uncertain_journal_and_prevents_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {"action": "DELETE", "context": "sandbox", "cluster_uid": "cluster",
                                                "namespace": "demo", "secret": "demo-tls", "uid": "uid-demo-1",
                                                "resource_version": "20", "old_fingerprint": "f"})
            def fake_backup(orig, target, recipient):
                target.write_text("SYNTHETIC CIPHERTEXT")
            kwargs = args(action="DELETE", plan=str(planpath), backup_recipient="age1placeholder")
            with patch.object(m, "validate_approval"), \
                 patch.object(m, "ensure_same_target", return_value=obj()), \
                 patch.object(m, "age_backup", side_effect=fake_backup), \
                 patch.object(m, "kube", side_effect=m.Stop("simulated cluster failure")):
                with self.assertRaises(m.Stop):
                    m.apply(kwargs)
                with self.assertRaisesRegex(m.Stop, "Prior execution journal"):
                    m.apply(kwargs)
            journal = json.loads((Path(tmp) / f"delete-{plan['plan_id']}-journal.json").read_text())
            self.assertEqual(journal["status"], "MUTATION_UNCERTAIN")

    def test_delete_recovery_reconcile_never_mutates(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {
                "action": "DELETE", "context": "sandbox", "cluster_uid": "cluster1",
                "namespace_uid": "ns1", "namespace": "demo", "secret": "demo-tls",
                "uid": "old", "resource_version": "7", "old_fingerprint": "fp"})
            journal = Path(tmp) / f"delete-{plan['plan_id']}-journal.json"
            journal.write_text(json.dumps({"action": "DELETE",
                "plan_id": plan["plan_id"], "status": "MUTATION_UNCERTAIN"}))
            with patch.object(m, "context_uid", return_value="cluster1"), \
                 patch.object(m, "find_target", return_value=None), \
                 patch.object(m, "kube_json", return_value={"metadata": {"uid": "ns1"}}), \
                 patch.object(m, "kube", side_effect=AssertionError("Never mutate during reconcile")):
                result = m.delete_recovery_evidence(args(plan=str(planpath)))
            self.assertEqual(result["observation"], "OBSERVED_ABSENT")
            self.assertEqual(result["journal_status"], "MUTATION_UNCERTAIN")
            self.assertFalse(result["restore_eligible"])

    def test_reconcile_eligibility_requires_backup_and_namespace_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {
                "action": "DELETE", "context": "sandbox", "cluster_uid": "cluster1",
                "namespace_uid": "ns1", "namespace": "demo", "secret": "demo-tls",
                "uid": "old", "resource_version": "7", "old_fingerprint": "fp"})
            (Path(tmp) / f"delete-{plan['plan_id']}-journal.json").write_text(json.dumps({
                "action": "DELETE", "plan_id": plan["plan_id"],
                "status": "COMPLETE_ABSENCE_VERIFIED", "prior_uid": "old"}))
            backup = Path(tmp) / f"delete-{plan['plan_id']}-backup.age"
            with patch.object(m, "context_uid", return_value="cluster1"), \
                 patch.object(m, "find_target", return_value=None), \
                 patch.object(m, "kube_json", return_value={"metadata": {"uid": "ns1"}}):
                missing = m.delete_recovery_evidence(args(plan=str(planpath)))
                self.assertFalse(missing["restore_eligible"])
                self.assertFalse(missing["backup_present"])
                backup.write_bytes(b"SYNTHETIC ENCRYPTED MATERIAL")
                backup.chmod(0o600)
                eligible = m.delete_recovery_evidence(args(plan=str(planpath)))
                self.assertTrue(eligible["restore_eligible"])
            with patch.object(m, "context_uid", return_value="cluster1"), \
                 patch.object(m, "find_target", return_value=None), \
                 patch.object(m, "kube_json", return_value={"metadata": {"uid": "changed-ns"}}):
                drift = m.delete_recovery_evidence(args(plan=str(planpath)))
                self.assertFalse(drift["restore_eligible"])
                self.assertFalse(drift["namespace_identity_match"])

    def test_restore_blocks_unknown_delete_journal_without_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {
                "action": "DELETE", "context": "sandbox", "cluster_uid": "cluster1",
                "namespace_uid": "ns1", "namespace": "demo", "secret": "demo-tls",
                "uid": "old", "resource_version": "7", "old_fingerprint": "fp"})
            (Path(tmp) / f"delete-{plan['plan_id']}-journal.json").write_text(json.dumps({
                "action": "DELETE", "plan_id": plan["plan_id"],
                "status": "MUTATION_UNCERTAIN", "prior_uid": "old"}))
            target = args(plan=str(planpath), operator_mode=True, approve=plan["plan_id"],
                          confirm_target="demo/demo-tls", operator_ack="RESTORE demo/demo-tls")
            with patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(m, "context_uid", return_value="cluster1"), \
                 patch.object(m, "kube_json", return_value={"metadata": {"uid": "ns1"}}), \
                 patch.object(m, "kube", side_effect=AssertionError("No write on uncertain state")):
                with self.assertRaisesRegex(m.Stop, "not verified complete"):
                    m.restore_deleted_secret(target)

    def test_restore_is_create_only_and_verifies_original_encrypted_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {
                "action": "DELETE", "context": "sandbox", "cluster_uid": "cluster1",
                "namespace_uid": "ns1", "namespace": "demo", "secret": "demo-tls",
                "uid": "uid-demo-1", "resource_version": "20", "old_fingerprint": "fp"})
            original = obj()
            (Path(tmp) / f"delete-{plan['plan_id']}-journal.json").write_text(json.dumps({
                "action": "DELETE", "plan_id": plan["plan_id"],
                "status": "COMPLETE_ABSENCE_VERIFIED", "prior_uid": "uid-demo-1"}))
            ciphertext = Path(tmp) / f"delete-{plan['plan_id']}-backup.age"
            ciphertext.write_bytes(b"ENCRYPTED TEST FIXTURE")
            ciphertext.chmod(0o600)
            identity = Path(tmp) / "recovery.agekey"
            identity.write_text("SYNTHETIC IDENTITY")
            identity.chmod(0o600)
            restored = {**original, "metadata": {
                **original["metadata"], "uid": "new-uid", "resourceVersion": "25"}}
            target = args(plan=str(planpath), operator_mode=True, approve=plan["plan_id"],
                          confirm_target="demo/demo-tls", operator_ack="RESTORE demo/demo-tls",
                          backup_identity=str(identity))
            writes = []
            def write(ctx, *argv, **kw):
                writes.append((argv, kw))
                return b"{}"
            with patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(m, "context_uid", return_value="cluster1"), \
                 patch.object(m, "kube_json", return_value={"metadata": {"uid": "ns1"}}), \
                 patch.object(m, "find_target", side_effect=[None, None, restored]), \
                 patch.object(m, "call", return_value=m.canonical(original)), \
                 patch.object(m, "fingerprint_from_der_or_pem", return_value="fp"), \
                 patch.object(m, "kube", side_effect=write):
                result = m.restore_deleted_secret(target)
            self.assertEqual(result["status"], "COMPLETE_SECRET_RESTORED")
            self.assertEqual(writes[0][0][2], "create")
            sent = json.loads(writes[0][1]["payload"])
            self.assertEqual(sent["data"], original["data"])
            self.assertNotIn("uid", sent["metadata"])
            journal = json.loads(Path(result["journal"]).read_text())
            self.assertNotIn("tls.key", json.dumps(journal))

    def test_create_submit_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {"action": "CREATE", "context": "sandbox", "cluster_uid": "cluster",
                                                "namespace": "demo", "secret": "demo-tls",
                                                "new_fingerprint": "f", "cert_sha256": m.digest(b"cert"),
                                                "key_sha256": m.digest(b"key"), "ingress_hosts": []})
            with patch.object(m, "validate_approval"), patch.object(m, "ensure_same_target", return_value=None), \
                 patch.object(m, "validate_source", return_value=(b"cert", b"key", {"fingerprint": "f"})), \
                 patch.object(m, "kube_json", return_value={"items": []}), \
                 patch.object(m, "kube", side_effect=lambda *a, **k: b"{}") as called, \
                 patch.object(m, "find_target", return_value={**obj(), "data": {
                     **obj()["data"], "tls.key": base64.b64encode(b"key").decode()}}), \
                 patch.object(m, "fingerprint_from_der_or_pem", return_value="f"):
                result = m.apply(args(action="CREATE", plan=str(planpath)))
            self.assertEqual(result["status"], "COMPLETE_SECRET_VERIFIED")
            self.assertIn("create", called.call_args.args)
            self.assertIn("-f", called.call_args.args)
            self.assertIn("-", called.call_args.args)
            self.assertNotIn(b"key", Path(result["journal"]).read_bytes())

    def test_missing_signed_approval_stops_before_mutation(self):
        plan = {"action": "DELETE", "plan_id": "abc123", "context": "sandbox",
                "cluster_uid": "cluster", "namespace": "demo", "secret": "demo-tls"}
        request = args(approve="abc123", confirm_target="demo/demo-tls",
                       approval_record="/missing/approval.json",
                       approval_signature="/missing/approval.sig",
                       approval_trust_key="/missing/trust.pem")
        with self.assertRaisesRegex(m.Stop, "Signed approval"):
            m.validate_approval(request, plan)

    def test_delete_uid_rv_drift_stops_before_backup(self):
        plan = {"context": "sandbox", "cluster_uid": "cluster", "namespace": "demo",
                "secret": "demo-tls", "action": "DELETE", "uid": "old-uid",
                "resource_version": "11"}
        with patch.object(m, "context_uid", return_value="cluster"), \
             patch.object(m, "find_target", return_value=obj()), \
             patch.object(m, "dependency_evidence", side_effect=AssertionError("Must stop before scan")):
            with self.assertRaisesRegex(m.Stop, "identity drifted"):
                m.ensure_same_target(plan)

    def test_age_backup_failure_blocks_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(m, "call", side_effect=m.Stop("age encryption failed")):
                with self.assertRaises(m.Stop):
                    m.age_backup(obj(), Path(tmp) / "backup.age", "age1" + "x" * 55)
            self.assertFalse((Path(tmp) / "backup.age").exists())

    def test_operation_scope_cannot_differ_from_immutable_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            planpath, plan = m.write_plan(tmp, {"action": "DELETE", "context": "sandbox",
                "cluster_uid": "cluster", "namespace": "demo", "secret": "demo-tls"})
            for kw in ({"context": "other"}, {"namespace": "other"},
                       {"secret": "different"}):
                with self.subTest(kw=kw), \
                     patch.object(m, "validate_approval", side_effect=AssertionError("must stop before approval")):
                    with self.assertRaisesRegex(m.Stop, "Command target/context"):
                        m.apply(args(action="DELETE", plan=str(planpath), **kw))

    def test_update_plan_refuses_san_identity_change(self):
        original = obj()
        with patch.object(m, "validate_source", return_value=(b"newcert", b"newkey", {
                "sans": ["different.example.test"], "fingerprint": "new", "not_after": "later"})), \
             patch.object(m, "find_target", return_value=original), \
             patch.object(m, "certificate_sans", return_value=["site.example.test"]), \
             patch.object(m, "ingress_hosts", side_effect=AssertionError("must stop before ingress reads")):
            with self.assertRaisesRegex(m.Stop, "SAN identity change"):
                m.plan_update(args())

    def test_update_plan_blocks_immutable_secret(self):
        original = obj()
        original["immutable"] = True
        with patch.object(m, "validate_source", return_value=(b"cert", b"key", {
                "sans": ["site.example.test"], "fingerprint": "new", "not_after": "later"})), \
             patch.object(m, "find_target", return_value=original), \
             patch.object(m, "certificate_sans", side_effect=AssertionError("Must stop")):
            with self.assertRaisesRegex(m.Stop, "Immutable"):
                m.plan_update(args())

    def test_update_plan_binds_old_target_and_new_certificate(self):
        original = obj()
        info = {"sans": ["site.example.test"], "fingerprint": "new", "not_after": "later"}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(m, "validate_source", return_value=(b"cert", b"key", info)), \
             patch.object(m, "find_target", return_value=original), \
             patch.object(m, "certificate_sans", return_value=["site.example.test"]), \
             patch.object(m, "ingress_hosts", return_value=["site.example.test"]), \
             patch.object(m, "fingerprint_from_der_or_pem", return_value="old"), \
             patch.object(m, "context_uid", return_value="cluster"), \
             patch.object(m.Path, "read_bytes", side_effect=[b"cert", b"key"]):
            planfile, plan = m.plan_update(args(workspace=tmp))
            self.assertEqual(plan["action"], "UPDATE")
            self.assertEqual(plan["uid"], "uid-demo-1")
            self.assertEqual(plan["resource_version"], "20")
            self.assertTrue(plan["requires_encrypted_backup"])
            self.assertNotIn("tls.key", planfile.read_text())

    def test_update_uses_resourceversion_cas_and_encrypted_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            planfile, plan = m.write_plan(tmp, {"action": "UPDATE", "context": "sandbox",
                "cluster_uid": "cluster", "namespace": "demo", "secret": "demo-tls",
                "uid": "uid-demo-1", "resource_version": "20", "old_fingerprint": "old",
                "new_fingerprint": "new", "cert_sha256": m.digest(b"cert"),
                "key_sha256": m.digest(b"key"), "ingress_hosts": []})
            observed = obj(cert=b"cert")
            observed["data"]["tls.key"] = base64.b64encode(b"key").decode()
            observed["metadata"]["resourceVersion"] = "21"
            requests = []
            def stub_kube(ctx, *parts, **kwargs):
                requests.append((parts, json.loads(kwargs["payload"])))
                return b"{}"
            def stub_backup(orig, dest, recipient):
                dest.write_bytes(b"SYNTHETIC ENCRYPTED BACKUP")
                return dest
            with patch.object(m, "validate_approval"), \
                 patch.object(m, "ensure_same_target", return_value=obj()), \
                 patch.object(m, "validate_source", return_value=(b"cert", b"key", {"fingerprint": "new"})), \
                 patch.object(m, "ingress_hosts", return_value=[]), \
                 patch.object(m.Path, "read_bytes", side_effect=[b"cert", b"key"]), \
                 patch.object(m, "age_backup", side_effect=stub_backup) as backup, \
                 patch.object(m, "kube", side_effect=stub_kube), \
                 patch.object(m, "find_target", return_value=observed), \
                 patch.object(m, "fingerprint_from_der_or_pem", return_value="new"):
                result = m.apply(args(action="UPDATE", plan=str(planfile),
                                      backup_recipient="age1synthetic"))
            self.assertEqual(result["status"], "COMPLETE_SECRET_VERIFIED")
            backup.assert_called_once()
            self.assertIn("replace", requests[0][0])
            self.assertEqual(requests[0][1]["metadata"]["resourceVersion"], "20")
            self.assertEqual(requests[0][1]["data"]["tls.crt"], base64.b64encode(b"cert").decode())
            self.assertNotIn("tls.key", Path(result["journal"]).read_text())

    def test_failed_update_records_uncertainty_and_never_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            planfile, plan = m.write_plan(tmp, {"action": "UPDATE", "context": "sandbox",
                "cluster_uid": "cluster", "namespace": "demo", "secret": "demo-tls",
                "uid": "uid-demo-1", "resource_version": "20", "old_fingerprint": "old",
                "new_fingerprint": "new", "cert_sha256": m.digest(b"cert"),
                "key_sha256": m.digest(b"key"), "ingress_hosts": []})
            params = args(action="UPDATE", plan=str(planfile), backup_recipient="age1example")
            def backup(orig, path, recipient):
                path.write_bytes(b"SYNTHETIC CIPHERTEXT")
            with patch.object(m, "validate_approval"), \
                 patch.object(m, "ensure_same_target", return_value=obj()), \
                 patch.object(m, "validate_source", return_value=(b"cert", b"key", {"fingerprint": "new"})), \
                 patch.object(m, "ingress_hosts", return_value=[]), \
                 patch.object(m.Path, "read_bytes", side_effect=[b"cert", b"key"]), \
                 patch.object(m, "age_backup", side_effect=backup), \
                 patch.object(m, "kube", side_effect=m.Stop("simulated stale resourceVersion")):
                with self.assertRaisesRegex(m.Stop, "simulated stale"):
                    m.apply(params)
                with self.assertRaisesRegex(m.Stop, "Prior execution journal"):
                    m.apply(params)
            journal = json.loads((Path(tmp)/f"update-{plan['plan_id']}-journal.json").read_text())
            self.assertEqual(journal["status"], "MUTATION_UNCERTAIN")

    def test_private_workspace_not_inside_repository(self):
        with self.assertRaisesRegex(m.Stop, "outside the source repository"):
            m.private_workspace(SCRIPT.parent.parent / "example-unsafe-evidence")

    def test_inventory_outputs_metadata_without_secret_material(self):
        other = {"metadata": {"name": "regular-opaque"}, "type": "Opaque",
                 "data": {"private": "DO-NOT-EXPOSE"}}
        tls = obj()
        with patch.object(m, "kube_json", return_value={"items": [tls, other]}), \
             patch.object(m, "fingerprint_from_der_or_pem", return_value="synthetic-fp"), \
             redirect_stdout(StringIO()) as out:
            rc = m.main(["--context", "sandbox", "inventory", "--namespace", "demo"])
        self.assertEqual(rc, 0)
        details = json.loads(out.getvalue())
        self.assertEqual(details["tls_secrets"][0]["secret"], "demo-tls")
        self.assertEqual(details["tls_secrets"][0]["fingerprint"], "synthetic-fp")
        self.assertNotIn("tls.key", out.getvalue())
        self.assertNotIn("DO-NOT-EXPOSE", out.getvalue())
        self.assertNotIn("SYNTHETIC SECRET MATERIAL", out.getvalue())

    def test_existing_workspace_permissions_are_not_automatically_relaxed(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "existing"
            work.mkdir(mode=0o755)
            work.chmod(0o755)
            with self.assertRaisesRegex(m.Stop, "private 0700"):
                m.private_workspace(work)
            self.assertEqual(work.stat().st_mode & 0o777, 0o755)

    def test_cli_help_requires_no_cluster(self):
        with patch.object(m, "kube", side_effect=AssertionError("Unexpected Kubernetes")), \
             redirect_stdout(StringIO()) as output:
            with self.assertRaises(SystemExit) as caught:
                m.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("plan-delete", output.getvalue())


if __name__ == "__main__":
    unittest.main()
