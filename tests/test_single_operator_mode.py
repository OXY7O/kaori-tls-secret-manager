"""Single-operator Create/Delete safety: all tests use synthetic data only."""
import argparse
from contextlib import redirect_stdout
from io import StringIO
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT / "scripts" / "tls_crud.py"
spec = importlib.util.spec_from_file_location("kaori_crud_one_operator", CODE)
crud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crud)
sys.path.insert(0, str(ROOT / "scripts" / "kubernetes" / "tls-secret-manager"))
import tls_secret_wizard as wizard


def cli_args(**kw):
    default = {"action": "DELETE", "approve": "plan123",
               "confirm_target": "sandbox/unused-tls",
               "operator_mode": True,
               "operator_ack": "DELETE sandbox/unused-tls",
               "operator_attested": True}
    default.update(kw)
    return argparse.Namespace(**default)


PLAN = {"action": "DELETE", "plan_id": "plan123",
        "context": "test-context", "cluster_uid": "test-cluster",
        "namespace": "sandbox", "secret": "unused-tls"}


class SingleOperatorModeTests(unittest.TestCase):
    def test_signed_mode_remains_required_by_default(self):
        a = cli_args(operator_mode=False)
        with self.assertRaisesRegex(crud.Stop, "Signed approval"):
            crud.validate_approval(a, PLAN)

    def test_operator_mode_never_runs_headless(self):
        with patch.object(crud.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(crud.Stop, "interactive terminal"):
                crud.validate_approval(cli_args(), PLAN)

    def test_exact_target_and_attestation_required(self):
        with patch.object(crud.sys.stdin, "isatty", return_value=True):
            for kwargs, expected in [
                ({"operator_ack": "DELETE sandbox/other-secret"}, "typed operation"),
                ({"operator_attested": False}, "external consumers"),
                ({"approve": "wrong-id"}, "PLAN ID"),
                ({"confirm_target": "sandbox/other"}, "Target confirmation"),
            ]:
                with self.subTest(kwargs=kwargs), self.assertRaisesRegex(crud.Stop, expected):
                    crud.validate_approval(cli_args(**kwargs), PLAN)
            crud.validate_approval(cli_args(), PLAN)

    def test_operator_mode_rejects_unrecoverable_backup_before_delete(self):
        with tempfile.TemporaryDirectory() as folder:
            draft = {k: v for k, v in PLAN.items() if k != "plan_id"}
            path, plan = crud.write_plan(folder, {**draft, "uid": "uid-1",
                                                 "resource_version": "10",
                                                 "old_fingerprint": "synthetic"})
            recover = Path(folder) / "recovery.agekey"
            recover.write_text("SYNTHETIC PRIVATE KEY", encoding="utf-8")
            recover.chmod(0o600)
            original = {"metadata": {"namespace": "sandbox", "name": "unused-tls"},
                        "type": "kubernetes.io/tls", "data": {"tls.crt": "test", "tls.key": "private"}}
            def backup(src, dest, recipient):
                dest.write_bytes(b"ENCRYPTED-SYNTHETIC")
                return dest
            args = cli_args(plan=str(path), approve=plan["plan_id"],
                            namespace="sandbox", context="test-context",
                            secret="unused-tls", backup_recipient="age1example",
                            backup_identity=str(recover))
            with patch.object(crud.sys.stdin, "isatty", return_value=True), \
                 patch.object(crud, "ensure_same_target", return_value=original), \
                 patch.object(crud, "age_backup", side_effect=backup), \
                 patch.object(crud, "call", return_value=b"WRONG BACKUP"), \
                 patch.object(crud, "kube", side_effect=AssertionError("No Kubernetes write")):
                with self.assertRaisesRegex(crud.Stop, "recovery verification failed"):
                    crud.apply(args)
            self.assertFalse(list(Path(folder).glob("*-journal.json")),
                             "No Kubernetes write must be attempted before recovery roundtrip")

    def test_create_from_wizard_uses_no_signing_artifacts(self):
        args = types.SimpleNamespace(context=None)
        responses = iter(["test-tls", "", "PROCEED",
                          "CREATE sandbox/test-tls"])
        with patch.object(wizard, "exec_read", side_effect=[
            "dev-context\n", '{"items":[{"metadata":{"name":"sandbox"}}]}']), \
             patch.object(wizard, "choose", side_effect=["dev-context", "sandbox"]), \
             patch.object(wizard, "ask", side_effect=lambda *a, **kw: next(responses)), \
             patch.object(wizard, "choose_certificate_inputs",
                          return_value=("cert.pem", "private.key", None)), \
             patch.object(wizard, "crud_command", side_effect=[
                 {"plan": "/tmp/create-plan.json", "plan_id": "plan123"},
                 {"status": "COMPLETE_SECRET_VERIFIED", "journal": "/tmp/journal.json"}]) as cmd, \
             redirect_stdout(StringIO()):
            wizard.crud_wizard(args, "create")
        self.assertEqual(cmd.call_count, 2)
        apply_tokens = cmd.call_args.args
        self.assertEqual(apply_tokens[1], "create")
        self.assertIn("--operator-mode", apply_tokens)
        self.assertNotIn("--approval-record", apply_tokens)
        self.assertNotIn("--approval-signature", apply_tokens)

    def test_held_delete_shows_named_resources_without_write_or_recovery_setup(self):
        args = types.SimpleNamespace(context=None)
        hold = {"status": "HOLD", "action": "DELETE",
                "target": "sandbox/in-use-tls",
                "reason": "SECRET_IN_USE",
                "blockers": ["Ingress TLS reference: sandbox/web",
                             "Pod dependency: sandbox/frontend"],
                "evidence": "/private/delete-hold.json"}
        with patch.object(wizard, "exec_read", side_effect=[
            "dev-context\n", '{"items":[{"metadata":{"name":"sandbox"}}]}']), \
             patch.object(wizard, "choose", side_effect=["dev-context", "sandbox"]), \
             patch.object(wizard, "ask", side_effect=["in-use-tls", ""]), \
             patch.object(wizard, "local_recovery_identity",
                          side_effect=AssertionError("HOLD must not set up key")), \
             patch.object(wizard, "crud_command", return_value=hold) as cmd, \
             redirect_stdout(StringIO()) as output:
            result = wizard.crud_wizard(args, "delete")
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(cmd.call_count, 1)
        text = output.getvalue()
        self.assertIn("DELETE ON HOLD", text)
        self.assertIn("Ingress TLS reference: sandbox/web", text)
        self.assertIn("Pod dependency: sandbox/frontend", text)
        self.assertIn("No executable plan", text)

    def test_delete_plan_only_does_not_run_write(self):
        args = types.SimpleNamespace(context=None)
        with patch.object(wizard, "exec_read", side_effect=[
            "dev-context\n", '{"items":[{"metadata":{"name":"sandbox"}}]}']), \
             patch.object(wizard, "choose", side_effect=["dev-context", "sandbox"]), \
             patch.object(wizard, "ask", side_effect=[
                 "unused-tls", "", ""]), \
             patch.object(wizard, "local_recovery_identity",
                          return_value=(Path("/secure/recovery.agekey"), "age1" + "x"*45)), \
             patch.object(wizard, "crud_command", return_value={
                 "plan": "/tmp/delete-plan.json", "plan_id": "plan123"}) as cmd, \
             redirect_stdout(StringIO()):
            wizard.crud_wizard(args, "delete")
        self.assertEqual(cmd.call_count, 1)
        self.assertEqual(cmd.call_args.args[1], "plan-delete")

    def test_delete_guided_flow_uses_single_operator_without_signatures(self):
        args = types.SimpleNamespace(context=None)
        answers = iter(["unused-tls", "", "PROCEED", "UNUSED",
                        "DELETE sandbox/unused-tls"])
        with patch.object(wizard, "exec_read", side_effect=[
            "dev-context\n", '{"items":[{"metadata":{"name":"sandbox"}}]}']), \
             patch.object(wizard, "choose", side_effect=["dev-context", "sandbox"]), \
             patch.object(wizard, "ask", side_effect=lambda *a, **kw: next(answers)), \
             patch.object(wizard, "local_recovery_identity",
                          return_value=(Path("/private/recovery.agekey"), "age1" + "x"*45)), \
             patch.object(wizard, "crud_command", side_effect=[
                 {"plan": "/tmp/delete-plan.json", "plan_id": "plan123"},
                 {"status": "COMPLETE_ABSENCE_VERIFIED",
                  "journal": "/tmp/delete-journal.json"}]) as cmd, \
             redirect_stdout(StringIO()):
            wizard.crud_wizard(args, "delete")
        self.assertEqual(cmd.call_count, 2)
        a = [str(v) for v in cmd.call_args.args]
        self.assertEqual(a[1], "delete")
        self.assertIn("--operator-mode", a)
        self.assertIn("--operator-attested", a)
        self.assertIn("DELETE sandbox/unused-tls", a)
        self.assertIn("--backup-identity", a)
        self.assertIn("/private/recovery.agekey", a)
        self.assertNotIn("--approval-record", a)
        self.assertNotIn("--approval-signature", a)
        self.assertNotIn("--approval-trust-key", a)

    def test_delete_wizard_requires_unused_attestation_before_write(self):
        args = types.SimpleNamespace(context=None)
        with patch.object(wizard, "exec_read", side_effect=[
            "dev-context\n", '{"items":[{"metadata":{"name":"sandbox"}}]}']), \
             patch.object(wizard, "choose", side_effect=["dev-context", "sandbox"]), \
             patch.object(wizard, "ask", side_effect=[
                 "unused-tls", "", "PROCEED", "NO"]), \
             patch.object(wizard, "local_recovery_identity",
                          return_value=(Path("/secure/recovery.agekey"), "age1" + "x"*45)), \
             patch.object(wizard, "crud_command", return_value={
                 "plan": "/tmp/delete-plan.json", "plan_id": "plan123"}) as cmd, \
             redirect_stdout(StringIO()):
            with self.assertRaisesRegex(Exception, "external consumer safety"):
                wizard.crud_wizard(args, "delete")
        self.assertEqual(cmd.call_count, 1)


if __name__ == "__main__":
    unittest.main()
