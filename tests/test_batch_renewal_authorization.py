"""Batch renewal operator authorization regression tests; no Kubernetes writes."""
import importlib.util
from io import StringIO
from pathlib import Path
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager"
sys.path.insert(0, str(HERE))
import tls_secret_wizard as wizard  # noqa: E402

spec = importlib.util.spec_from_file_location("renewal_single_operator", HERE / "tls_secret_manager.py")
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class BatchRenewalAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "plan_id": "fixed-plan-id", "context": "uat",
            "entries": [
                {"status": "READY", "namespace": "web", "secret_name": "app-tls"},
                {"status": "READY", "namespace": "payments", "secret_name": "api-tls"},
                {"status": "HOLD", "namespace": "other", "secret_name": "held-tls"},
            ],
        }
        self.ready = [e for e in self.plan["entries"] if e["status"] == "READY"]
        self.endpoints = [
            {"verification_mode": "SECRET_BOUND"},
            {"verification_mode": "SECRET_BOUND"},
        ]
        self.args = types.SimpleNamespace(
            operator_mode=True, operator_ack="RENEW 2 TLS SECRETS",
            approve="fixed-plan-id", approval_record=None, approval_signature=None
        )

    def test_two_secret_bound_targets_allow_one_authorized_tty_operator(self):
        with patch.object(engine.sys.stdin, "isatty", return_value=True), \
             patch.object(engine, "verify_approval_attestation",
                          side_effect=AssertionError("must not need independent signature")):
            self.assertEqual(engine.authorize_renewal(
                self.plan, self.args, self.ready, self.endpoints), "SINGLE_OPERATOR_BATCH")

    def test_noninteractive_batch_cannot_use_operator_mode(self):
        with patch.object(engine.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(engine.Stop, "interactive TTY"):
                engine.authorize_renewal(self.plan, self.args, self.ready, self.endpoints)

    def test_batch_phrase_and_plan_id_must_match(self):
        for field, bad, message in [
            ("operator_ack", "RENEW 3 TLS SECRETS", "exact batch"),
            ("approve", "wrong-plan-id", "PLAN ID"),
        ]:
            with self.subTest(field=field), patch.object(engine.sys.stdin, "isatty", return_value=True):
                original = getattr(self.args, field)
                setattr(self.args, field, bad)
                with self.assertRaisesRegex(engine.Stop, message):
                    engine.authorize_renewal(self.plan, self.args, self.ready, self.endpoints)
                setattr(self.args, field, original)

    def test_operator_batch_rejects_external_tls_termination(self):
        external = [{"verification_mode": "EXTERNAL_TERMINATION"}]
        with patch.object(engine.sys.stdin, "isatty", return_value=True):
            with self.assertRaisesRegex(engine.Stop, "independently signed"):
                engine.authorize_renewal(self.plan, self.args, self.ready, external)

    def test_operator_batch_does_not_mix_with_signed_record(self):
        self.args.approval_record = "/dummy/signed.json"
        with patch.object(engine.sys.stdin, "isatty", return_value=True):
            with self.assertRaisesRegex(engine.Stop, "cannot be combined"):
                engine.authorize_renewal(self.plan, self.args, self.ready, self.endpoints)

    def test_operator_mode_rejected_for_single_target(self):
        with patch.object(engine.sys.stdin, "isatty", return_value=True):
            with self.assertRaisesRegex(engine.Stop, "only for multi-target"):
                engine.authorize_renewal(self.plan, self.args, self.ready[:1],
                                         self.endpoints[:1])

    def test_ack_without_operator_mode_is_rejected(self):
        self.args.operator_mode = False
        with self.assertRaisesRegex(engine.Stop, "requires --operator-mode"):
            engine.authorize_renewal(self.plan, self.args, self.ready, self.endpoints)

    def test_plain_unsigned_multi_target_still_requires_independent_approval(self):
        self.args.operator_mode = False
        self.args.operator_ack = None
        with self.assertRaisesRegex(engine.Stop, "Signed approval record/signature"):
            engine.authorize_renewal(self.plan, self.args, self.ready, self.endpoints)

    def test_signed_batch_still_supported_and_required_for_external(self):
        self.args.operator_mode = False
        self.args.operator_ack = None
        for endpoints in (self.endpoints, [{"verification_mode": "EXTERNAL_TERMINATION"}]):
            with self.subTest(endpoints=endpoints), \
                 patch.object(engine, "verify_approval_attestation") as verify:
                self.assertEqual(engine.authorize_renewal(
                    self.plan, self.args, self.ready, endpoints), "SIGNED")
                verify.assert_called_once_with(self.plan, self.args, required=True)

    def test_wizard_lists_ready_and_requires_batch_phrase(self):
        with patch.object(wizard, "ask", return_value="RENEW 2 TLS SECRETS") as ask, \
             redirect_stdout(StringIO()) as output:
            result = wizard.confirm_single_operator_batch(self.plan, 2)
        self.assertEqual(result, ["--operator-mode", "--operator-ack", "RENEW 2 TLS SECRETS"])
        self.assertIn("web/app-tls", output.getvalue())
        self.assertIn("payments/api-tls", output.getvalue())
        self.assertNotIn("other/held-tls", output.getvalue())
        self.assertIn("RENEW 2 TLS SECRETS", ask.call_args.args[0])

    def test_wizard_rejects_wrong_phrase_and_duplicate_ready_targets(self):
        with patch.object(wizard, "ask", return_value="YES"):
            with self.assertRaisesRegex(wizard.Stop, "confirmation mismatch"):
                wizard.confirm_single_operator_batch(self.plan, 2)
        self.plan["entries"][1]["namespace"] = "web"
        self.plan["entries"][1]["secret_name"] = "app-tls"
        with patch.object(wizard, "ask", side_effect=AssertionError("Must fail before prompt")):
            with self.assertRaisesRegex(wizard.Stop, "Duplicate READY"):
                wizard.confirm_single_operator_batch(self.plan, 2)
        with self.assertRaisesRegex(wizard.Stop, "READY count differs"):
            wizard.confirm_single_operator_batch(self.plan, 3)


if __name__ == "__main__":
    unittest.main()
