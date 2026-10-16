"""Offline Inventory read resilience: no cluster calls, no Secret payload logging."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("inventory_resilience", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def proc(stdout=b"", stderr=b"", code=0):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=code)


class InventoryResilience(unittest.TestCase):
    def test_defaults_and_limits(self):
        self.assertEqual(m.inventory_options(types.SimpleNamespace()), (90, 100, 2))
        for overrides in (
            {"read_timeout_seconds": 19},
            {"read_timeout_seconds": 301},
            {"chunk_size": 9},
            {"chunk_size": 501},
            {"read_retries": 3},
            {"read_retries": -1},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(m.Stop):
                m.inventory_options(types.SimpleNamespace(**overrides))

    def test_secret_list_uses_pagination_and_longer_read_timeout(self):
        with patch.object(m.subprocess, "run", return_value=proc(b"web-tls kubernetes.io/tls\n")) as call:
            result = m.inventory_k("cluster-a", "payments", "secrets",
                                   timeout_seconds=90, chunk_size=100, retries=0,
                                   output_args=["-o", "custom-columns=NAME:.metadata.name,TYPE:.type", "--no-headers"])
        self.assertIn(b"web-tls", result)
        args = call.call_args.args[0]
        self.assertEqual(args[0], "kubectl")
        self.assertIn("--context", args)
        self.assertIn("--request-timeout=90s", args)
        self.assertIn("--chunk-size=100", args)
        self.assertIn("-n", args)
        self.assertEqual(call.call_args.kwargs["timeout"], 105)

    def test_get_has_no_list_chunk_flag(self):
        with patch.object(m.subprocess, "run", return_value=proc(b"{}")) as call:
            m.inventory_k("cluster-a", "payments", "secret", name="web-tls", retries=0)
        args = call.call_args.args[0]
        self.assertNotIn("--chunk-size=100", args)
        self.assertEqual(args[-3:], ["web-tls", "-o", "json"])

    def test_timeout_is_retried_only_within_budget(self):
        timeout = proc(stderr=b"client.Timeout or context cancellation while reading body", code=1)
        with patch.object(m.subprocess, "run", side_effect=[
            timeout, timeout, proc(b'{"items":[]}')
        ]) as run, patch.object(m.time, "sleep") as sleep:
            result = m.inventory_k("ops", "ns-a", "ingresses.networking.k8s.io")
        self.assertIn(b"items", result)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_kubectl_client_timeout_is_retried(self):
        with patch.object(m.subprocess, "run", side_effect=[
            subprocess.TimeoutExpired(["kubectl"], 105),
            proc(b'{"items":[]}')
        ]) as run, patch.object(m.time, "sleep"):
            result = m.inventory_k("ops", None, "namespaces")
        self.assertIn(b"items", result)
        self.assertEqual(run.call_count, 2)

    def test_access_denied_is_not_retried_or_exposed(self):
        secret = b'private-token-dont-print'
        err = b'Error from server (Forbidden): ' + secret
        with patch.object(m.subprocess, "run", return_value=proc(stderr=err, code=1)) as run:
            with self.assertRaises(m.Stop) as caught:
                m.inventory_k("ops", "dev", "secrets")
        self.assertEqual(run.call_count, 1)
        message = str(caught.exception)
        self.assertIn("INVENTORY_INCOMPLETE", message)
        self.assertIn("namespace=dev", message)
        self.assertIn("verb=LIST", message)
        self.assertIn("cause=ACCESS_DENIED", message)
        self.assertNotIn(secret.decode(), message)

    def test_exhausted_timeout_is_incomplete_not_success(self):
        with patch.object(m.subprocess, "run", return_value=proc(
            stderr=b'net/http: request canceled (Client.Timeout while reading body)', code=1
        )) as run, patch.object(m.time, "sleep"):
            with self.assertRaises(m.Stop) as caught:
                m.inventory_k("ops", "team", "secrets")
        self.assertEqual(run.call_count, 3)
        self.assertIn("INVENTORY_INCOMPLETE", str(caught.exception))
        self.assertIn("attempts=3", str(caught.exception))
        self.assertIn("verb=LIST", str(caught.exception))

    def test_invalid_api_json_is_incomplete(self):
        with patch.object(m.subprocess, "run", return_value=proc(b'not json')):
            with self.assertRaisesRegex(m.Stop, "INVENTORY_INCOMPLETE.*INVALID_API_RESPONSE"):
                m.inventory_json("ops", "team", "secrets")

    def test_secret_get_api_error_cannot_become_certificate_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            nsfile = Path(directory) / "namespace-list"
            nsfile.write_text("payments\n")
            args = types.SimpleNamespace(context="ops-uat", namespaces=nsfile,
                                         runs_dir=Path(directory), warn_days=30)
            with patch.object(m, "ingress_references", return_value={}), \
                 patch.object(m, "tls_secret_names", return_value=["web-tls"]), \
                 patch.object(m, "inventory_json",
                              side_effect=m.Stop("INVENTORY_INCOMPLETE: timeout")), \
                 patch.object(m, "new_run") as report:
                with self.assertRaisesRegex(m.Stop, "INVENTORY_INCOMPLETE"):
                    m.cmd_discover(args)
            report.assert_not_called()
            self.assertEqual(list(Path(directory).glob("*/inventory.csv")), [])

    def test_certificate_malformed_is_still_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            nsfile = Path(directory) / "namespace-list"
            nsfile.write_text("payments\n")
            args = types.SimpleNamespace(context="ops-uat", namespaces=nsfile,
                                         runs_dir=Path(directory), warn_days=30)
            obj = {"type": "kubernetes.io/tls", "data": {"tls.crt": "x", "tls.key": "y"}}
            with patch.object(m, "ingress_references", return_value={}), \
                 patch.object(m, "tls_secret_names", return_value=["web-tls"]), \
                 patch.object(m, "inventory_json", return_value=obj), \
                 patch.object(m, "old_info", side_effect=m.Stop("Malformed certificate")):
                m.cmd_discover(args)
            reports = list(Path(directory).glob("*/inventory.csv"))
            self.assertEqual(len(reports), 1)
            self.assertIn("INVALID", reports[0].read_text())


if __name__ == "__main__":
    unittest.main()
