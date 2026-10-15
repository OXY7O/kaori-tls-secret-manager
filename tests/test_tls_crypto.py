"""Actual local OpenSSL tests with ephemeral synthetic certs; no Kubernetes network."""
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "kaori_tls_crud_crypto",
    Path(__file__).resolve().parents[1] / "scripts" / "tls_crud.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class CertificateValidationTests(unittest.TestCase):
    def test_valid_signed_san_and_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, k = Path(tmp) / "tls.crt", Path(tmp) / "tls.key"
            process = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(k), "-out", str(c), "-days", "2",
                "-subj", "/CN=demo.example.test",
                "-addext", "subjectAltName=DNS:demo.example.test",
                "-addext", "extendedKeyUsage=serverAuth",
            ], capture_output=True, check=True)
            k.chmod(0o600)
            cert, key, detail = m.validate_source(c, k, ca_bundle=c)
            self.assertEqual(detail["sans"], ["demo.example.test"])
            self.assertEqual(len(detail["fingerprint"]), 64)
            self.assertTrue(cert.startswith(b"-----BEGIN CERTIFICATE-----"))
            self.assertTrue(key.startswith(b"-----BEGIN PRIVATE KEY-----"))
            self.assertEqual(m.fingerprint_from_der_or_pem(cert), detail["fingerprint"])
            self.assertEqual(process.returncode, 0)

    def test_local_key_file_rejects_world_readable_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            c, k = Path(tmp) / "tls.crt", Path(tmp) / "tls.key"
            c.write_text("-----BEGIN CERTIFICATE-----\nDUMMY\n")
            k.write_text("-----BEGIN PRIVATE KEY-----\nDUMMY\n")
            k.chmod(0o644)
            with self.assertRaisesRegex(m.Stop, "0600"):
                m.validate_source(c, k)

    def test_failed_approval_does_not_print_key_material(self):
        keytext = "DO-NOT-LOG-KEY"
        with patch.object(m, "kube", side_effect=m.Stop("kubectl permission denied")), \
             redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
            code = m.main(["--context", "sandbox", "inspect", "--namespace", "demo",
                           "--secret", "demo-tls"])
            # find_target uses kube_json, which calls kube; fake access test only.
        self.assertNotIn(keytext, stdout.getvalue() + stderr.getvalue())
        self.assertIn("STOP:", stderr.getvalue())
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
