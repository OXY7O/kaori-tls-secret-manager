"""Pre-merge negative-path regression. No Kubernetes API connections or writes."""
import base64
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager/tls_secret_manager.py"
spec = importlib.util.spec_from_file_location("tlsmanager_safety", CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
A, B = "a" * 64, "b" * 64


class CertificatePurposeSafety(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_client_auth_only_certificate_refused_for_tls_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, cert = root / "key.pem", root / "cert.pem"
            run = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-days", "3", "-subj", "/CN=web.example.test",
                "-addext", "subjectAltName=DNS:web.example.test",
                "-addext", "extendedKeyUsage=clientAuth",
                "-keyout", str(key), "-out", str(cert),
            ], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            key.chmod(0o600)
            with self.assertRaisesRegex(m.Stop, "openssl operation failed"):
                m.verify_source(cert, key, cert)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_server_auth_certificate_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, cert = root / "key.pem", root / "cert.pem"
            run = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-days", "3", "-subj", "/CN=web.example.test",
                "-addext", "subjectAltName=DNS:web.example.test",
                "-addext", "extendedKeyUsage=serverAuth",
                "-keyout", str(key), "-out", str(cert),
            ], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            key.chmod(0o600)
            _, _, details = m.verify_source(cert, key, cert)
            self.assertEqual(details["sans"], ["web.example.test"])

    def test_stored_mismatched_tls_key_fails_closed(self):
        cert = base64.b64encode(b"dummy-public").decode()
        key = base64.b64encode(b"private-sensitive-key").decode()
        obj = {"data": {"tls.crt": cert, "tls.key": key}}
        with patch.object(m, "old_info", return_value={"public_key_hash": m.digest(b"expected")}), \
             patch.object(m, "run", return_value=b"other-public"):
            with self.assertRaisesRegex(m.Stop, "certificate/private key mismatch") as caught:
                m.verify_stored_pair(obj)
        self.assertNotIn("private-sensitive-key", str(caught.exception))


class NonWriteIsolationTests(unittest.TestCase):
    def test_held_and_skipped_targets_are_never_requeried_before_ready_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allow = root / "namespaces.txt"
            allow.write_text("dev\n")
            info = {"fingerprint": B}
            plan = {
                "schema_version": 1, "context": "ctx", "cluster_uid": "uid",
                "source_sha256": m.digest(b"new"), "new_fingerprint": B,
                "allowlist_sha256": m.digest(allow.read_bytes()),
                "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "selection_policy": {"mode": "selective-hold"},
                "entries": [
                    {"namespace": "dev", "secret_name": "independent-held", "status": "HOLD"},
                    {"namespace": "dev", "secret_name": "independent-skipped", "status": "SKIPPED"},
                ],
            }
            plan["plan_id"] = m.plan_id(plan)
            args = types.SimpleNamespace(context="ctx", namespaces=str(allow))
            with patch.object(m, "cluster_id", return_value="uid"), \
                 patch.object(m, "secret", side_effect=AssertionError("Do not read HELD/SKIPPED")), \
                 patch.object(m, "ingress_references",
                              side_effect=AssertionError("Do not read non-write Ingress")):
                m.assert_plan(plan, args, b"new", info)

    def test_held_secret_drift_is_review_not_ready_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = {"context": "ctx", "cluster_uid": "uid", "new_fingerprint": B,
                    "entries": [
                        {"namespace": "dev", "secret_name": "held", "status": "HOLD",
                         "old_fingerprint": A},
                        {"namespace": "dev", "secret_name": "ready", "status": "READY",
                         "old_fingerprint": A},
                    ]}
            path = Path(tmp) / "renewal-plan.json"
            path.write_text(json.dumps(plan))
            def observe(obj):
                return {"fingerprint": A if obj["name"] == "held" else B}
            def get_secret(ctx, ns, name):
                return {"name": name}
            with patch.object(m, "cluster_id", return_value="uid"), \
                 patch.object(m, "secret", side_effect=get_secret), \
                 patch.object(m, "old_info", side_effect=lambda obj: {
                     "fingerprint": "c" * 64 if obj["name"] == "held" else B
                 }), patch("builtins.print") as printed:
                m.cmd_verify(types.SimpleNamespace(context="ctx", plan=str(path)))
            output = "\n".join(str(x) for x in printed.call_args_list)
            self.assertIn("HOLD_DRIFT_REVIEW", output)


class WaveGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root
        self.ns_file = root / "namespaces.txt"
        self.ns_file.write_text("dev\n")
        self.plan_file = root / "renewal-plan.json"
        self.targets = [("dev", "first-tls"), ("dev", "second-tls")]
        self.plan = {
            "schema_version": 1, "context": "ctx", "cluster_uid": "cluster",
            "new_fingerprint": B,
            "entries": [
                {"namespace": ns, "secret_name": name, "uid": name,
                 "mode": "renew", "status": "READY", "old_fingerprint": A,
                 "resource_version": str(i + 1),
                 "ingress_refs": [{"host": f"{name}.example.test"}]}
                for i, (ns, name) in enumerate(self.targets)
            ]
        }
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_file.write_text(json.dumps(self.plan))
        self.endpoint_rows = [{
            "namespace": "dev", "secret_name": name,
            "hostname": f"{name}.example.test", "port": 443,
            "connect_host": f"{name}.example.test",
            "verification_mode": "SECRET_BOUND",
            "expected_endpoint_fingerprint": None,
            "review_reference": "",
        } for _, name in self.targets]
        self.args = types.SimpleNamespace(
            context="ctx", cert="cert.pem", key="key.pem",
            ca_bundle=None, namespaces=self.ns_file, plan=str(self.plan_file),
            approve=self.plan["plan_id"], backup_recipient="age1dummy",
            ack_identity_replacement=False, endpoints=str(root / "endpoints.csv"),
            staged_targets=None, wave_timeout_seconds=10,
        )
        Path(self.args.endpoints).write_text("dummy")
        self.old_objects = {}
        for i, (_, name) in enumerate(self.targets):
            self.old_objects[name] = {
                "metadata": {"namespace": "dev", "name": name, "uid": name,
                             "resourceVersion": str(i+1)},
                "type": "kubernetes.io/tls", "data": {"tls.crt": "old"},
                "leaf": A,
            }
        self.mutations = []

    def execute(self, endpoint_fp=B, fail_after_write=False):
        def fake_secret(ctx, ns, name):
            obj = copy.deepcopy(self.old_objects[name])
            if name in self.mutations:
                obj["metadata"]["resourceVersion"] = "new-" + name
                obj["leaf"] = B
            return obj
        def fake_change(ctx, obj, cert, key):
            self.mutations.append(obj["metadata"]["name"])
            return obj
        def fake_probe(host, dest, port, ca):
            return {"fingerprint": endpoint_fp, "tls_version": "TLSv1.3"}
        with patch.object(m, "verify_source", return_value=(b"cert", b"key", {"fingerprint": B})), \
             patch.object(m, "assert_plan", return_value=None), \
             patch.object(m, "secret", side_effect=fake_secret), \
             patch.object(m, "old_info", side_effect=lambda obj: {"fingerprint": obj["leaf"]}), \
             patch.object(m, "backup_age", side_effect=lambda path, snaps, recipient: (
                 path.parent.mkdir(exist_ok=True), path.write_bytes(b"encrypted"))), \
             patch.object(m, "verify_approval_attestation", return_value=None), \
             patch.object(m, "read_endpoint_targets", return_value=self.endpoint_rows), \
             patch.object(m, "change_secret", side_effect=fake_change), \
             patch.object(m, "probe_https_endpoint", side_effect=fake_probe), \
             patch.object(m.time, "monotonic", side_effect=[0, 999] if fail_after_write else None), \
             patch.object(m.time, "sleep", return_value=None):
            return m.cmd_renew(self.args)

    def test_verified_wave_permits_next_target(self):
        self.execute()
        self.assertEqual(self.mutations, ["first-tls", "second-tls"])
        j = json.loads((self.root / "execution-journal.json").read_text())
        self.assertEqual(j["status"], "COMPLETE_ENDPOINT_UNVERIFIED")
        self.assertTrue(all(i["wave_verification"] == "SECRET_BOUND_ENDPOINT_VERIFIED"
                            for i in j["items"]))

    def test_failed_first_wave_stops_before_next_secret_write(self):
        with self.assertRaisesRegex(m.Stop, "Wave HTTPS verification failed"):
            self.execute(endpoint_fp=A, fail_after_write=True)
        self.assertEqual(self.mutations, ["first-tls"])
        j = json.loads((self.root / "execution-journal.json").read_text())
        self.assertEqual(j["status"], "STOPPED")
        self.assertEqual(j["items"][0]["checkpoint_status"], "SECRET_POST_WRITE_VALIDATED")
        self.assertEqual(len(j["items"]), 1)

    def test_multi_target_without_signed_approval_is_blocked(self):
        with patch.object(m, "verify_source", return_value=(b"cert", b"key", {})), \
             patch.object(m, "assert_plan", return_value=None), \
             patch.object(m, "read_endpoint_targets", return_value=self.endpoint_rows), \
             patch.object(m, "secret", side_effect=AssertionError("No write-preflight reads")):
            with self.assertRaisesRegex(m.Stop, "Signed approval record/signature required"):
                m.cmd_renew(self.args)

    def test_multi_target_requires_mapping_before_backup_or_write(self):
        self.args.endpoints = None
        with patch.object(m, "verify_source", return_value=(b"cert", b"key", {})), \
             patch.object(m, "assert_plan", return_value=None), \
             patch.object(m, "secret", side_effect=AssertionError("No target write read")):
            with self.assertRaisesRegex(m.Stop, "Multi-Secret renewal requires --endpoints"):
                m.cmd_renew(self.args)


class SignedApprovalSafety(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_signed_approval_binds_plan_and_endpoint_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            priv = root / "approver.pem"
            pub = root / "trust.pem"
            record = root / "approval.json"
            sig = root / "approval.sig"
            mapping = root / "endpoints.csv"
            mapping.write_text("approved mapping\n")
            for command in [
                ["openssl", "ecparam", "-name", "prime256v1", "-genkey",
                 "-noout", "-out", str(priv)],
                ["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)],
            ]:
                done = subprocess.run(command, capture_output=True)
                self.assertEqual(done.returncode, 0)
            plan = {"plan_id": "my-plan-id", "context": "dev", "cluster_uid": "cluster-uid"}
            now = dt.datetime.now(dt.timezone.utc)
            data = {
                "schema_version": 1, "action": "RENEW", "target": "",
                "plan_id": "my-plan-id",
                "context": "dev", "cluster_uid": "cluster-uid",
                "approver": "independent-security-reviewer",
                "change_reference": "CHG-APPROVED-20261014",
                "approved_utc": (now - dt.timedelta(minutes=1)).isoformat(),
                "expires_utc": (now + dt.timedelta(minutes=30)).isoformat(),
                "endpoint_sha256": m.digest(mapping.read_bytes()),
                "staged_sha256": "",
            }
            record.write_text(json.dumps(data, sort_keys=True))
            signed = subprocess.run([
                "openssl", "dgst", "-sha256", "-sign", str(priv),
                "-out", str(sig), str(record)], capture_output=True)
            self.assertEqual(signed.returncode, 0)
            args = types.SimpleNamespace(
                endpoints=str(mapping), staged_targets=None,
                approval_record=str(record), approval_signature=str(sig),
                approval_trust_key=str(pub))
            with patch.object(m, "verify_approval_trust_anchor", return_value=None):
                m.verify_approval_attestation(plan, args, required=True)
                mapping.write_text("tampered mapping\n")
                with self.assertRaisesRegex(m.Stop, "endpoint mapping checksum mismatch"):
                    m.verify_approval_attestation(plan, args, required=True)
                mapping.write_text("approved mapping\n")
                data["plan_id"] = "evil-plan"
                record.write_text(json.dumps(data, sort_keys=True))
                with self.assertRaisesRegex(m.Stop, "does not match plan"):
                    m.verify_approval_attestation(plan, args, required=True)
                data["plan_id"] = "my-plan-id"
                record.write_text(json.dumps(data, sort_keys=True) + " ")
                with self.assertRaisesRegex(m.Stop, "openssl operation failed"):
                    m.verify_approval_attestation(plan, args, required=True)

    def test_untrusted_non_root_public_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / "approver-pub.pem"
            pub.write_text("dummy")
            pub.chmod(0o666)
            with self.assertRaisesRegex(m.Stop, "root-owned"):
                m.verify_approval_trust_anchor(pub)


class ExternalTerminationSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "endpoints.csv"
        self.plan = {
            "new_sans": ["*.example.test"],
            "new_fingerprint": B,
            "entries": [{"namespace": "dev", "secret_name": "tls",
                         "status": "READY",
                         "ingress_refs": [{"host": "web.example.test"}]}],
        }

    def csv(self, sha=A, mode="EXTERNAL_TERMINATION", reason="Owner approved independent NGINX certificate"):
        self.path.write_text(
            "namespace,secret_name,hostname,port,connect_host,verification_mode,expected_endpoint_fingerprint,review_reference\n"
            f"dev,tls,web.example.test,443,,{mode},{sha},{reason}\n"
        )

    def test_external_requires_pinned_fp_and_reason(self):
        self.csv(sha="")
        with self.assertRaisesRegex(m.Stop, "requires expected endpoint SHA256"):
            m.read_endpoint_targets(self.path, self.plan)

    def test_external_does_not_claim_secret_bound(self):
        self.csv()
        ep = m.read_endpoint_targets(self.path, self.plan)[0]
        self.assertEqual(ep["verification_mode"], "EXTERNAL_TERMINATION")
        self.assertEqual(ep["expected_endpoint_fingerprint"], A)

    def test_external_without_owner_approval_is_rejected(self):
        self.csv(reason="unreviewed")
        with self.assertRaisesRegex(m.Stop, "requires expected endpoint SHA256"):
            m.read_endpoint_targets(self.path, self.plan)


if __name__ == "__main__":
    unittest.main()
