"""Offline safety tests for restoring one TLS Secret from encrypted backup."""
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / 'scripts/kubernetes/tls-secret-manager/tls_secret_manager.py'
spec = importlib.util.spec_from_file_location('tlsmanager_scoped', CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ScopedRollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = ('sample-development', 'portal.example.test-tls')
        self.other = ('monitoring', 'alertmanager-tls')
        self.fp_old = 'a' * 64
        self.fp_new = 'b' * 64
        self.plan = {
            'schema_version': 1, 'context': 'development',
            'cluster_uid': 'known-cluster',
            'new_fingerprint': self.fp_new,
            'entries': [
                {'namespace': self.key[0], 'secret_name': self.key[1],
                 'status': 'READY', 'uid': 'uid-a', 'old_fingerprint': self.fp_old},
                {'namespace': self.other[0], 'secret_name': self.other[1],
                 'status': 'READY', 'uid': 'uid-b', 'old_fingerprint': 'c' * 64},
            ]
        }
        self.plan['plan_id'] = m.plan_id(self.plan)
        self.plan_path = self.root / 'renewal-plan.json'
        self.plan_path.write_text(json.dumps(self.plan))
        self.journal = {
            'plan_id': self.plan['plan_id'],
            'status': 'COMPLETE_ENDPOINT_UNVERIFIED',
            'items': [
                {'namespace': self.key[0], 'secret_name': self.key[1],
                 'status': 'SECRET_UPDATED_ENDPOINT_UNVERIFIED',
                 'post_resource_version': '450063905'},
                {'namespace': self.other[0], 'secret_name': self.other[1],
                 'status': 'SECRET_UPDATED_ENDPOINT_UNVERIFIED',
                 'post_resource_version': '450064000'},
            ]
        }
        (self.root / 'execution-journal.json').write_text(json.dumps(self.journal))
        (self.root / 'backup').mkdir()
        (self.root / 'backup' / 'secrets.age').write_bytes(b'dummy encrypted backup')
        self.old = {'metadata': {
            'namespace': self.key[0], 'name': self.key[1], 'uid': 'uid-a'},
            'type': 'kubernetes.io/tls',
            'data': {'tls.crt': 'old-public-cert', 'tls.key': 'old-sensitive-key'}
        }
        self.current = {'metadata': {
            'namespace': self.key[0], 'name': self.key[1],
            'uid': 'uid-a', 'resourceVersion': '450063905'},
            'type': 'kubernetes.io/tls',
            'data': {'tls.crt': 'new-public-cert', 'tls.key': 'new-sensitive-key'}
        }
        self.after = {'metadata': {
            'namespace': self.key[0], 'name': self.key[1],
            'uid': 'uid-a', 'resourceVersion': '450064501'},
            'type': 'kubernetes.io/tls',
            'data': copy.deepcopy(self.old['data'])}
        self.args = types.SimpleNamespace(
            context='development', plan=str(self.plan_path),
            namespace=self.key[0], secret=self.key[1],
            backup_identity='recovery-identity',
            dry_run=True, approve=None, confirm_target=None
        )
        self.not_after = (dt.datetime.now(dt.timezone.utc) +
                          dt.timedelta(days=15)).isoformat()

    def run_it(self, after=None, current=None, fingerprint_old=None,
               key_ok=True, post_fail=False):
        old = self.old
        current = current or self.current
        after = after or self.after

        def fake_old_info(obj):
            if obj['data']['tls.crt'] == 'old-public-cert':
                return {'fingerprint': fingerprint_old or self.fp_old,
                        'not_after': self.not_after}
            return {'fingerprint': self.fp_new, 'not_after': self.not_after}

        def fake_run(argv, **kwargs):
            self.assertEqual(argv[0], 'age')
            self.assertEqual(argv[1:4], ['-d', '-i', 'recovery-identity'])
            return json.dumps([old]).encode()

        changes = []
        def fake_k(ctx, *args, payload=None):
            self.assertEqual(args[:3], ('replace', '-f', '-'))
            obj = json.loads(payload)
            changes.append(obj)
            if post_fail:
                raise m.Stop('Failed after attempted replace')
            return b'OK'

        def fake_secret(ctx, ns, name):
            self.assertEqual((ns, name), self.key, 'Other targets must not be touched')
            if changes and not post_fail:
                return copy.deepcopy(after)
            return copy.deepcopy(current)

        with patch.object(m, 'cluster_id', return_value='known-cluster'), \
             patch.object(m, 'run', side_effect=fake_run), \
             patch.object(m, 'old_info', side_effect=fake_old_info), \
             patch.object(m, 'secret', side_effect=fake_secret), \
             patch.object(m, 'verify_approval_attestation', return_value=None), \
             patch.object(m, 'k', side_effect=fake_k):
            m.cmd_rollback_target(self.args)
        return changes

    def test_dry_run_does_not_change_any_target_or_journal(self):
        self.assertEqual(self.run_it(), [])
        self.assertEqual(
            json.loads((self.root / 'execution-journal.json').read_text()),
            self.journal)

    def test_actual_rollback_restores_only_selected_target(self):
        self.args.dry_run = False
        self.args.approve = self.plan['plan_id']
        self.args.confirm_target = '/'.join(self.key)
        changes = self.run_it()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['metadata']['name'], self.key[1])
        self.assertEqual(changes[0]['metadata']['resourceVersion'], '450063905')
        self.assertEqual(changes[0]['data'], self.old['data'])
        journal = json.loads((self.root / 'execution-journal.json').read_text())
        self.assertEqual(journal['status'], 'PARTIAL_ROLLBACK_ENDPOINT_UNVERIFIED')
        self.assertEqual(journal['items'][0]['status'], 'ROLLED_BACK_ENDPOINT_UNVERIFIED')
        self.assertEqual(journal['items'][0]['rollback_resource_version'], '450064501')
        self.assertEqual(journal['items'][1], self.journal['items'][1])
        m.cmd_report(types.SimpleNamespace(plan=str(self.plan_path)))
        self.assertIn('ROLLED_BACK_ENDPOINT_UNVERIFIED',
                      (self.root / 'renewal-report.csv').read_text())

    def test_missing_approval_or_target_confirmation_is_fail_closed(self):
        self.args.dry_run = False
        with self.assertRaisesRegex(m.Stop, 'Explicit --approve'):
            self.run_it()
        self.args.approve = self.plan['plan_id']
        self.args.confirm_target = '/'.join(self.other)
        with self.assertRaisesRegex(m.Stop, 'confirm-target'):
            self.run_it()
        self.assertEqual(
            json.loads((self.root / 'execution-journal.json').read_text()),
            self.journal)

    def test_stale_resource_version_refused_before_mutation(self):
        stale = copy.deepcopy(self.current)
        stale['metadata']['resourceVersion'] = 'other-write'
        with self.assertRaisesRegex(m.Stop, 'changed since renewal'):
            self.run_it(current=stale)
        self.assertEqual(
            json.loads((self.root / 'execution-journal.json').read_text()), self.journal)

    def test_old_fingerprint_mismatch_refused(self):
        with self.assertRaisesRegex(m.Stop, 'Original fingerprint differs'):
            self.run_it(fingerprint_old='d' * 64)

    def test_expired_old_certificate_refused(self):
        self.not_after = (dt.datetime.now(dt.timezone.utc) -
                          dt.timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(m.Stop, 'expired'):
            self.run_it()

    def test_post_write_failure_leaves_uncertain_state(self):
        self.args.dry_run = False
        self.args.approve = self.plan['plan_id']
        self.args.confirm_target = '/'.join(self.key)
        with self.assertRaisesRegex(m.Stop, 'Failed after attempted replace'):
            self.run_it(post_fail=True)
        journal = json.loads((self.root / 'execution-journal.json').read_text())
        self.assertEqual(journal['status'], 'PARTIAL_ROLLBACK_UNCERTAIN')
        self.assertEqual(journal['items'][0]['status'], 'ROLLBACK_TARGET_UNKNOWN')
        self.assertEqual(journal['items'][1], self.journal['items'][1])

    def test_scoped_rollback_requires_independently_signed_approval(self):
        self.args.dry_run = False
        self.args.approve = self.plan["plan_id"]
        self.args.confirm_target = "/".join(self.key)
        original = m.verify_approval_attestation
        with patch.object(m, "cluster_id", return_value="known-cluster"), \
             patch.object(m, "run", return_value=json.dumps([self.old]).encode()), \
             patch.object(m, "old_info", side_effect=lambda obj: {
                 "fingerprint": self.fp_old if obj["data"]["tls.crt"] == "old-public-cert"
                 else self.fp_new,
                 "not_after": self.not_after
             }), \
             patch.object(m, "secret", return_value=copy.deepcopy(self.current)), \
             patch.object(m, "verify_approval_attestation", wraps=original):
            with self.assertRaisesRegex(m.Stop, "Signed approval record/signature required"):
                m.cmd_rollback_target(self.args)
        self.assertEqual(json.loads((self.root / "execution-journal.json").read_text()),
                         self.journal)

    def test_full_rollback_write_failure_writes_unknown_before_mutation(self):
        # Limit this test to one candidate to prove write-ahead without touching peers.
        self.plan["entries"] = self.plan["entries"][:1]
        self.plan["plan_id"] = m.plan_id(self.plan)
        self.plan_path.write_text(json.dumps(self.plan))
        journal = {
            "plan_id": self.plan["plan_id"], "status": "COMPLETE_ENDPOINT_UNVERIFIED",
            "items": [copy.deepcopy(self.journal["items"][0])],
        }
        (self.root / "execution-journal.json").write_text(json.dumps(journal))
        args = types.SimpleNamespace(
            context="development", plan=str(self.plan_path),
            approve=self.plan["plan_id"], backup_identity="recovery-identity",
        )
        def fake_run(argv, **kwargs):
            self.assertEqual(argv[0], "age")
            return json.dumps([self.old]).encode()
        def fake_old_info(obj):
            if obj["data"]["tls.crt"] == "old-public-cert":
                return {"fingerprint": self.fp_old, "not_after": self.not_after}
            return {"fingerprint": self.fp_new, "not_after": self.not_after}
        with patch.object(m, "cluster_id", return_value="known-cluster"), \
             patch.object(m, "run", side_effect=fake_run), \
             patch.object(m, "secret", return_value=copy.deepcopy(self.current)), \
             patch.object(m, "old_info", side_effect=fake_old_info), \
             patch.object(m, "verify_approval_attestation", return_value=None), \
             patch.object(m, "k", side_effect=m.Stop("timeout after attempted replace")):
            with self.assertRaisesRegex(m.Stop, "timeout after attempted replace"):
                m.cmd_rollback(args)
        latest = json.loads((self.root / "execution-journal.json").read_text())
        self.assertEqual(latest["status"], "PARTIAL_ROLLBACK_UNCERTAIN")
        self.assertEqual(latest["items"][0]["status"], "ROLLBACK_TARGET_UNKNOWN")

    def test_repeat_rollback_refused(self):
        self.journal['status'] = 'PARTIAL_ROLLBACK_ENDPOINT_UNVERIFIED'
        (self.root / 'execution-journal.json').write_text(json.dumps(self.journal))
        with self.assertRaisesRegex(m.Stop, 'unrolled batch'):
            self.run_it()


if __name__ == '__main__':
    unittest.main()
