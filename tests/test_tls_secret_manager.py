"""Offline guardrail unit tests. Never contacts a real Kubernetes API."""
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1] / 'scripts/kubernetes/tls-secret-manager/tls_secret_manager.py'
spec = importlib.util.spec_from_file_location('tlsmanager', CODE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Guards(unittest.TestCase):
    def test_wildcard_one_label_only(self):
        self.assertTrue(m.covers('*.example.test', 'www.example.test'))
        self.assertFalse(m.covers('*.example.test', 'v2.api.example.test'))
        self.assertFalse(m.covers('*.example.test', 'example.test'))
    def test_renew_different_identity_blocks(self):
        old = {'sans':['*.example.test'], 'fingerprint':'a'}
        new = {'sans':['*.other.test'], 'fingerprint':'b'}
        obj = {'metadata':{}}
        self.assertEqual(m.assess(obj, old, new, [], 'renew')[0], 'BLOCKED')
        self.assertEqual(m.assess(obj, old, new, [], 'replace-identity')[0], 'READY')
    def test_replace_still_requires_ingress_hostname_coverage(self):
        old = {'sans':['*.example.test'], 'fingerprint':'a'}
        new = {'sans':['*.other.test'], 'fingerprint':'b'}
        status, reason = m.assess({'metadata':{}}, old, new, [{'host':'api.example.test'}], 'replace-identity')
        self.assertEqual(status, 'BLOCKED')
    def test_allowlist_and_duplicate_target(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p/'namespaces.txt').write_text('app-development\n')
            self.assertEqual(m.allowlist(p/'namespaces.txt'), ['app-development'])
            (p/'targets.csv').write_text('namespace,secret_name,mode,reason\napp-development,tls-secret,renew,\napp-development,tls-secret,renew,\n')
            with self.assertRaises(m.Stop):
                m.targets(p/'targets.csv', m.allowlist(p/'namespaces.txt'))
    def test_plan_tampering_detected(self):
        plan = {'schema_version':1,'plan_id':'wrong', 'entries':[]}
        with self.assertRaises(m.Stop):
            m.assert_plan(plan, types.SimpleNamespace(context='mock',namespaces='none'),b'',{})
    def test_metadata_output_never_includes_key(self):
        o = {'metadata':{'name':'tls-secret'}, 'data':{'tls.key':'SUPER_SECRET'}}
        with patch.object(m,'old_info',return_value={'subject':'CN=*.example.test'}):
            self.assertNotIn('SUPER_SECRET', str(m.old_info(o)))

if __name__ == '__main__':
    unittest.main()
