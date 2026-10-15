"""Offline tests for GitHub Code Scanning alert metadata minimization."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "code_scanning_alerts.py"
spec = importlib.util.spec_from_file_location("code_scanning_alerts", SOURCE)
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)


class AlertInventoryTests(unittest.TestCase):
    def test_safe_fields_exclude_sensitive_messages_and_snippets(self):
        raw = {"number": 36, "state": "open",
               "rule": {"id": "py/clear-text-logging-sensitive-data"},
               "tool": {"name": "CodeQL"},
               "most_recent_instance": {"location": {
                   "path": "scripts/cli.py", "start_line": 1676},
                   "message": {"text": "DO_NOT_PRINT_SECRET_VALUE"}},
               "extra_sensitive_payload": "DO_NOT_PRINT_PRIVATE_KEY"}
        item = script.describe(raw)
        self.assertEqual(item["number"], 36)
        self.assertEqual(item["path"], "scripts/cli.py")
        self.assertEqual(item["line"], 1676)
        self.assertEqual(item["state"], "open")
        self.assertEqual(set(item), {"number", "state", "rule", "path",
                                     "line", "tool", "reason"})
        self.assertNotIn("DO_NOT_PRINT", str(item))

    def test_missing_token_refuses_api_request(self):
        with self.assertRaisesRegex(ValueError, "required"):
            script.fetch_open_alerts("OXY7O/kaori-tls-secret-manager", "")


if __name__ == "__main__":
    unittest.main()
