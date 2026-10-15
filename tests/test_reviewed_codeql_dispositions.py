"""Safety tests for explicit one-time alert dispositions; no API writes."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "ci" /
          "reviewed_codeql_dispositions.py")
spec = importlib.util.spec_from_file_location("disposition_review", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def records():
    return [
        {"number": number, "state": "open", "rule": m.RULE,
         "path": path, "line": line, "tool": "CodeQL"}
        for number, (path, line) in sorted(m.EXPECTED.items())
    ]


class ReviewedDispositionTests(unittest.TestCase):
    def test_preflight_approves_only_the_31_reviewed_alerts(self):
        self.assertEqual(len(m.EXPECTED), 31)
        self.assertNotIn(36, m.EXPECTED)
        self.assertTrue(m.validate(records()))

    def test_preflight_rejects_unexpected_open_alert(self):
        data = records()
        data.append({**data[0], "number": 1000})
        with self.assertRaisesRegex(ValueError, "do not exactly match"):
            m.validate(data)

    def test_preflight_rejects_changed_sink(self):
        data = records()
        data[0]["line"] += 1
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            m.validate(data)

    def test_preflight_rejects_changed_rule(self):
        data = records()
        data[0]["rule"] = "py/clear-text-logging-sensitive-key-values"
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            m.validate(data)

    def test_consequence_is_accepted_metadata_risk_not_claimed_fix(self):
        self.assertIn("RESOURCE IDENTITY", m.REASON)
        self.assertIn("residual metadata exposure accepted", m.REASON)
        self.assertNotIn("secure forever", m.REASON)


if __name__ == "__main__":
    unittest.main()
