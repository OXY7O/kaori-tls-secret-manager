"""Synthetic SARIF coverage: no real private keys, cluster names or credentials."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "sarif_triage", ROOT / "scripts" / "ci" / "sarif_triage.py"
)
triage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(triage)


def sample(rule="py/clear-text-logging-sensitive-data", score="8.1"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": []},
                     "extensions": [{"rules": [{
                         "id": rule, "properties": {"security-severity": score}
                     }]}]},
            "results": [{
                "ruleId": rule,
                "message": {"text": "sensitive fixture must NOT enter metadata index"},
                "locations": [{"location": {"physicalLocation": {
                    "artifactLocation": {"uri": "scripts/a.py"},
                    "region": {"startLine": 10}
                }}}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "scripts/a.py"},
                        "region": {"startLine": 5}
                    }}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "scripts/a.py"},
                        "region": {"startLine": 10}
                    }}},
                ]}]}],
            }],
        }],
    }


class SarifTriageTests(unittest.TestCase):
    def test_collect_retains_locations_and_not_messages(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "python.sarif"
            path.write_text(json.dumps(sample()), encoding="utf-8")
            findings = triage.collect(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["path"], "scripts/a.py")
        self.assertEqual(findings[0]["flow_start"]["line"], 5)
        self.assertEqual(findings[0]["flow_end"]["line"], 10)
        self.assertNotIn("sensitive fixture", json.dumps(findings))

    def test_report_groups_multiple_languages(self):
        with tempfile.TemporaryDirectory() as work:
            folder = Path(work)
            (folder / "python.sarif").write_text(json.dumps(sample()), encoding="utf-8")
            (folder / "actions.sarif").write_text(
                json.dumps(sample("actions/missing-workflow-permissions", "5.0")), encoding="utf-8"
            )
            report = triage.build_report(folder)
        self.assertEqual(report["result_count"], 2)
        self.assertEqual(report["severity_counts"], {"high": 1, "medium": 1})

    def test_missing_sarif_fails_closed(self):
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaisesRegex(ValueError, "No SARIF files"):
                triage.build_report(Path(work))

    def test_invalid_schema_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            folder = Path(work)
            (folder / "bad.sarif").write_text('{"version":"0.0","runs":[]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Expected SARIF 2.1.0"):
                triage.build_report(folder)


if __name__ == "__main__":
    unittest.main()
