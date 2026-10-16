"""Guard required CI contexts against accidental path-filter deadlocks."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RequiredCheckPolicyTests(unittest.TestCase):
    def test_required_ruff_job_always_reports_for_main_pull_requests(self):
        workflow = (ROOT / ".github/workflows/python-quality.yml").read_text(encoding="utf-8")
        self.assertIn("name: Python Quality (Ruff)", workflow)
        # GitHub skips status entirely if pull_request has paths filters.
        pull_request_event = workflow.split("\n  pull_request:", 1)[1].split("\n  push:", 1)[0]
        self.assertIn("branches: [main]", pull_request_event)
        self.assertNotIn("paths:", pull_request_event)

    def test_ruff_install_and_execution_require_actual_python_changes(self):
        workflow = (ROOT / ".github/workflows/python-quality.yml").read_text(encoding="utf-8")
        self.assertIn("id: changed", workflow)
        self.assertIn("has_python == 'true'", workflow)
        self.assertEqual(workflow.count("if: steps.changed.outputs.has_python == 'true'"), 3)

    def test_existing_quality_and_codeql_contexts_are_preserved(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        self.assertIn("name: Quality Gate", ci)
        self.assertIn("name: CodeQL (${{ matrix.language }})", codeql)
        self.assertIn("language: [python, actions]", codeql)


if __name__ == "__main__":
    unittest.main()
