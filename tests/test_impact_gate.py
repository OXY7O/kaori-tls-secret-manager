"""Change-impact routing tests: fail closed and preserve TLS safety coverage."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "scripts/ci/impact_gate.py"
spec = importlib.util.spec_from_file_location("kaori_impact_gate", FILE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
BASE, HEAD = "a" * 40, "b" * 40


class ImpactGateTests(unittest.TestCase):
    def test_docs_only_uses_documentation_suite(self):
        result = gate.classify({"README.md", "docs/OPERATOR-GUIDE.md"})
        self.assertEqual(result["mode"], "docs")
        self.assertEqual(result["tests"], ["test_documentation_integrity.py"])

    def test_touched_test_runs_only_its_own_suite(self):
        result = gate.classify({"tests/test_branding_assets.py"})
        self.assertEqual(result["mode"], "selected")
        self.assertEqual(result["tests"], ["test_branding_assets.py"])

    def test_ci_utility_change_runs_mapped_tests(self):
        result = gate.classify({"scripts/ci/changed_python_quality.py", "ruff.toml"})
        self.assertEqual(result["mode"], "selected")
        self.assertEqual(result["tests"],
                         ["test_changed_python_quality.py", "test_required_check_policy.py"])

    def test_examples_use_inventory_and_endpoint_tests(self):
        result = gate.classify({
            "scripts/kubernetes/tls-secret-manager/examples/endpoints.csv"})
        self.assertEqual(result["tests"],
                         ["test_tls_inventory.py", "test_tls_staged_endpoints.py"])

    def test_any_mutation_runtime_change_runs_all_regressions(self):
        paths = {"README.md", "scripts/tls_crud.py", "tests/test_documentation_integrity.py"}
        self.assertEqual(gate.classify(paths)["mode"], "full")
        self.assertEqual(gate.classify({"scripts/kubernetes/tls-secret-manager/tls_ops.py"})["mode"],
                         "full")

    def test_security_and_gate_changes_force_full(self):
        for path in [".github/workflows/ci.yml", ".github/workflows/codeql.yml",
                     "scripts/ci/impact_gate.py", ".github/dependabot.yml", "VERSION"]:
            with self.subTest(path=path):
                self.assertEqual(gate.classify({path})["mode"], "full")

    def test_unknown_deletion_renames_and_empty_diff_fail_closed(self):
        self.assertEqual(gate.classify(set())["mode"], "full")
        self.assertEqual(gate.classify({"mystery.bin"})["mode"], "full")
        self.assertEqual(gate.classify({"../private.pem"})["mode"], "full")
        self.assertEqual(gate.classify({"<initial-push>"})["mode"], "full")

    def test_unknown_future_python_module_falls_back_to_full(self):
        # A newly introduced utility cannot silently escape test coverage.
        result = gate.classify({"scripts/ci/new_helper.py", "docs/FAQ.md"})
        self.assertEqual(result["mode"], "full")
        self.assertEqual(result["reason"], "unmapped path (fail closed)")

    def test_scheduled_or_manual_runs_always_full(self):
        for event in ["schedule", "workflow_dispatch"]:
            self.assertEqual(gate.classify({"docs/CODE-QUALITY.md"}, event=event)["mode"], "full")

    def test_change_detection_preserves_names_with_null_separator(self):
        with tempfile.TemporaryDirectory() as td:
            expected = b"docs/README.md\0scripts/tls_crud.py\0"
            with patch.object(gate.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, expected)) as runner:
                output = gate.changed_paths(BASE, HEAD, root=Path(td))
            self.assertEqual(output, {"docs/README.md", "scripts/tls_crud.py"})
            args = runner.call_args.args[0]
            self.assertIn("--no-renames", args)
            self.assertIn("-z", args)

    def test_git_diff_failure_must_not_skip_validation(self):
        with patch.object(gate.subprocess, "run",
                          side_effect=subprocess.CalledProcessError(128, "git")):
            with self.assertRaises(subprocess.CalledProcessError):
                gate.changed_paths(BASE, HEAD)

    def test_invalid_sha_is_rejected_before_git_call(self):
        with self.assertRaisesRegex(ValueError, "full commit SHAs"):
            gate.changed_paths("main", HEAD)

    def test_full_suite_selection_is_invoked_by_same_process(self):
        with patch.object(gate.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(gate.run_tests({"mode": "full", "tests": []}, root=ROOT), 0)
        self.assertIn("discover", run.call_args.args[0])

    def test_selected_missing_test_module_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing/unsafe"):
            gate.run_tests({"mode": "selected", "tests": ["test_missing.py"]}, root=ROOT)


if __name__ == "__main__":
    unittest.main()
