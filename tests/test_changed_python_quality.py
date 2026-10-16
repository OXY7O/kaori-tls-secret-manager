"""Offline tests for path-aware Ruff selection. No network or real cluster."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/ci/changed_python_quality.py"
spec = importlib.util.spec_from_file_location("changed_python_quality", SCRIPT)
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)

BASE = "1" * 40
HEAD = "2" * 40


class ChangedPythonQualityTests(unittest.TestCase):
    def test_only_modified_existing_python_paths_are_selected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests/changed.py").write_text("x = 1\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts/module.py").write_text("y = 2\n", encoding="utf-8")
            changed = b"tests/changed.py\0scripts/module.py\0deleted.py\0docs/readme.md\0"
            with patch.object(quality.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, changed)) as command:
                files = quality.changed_python_files(BASE, HEAD, root=root)
            self.assertEqual(files, ["scripts/module.py", "tests/changed.py"])
            self.assertIn("--diff-filter=ACMR", command.call_args.args[0])
            self.assertEqual(command.call_args.kwargs["cwd"], root)

    def test_missing_or_malformed_sha_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "40-character"):
            quality.changed_python_files("main", HEAD)

    def test_initial_push_checks_all_tracked_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x = 1\n", encoding="utf-8")
            with patch.object(quality.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, b"a.py\0")) as cmd:
                files = quality.changed_python_files("0" * 40, HEAD, root=root)
            self.assertEqual(files, ["a.py"])
            self.assertIn("ls-files", cmd.call_args.args[0])

    def test_document_only_change_skips_install_and_lint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(quality.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, b"")):
                files = quality.changed_python_files(BASE, HEAD, root=root)
            output = root / "github-output"
            record = root / "paths.json"
            quality.write_detection(files, record, output)
            self.assertEqual(json.loads(record.read_text()), [])
            self.assertEqual(output.read_text().strip(), "has_python=false")

    def test_lint_uses_no_shell_and_preserves_ruff_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = root / "changed.json"
            payload.write_text(json.dumps(["tests/test_changed_python_quality.py"]))
            with patch.object(quality.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 1)) as cmd:
                code = quality.lint_files(payload)
            self.assertEqual(code, 1)
            self.assertEqual(cmd.call_args.args[0][:4],
                             ["ruff", "check", "--no-cache", "--output-format=github"])
            self.assertFalse(cmd.call_args.kwargs.get("shell", False))

    def test_lint_rejects_deleted_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "changed.json"
            payload.write_text(json.dumps(["deleted.py"]))
            with self.assertRaisesRegex(ValueError, "Unsafe or missing"):
                quality.lint_files(payload)


if __name__ == "__main__":
    unittest.main()
