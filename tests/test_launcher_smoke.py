"""Offline launcher smoke tests. Never contact a Kubernetes API."""
import os
from pathlib import Path
import subprocess
import unittest

LAUNCHER = Path(__file__).resolve().parents[1] / "scripts/kaori-tls-secret-manager.sh"


class LauncherSmokeTests(unittest.TestCase):
    def launch(self, *args):
        env = os.environ.copy()
        env.pop("KAORI_LEGACY_DIR", None)
        return subprocess.run(["bash", str(LAUNCHER), *args], env=env,
                              capture_output=True, text=True, timeout=10)

    def test_help_is_local(self):
        result = self.launch("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("wizard", result.stdout)

    def test_doctor_is_local(self):
        result = self.launch("doctor")
        self.assertEqual(result.returncode, 0)
        self.assertIn("no Kubernetes API requests", result.stdout)

    def test_unavailable_wizard_fails_closed(self):
        result = self.launch("wizard", "--help")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not been migrated", result.stderr)

    def test_standalone_crud_remains_available(self):
        result = self.launch("crud", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("plan-create", result.stdout)
        self.assertIn("plan-update", result.stdout)
        self.assertIn("plan-delete", result.stdout)


if __name__ == "__main__":
    unittest.main()
