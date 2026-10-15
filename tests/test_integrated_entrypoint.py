"""Offline checks for one-repository KAORI entrypoint and preserved wizard."""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "tls-secret-manager.sh"


class IntegratedLauncherTests(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ)
        env.pop("KAORI_LEGACY_DIR", None)
        env["NO_COLOR"] = "1"
        # capture_output only pipes stdout/stderr; without DEVNULL the child
        # inherits the operator\'s real TTY and waits for wizard input.
        # All subprocess smoke tests must explicitly simulate non-interactive stdin.
        return subprocess.run(["bash", str(ENTRY), *args], cwd=ROOT,
                              env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=30)

    def test_no_external_checkout_required_for_diagnostics(self):
        result = self.run_cli("doctor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Original guided wizard and standalone CRUD: included",
                      result.stdout)

    def test_historical_engine_help_is_accessible(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("discover", result.stdout)
        self.assertIn("renew", result.stdout)

    def test_original_wizard_help_does_not_access_cluster(self):
        result = self.run_cli("wizard", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--plain", result.stdout)
        self.assertIn("--workspace", result.stdout)

    def test_crud_engine_help_is_accessible(self):
        result = self.run_cli("crud", "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("plan-create", result.stdout)
        self.assertIn("plan-delete", result.stdout)

    def test_default_without_tty_is_fail_closed(self):
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Interactive TTY required", result.stderr)


if __name__ == "__main__":
    unittest.main()
