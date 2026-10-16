"""Offline tests for read-only unified TLS discovery, evidence, and wizard UX."""
import csv
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager"
sys.path.insert(0, str(TOOLS))
import tls_inventory as inv  # noqa: E402 - fixture modules need local TOOL path first
import tls_secret_wizard as wizard  # noqa: E402 - fixture modules need local TOOL path first
import tls_secret_manager as helper  # noqa: E402 - fixture modules need local TOOL path first

A = "a" * 64


class TLSInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "inventory.csv"
        self.references = self.root / "ingress-references.csv"
        self.inventory.write_text(
            "namespace,secret_name,subject,issuer,san,not_before,not_after,"
            "days_remaining,fingerprint_sha256,ingress_count,status\n"
            f"energy-dev,web-tls,,,*.example.test,,2026-11-30T00:00:00+00:00,"
            f"46,{A},2,EXPIRING\n"
            f"chatbot-dev,preprovisioned-tls,,,*.example.test,,2027-02-01T00:00:00+00:00,"
            f"109,{A},0,VALID\n"
            f"monitoring,legacy-tls,,,old.example.test,,2026-01-01T00:00:00+00:00,"
            f"-280,{A},1,EXPIRED\n",
            encoding="utf-8"
        )
        self.references.write_text(
            "namespace,secret_name,ingress,host\n"
            "energy-dev,web-tls,energy-web,www.example.test\n"
            "energy-dev,web-tls,energy-api,api.example.test\n"
            "monitoring,legacy-tls,legacy,legacy.example.test\n"
            "chatbot-dev,absent-secret,unknown-ingress,bad.example.test\n"
            "energy-dev,,default-cert,public.example.test\n",
            encoding="utf-8"
        )

    def test_join_multiple_hosts_no_ingress_and_unresolved_references(self):
        rows, unresolved = inv.join_discovery(self.inventory, self.references)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(unresolved), 2)
        web = next(r for r in rows if r["secret_name"] == "web-tls")
        self.assertEqual(web["ingress_hostnames"],
                         "api.example.test; www.example.test")
        self.assertEqual(web["ingress_count"], 2)
        empty = next(r for r in rows if r["secret_name"] == "preprovisioned-tls")
        self.assertEqual(empty["ingress_usage"], "NO_INGRESS_REFERENCE")
        self.assertIn("UNSPECIFIED_TLS_SECRET", [r["secret_name"] for r in unresolved])
        totals = inv.summary(rows, unresolved)
        self.assertEqual(totals["TLS_SECRETS"], 3)
        self.assertEqual(totals["NAMESPACES"], 3)
        self.assertEqual(totals["NO_INGRESS_REFERENCE"], 1)

    def test_filter_namespace_status_hostname_and_secret(self):
        rows, _ = inv.join_discovery(self.inventory, self.references)
        self.assertEqual(len(inv.filter_overview(rows, namespace="energy")), 1)
        self.assertEqual(len(inv.filter_overview(rows, status="EXPIRING")), 1)
        self.assertEqual(len(inv.filter_overview(rows, query="api.example.test")), 1)
        self.assertEqual(len(inv.filter_overview(rows, query="preprovisioned")), 1)
        self.assertEqual(len(inv.filter_overview(rows, query="UNKNOWN")), 0)
        with self.assertRaisesRegex(ValueError, "Unknown TLS status"):
            inv.filter_overview(rows, status="PASSED")

    def test_bad_inventory_or_inconsistent_mapping_fails_closed(self):
        self.inventory.write_text(self.inventory.read_text().replace(
            f"{A},2,EXPIRING", f"{A},1,EXPIRING"))
        with self.assertRaisesRegex(ValueError, "count changed"):
            inv.join_discovery(self.inventory, self.references)
        self.inventory.write_text(
            "namespace,secret_name,status\nenergy-dev,web-tls,VALID\n")
        with self.assertRaisesRegex(ValueError, "missing columns"):
            inv.join_discovery(self.inventory, self.references)

    def test_report_exports_are_metadata_only_private_and_not_overwritten(self):
        rows, unresolved = inv.join_discovery(self.inventory, self.references)
        generated = inv.write_overview_reports(self.root, rows, unresolved,
                                               context="development")
        for path in generated.values():
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        as_json = json.loads(generated["json"].read_text())
        self.assertEqual(as_json["summary"]["UNRESOLVED_INGRESS_REFERENCE"], 2)
        self.assertIn("NO_INGRESS_REFERENCE", generated["markdown"].read_text())
        self.assertNotIn("PRIVATE KEY", generated["markdown"].read_text())
        with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
            inv.write_overview_reports(self.root, rows, unresolved,
                                       context="development")

    def test_report_file_remains_private_with_permissive_umask(self):
        import os
        previous_umask = os.umask(0)
        try:
            path = inv._write_exclusive(self.root / "permission-test.txt", "synthetic metadata")
        finally:
            os.umask(previous_umask)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_advisory_candidates_do_not_allow_invalid_or_future(self):
        rows, _ = inv.join_discovery(self.inventory, self.references)
        selected = inv.candidates(rows, [1, 1, 2])
        self.assertEqual(len(selected), 2)
        self.assertTrue(all(x["mode"] == "renew" for x in selected))
        self.assertEqual(list(selected[0]), list(inv.CANDIDATE_COLUMNS))
        artifact = inv.write_candidates(self.root / "renewal-candidates.csv", selected)
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
        with self.assertRaisesRegex(ValueError, "outside"):
            inv.candidates(rows, [999])
        unsafe = [{**rows[0], "status": "INVALID"}]
        with self.assertRaisesRegex(ValueError, "Unsafe candidate"):
            inv.candidates(unsafe, [1])
        self.assertFalse((self.root / "renewal-plan.json").exists())

    def test_terminal_preview_and_candidate_export_without_cluster_mutation(self):
        rows, unresolved = inv.join_discovery(self.inventory, self.references)
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            wizard.display_tls_overview(rows, unresolved, context="dev", max_rows=2)
        self.assertIn("READ ONLY", output.getvalue())
        self.assertIn("EXPIRED", output.getvalue())
        self.assertIn("first 2/3", output.getvalue())
        with patch.object(wizard, "ask", side_effect=["1,2", "CANDIDATES"]), \
             redirect_stdout(StringIO()):
            path = wizard.export_renewal_candidates(rows, self.root)
        self.assertTrue(path.exists())
        self.assertFalse((self.root / "execution-journal.json").exists())

    def test_main_dashboard_only_calls_discover_helper(self):
        calls = []
        def fake_exec(argv):
            calls.append(tuple(argv))
            if argv[1:4] == ["config", "get-contexts", "-o"]:
                return "dev\n"
            return json.dumps({"items": [{"metadata": {"name": "energy-dev"}}]})
        def fake_helper(context, action, *args):
            self.assertEqual(context, "dev")
            self.assertEqual(action, "discover")
            calls.append(("helper", action))
            root = Path(args[args.index("--runs-dir") + 1])
            destination = root / "discovery-1"
            destination.mkdir(parents=True)
            (destination / "inventory.csv").write_bytes(self.inventory.read_bytes())
            (destination / "ingress-references.csv").write_bytes(self.references.read_bytes())
            return f"DISCOVERY: 3 TLS Secrets; reports: {destination}\n"
        args = types.SimpleNamespace(context=None, workspace=str(self.root / "workspace"))
        with patch.object(wizard.sys.stdin, "isatty", return_value=True), \
             patch.object(wizard, "choose", return_value="dev"), \
             patch.object(wizard, "choose_namespaces", return_value=["energy-dev"]), \
             patch.object(wizard, "exec_read", side_effect=fake_exec), \
             patch.object(helper, "inventory_json", return_value={"items": [{"metadata": {"name": "energy-dev"}}]}), \
             patch.object(wizard, "helper", side_effect=fake_helper), \
             patch.object(wizard, "ask", side_effect=["30", "?", "0"]):
            location = wizard.tls_discovery_dashboard(args)
        self.assertEqual([x for x in calls if x[0] == "helper"],
                         [("helper", "discover")])
        self.assertTrue((location / "tls-overview.csv").is_file())
        self.assertTrue((location / "tls-overview.json").is_file())
        self.assertTrue((location / "tls-overview.md").is_file())
        self.assertFalse((location / "renewal-plan.json").exists())


if __name__ == "__main__":
    unittest.main()
