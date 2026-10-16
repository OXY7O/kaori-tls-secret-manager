"""Offline interactive wizard tests: no real kubectl writes or TLS keys."""
import csv
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

TOOLDIR = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager"
sys.path.insert(0, str(TOOLDIR))
spec = importlib.util.spec_from_file_location("tlswizard_test", TOOLDIR / "tls_secret_wizard.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
m = importlib.import_module("tls_secret_manager")

OLD = "a" * 64
NEW = "b" * 64


class WizardTests(unittest.TestCase):
    def test_noninteractive_input_is_rejected_before_cluster_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp, context=None)
            with patch.object(w.sys.stdin, "isatty", return_value=False), \
                 patch.object(w.subprocess, "run", side_effect=AssertionError("No external calls allowed")):
                with self.assertRaisesRegex(m.Stop, "Interactive TTY"):
                    w.wizard(args)

    def test_unique_baseline_requires_explicit_operator_confirmation(self):
        rows = [{"san": "*.example.test", "fingerprint_sha256": OLD}]
        with patch.object(w, "ask", return_value="HOLD"):
            with self.assertRaisesRegex(m.Stop, "Baseline not confirmed"):
                w.choose_baseline(rows, {"sans": ["*.example.test"], "fingerprint": NEW})
        with patch.object(w, "ask", return_value="BASELINE"):
            self.assertEqual(w.choose_baseline(rows, {"sans": ["*.example.test"],
                                                     "fingerprint": NEW}), OLD)

    def test_mixed_old_certificate_group_not_auto_selected(self):
        rows = [{"san": "*.example.test", "fingerprint_sha256": OLD},
                {"san": "*.example.test", "fingerprint_sha256": "c" * 64}]
        with patch.object(w, "choose", return_value="HOLD: do not select a baseline; defer ambiguous certificate families"):
            self.assertIsNone(w.choose_baseline(rows, {"sans": ["*.example.test"],
                                                       "fingerprint": NEW}))

    def test_mapping_only_ready_secrets_and_staged_requires_review(self):
        plan = {"entries": [
            {"namespace": "dev", "secret_name": "active", "status": "READY",
             "ingress_refs": [{"host": "web.example.test"}]},
            {"namespace": "dev", "secret_name": "staged", "status": "READY",
             "ingress_refs": []},
            {"namespace": "dev", "secret_name": "held", "status": "HOLD",
             "ingress_refs": [{"host": "held.example.test"}]},
        ], "new_sans": ["*.example.test"]}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(w, "ask", side_effect=[
                 "web.example.test", "443", "", "", "STAGED",
                 "Pre-provisioned and approved by the application owner"
             ]):
            endpoints, staged = w.build_endpoint_maps(plan, Path(tmp))
            with endpoints.open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["secret_name"], "active")
            with staged.open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["secret_name"], "staged")

    def test_review_hold_interactive_never_executes_kubectl_and_pins_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = {
                "schema_version": 1, "context": "uat", "cluster_uid": "uid",
                "new_fingerprint": NEW,
                "entries": [{
                    "namespace": "dev", "secret_name": "web-tls", "status": "HOLD",
                    "base_status": "READY",
                    "old_fingerprint": OLD, "old_sans": ["*.example.test"],
                    "message": "Identity review required: ISSUER_CHANGED",
                }, {
                    "namespace": "dev", "secret_name": "managed-tls", "status": "HOLD",
                    "base_status": "BLOCKED", "old_fingerprint": OLD,
                    "old_sans": ["*.example.test"], "message": "Controller ownership"
                }]
            }
            plan["plan_id"] = m.plan_id(plan)
            plan_path = root / "renewal-plan.json"
            plan_path.write_text(json.dumps(plan))
            args = types.SimpleNamespace(review_plan=str(plan_path), workspace=str(root))
            with patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "ask", side_effect=[
                     "REVIEW", OLD, "Owner approved this separate TLS issuance"
                 ]), patch.object(w.subprocess, "run",
                                  side_effect=AssertionError("No external call allowed")):
                w.review_hold_plan(args)
            review_files = list(root.glob("held-review-*/reviewed-holds.csv"))
            self.assertEqual(len(review_files), 1)
            with review_files[0].open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["secret_name"], "web-tls")
            self.assertEqual(rows[0]["old_fingerprint"], OLD)

    def test_secret_selection_requires_explicit_confirmation(self):
        rows = [{"namespace": "dev", "secret_name": "tls-a", "fingerprint_sha256": OLD,
                 "ingress_count": "1", "san": "*.example.test", "status": "VALID"},
                {"namespace": "uat", "secret_name": "tls-b", "fingerprint_sha256": OLD,
                 "ingress_count": "0", "san": "*.example.test", "status": "VALID"}]
        with patch.object(w, "ask", side_effect=["1", "YES"]):
            picked = w.choose_indices(rows)
            self.assertEqual(len(picked), 1)
            self.assertEqual(picked[0]["secret_name"], "tls-a")

    def test_secret_selection_all_requires_confirmation(self):
        rows = [{"namespace": "dev", "secret_name": "tls-a", "fingerprint_sha256": OLD,
                 "ingress_count": "1", "san": "*.example.test", "status": "VALID"}]
        with patch.object(w, "ask", side_effect=["ALL", "NO"]):
            with self.assertRaisesRegex(m.Stop, "ALL selection cancelled"):
                w.choose_indices(rows)

    def test_endpoint_mapping_english_guidance_and_no_false_https_pass(self):
        from contextlib import redirect_stdout
        from io import StringIO
        plan = {"entries": [{
            "namespace": "energy-development", "secret_name": "tls-secret",
            "status": "READY",
            "ingress_refs": [{"host": "demo.example.test"}],
        }], "new_sans": ["demo.example.test"]}
        with tempfile.TemporaryDirectory() as tmp:
            out = StringIO()
            with patch.object(w, "ask", side_effect=[
                "demo.example.test", "443", "", ""
            ]) as ask_mock, redirect_stdout(out):
                endpoint_file, staged = w.build_endpoint_maps(plan, Path(tmp))
            text = out.getvalue()
            self.assertIsNone(staged)
            self.assertIn(
                "Optional connection address (IP/hostname; Enter to use SNI hostname)",
                [call.args[0] for call in ask_mock.call_args_list]
            )
            self.assertIn("ENDPOINT MAPPING VALIDATED", text)
            self.assertIn("HTTPS NOT YET TESTED", text)
            self.assertIn("Step 9", text)
            self.assertNotIn("hostname koneksi", text)
            self.assertNotIn("endpoint aktif", text)
            with endpoint_file.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["hostname"], "demo.example.test")
            self.assertEqual(rows[0]["port"], "443")
            self.assertEqual(rows[0]["connect_host"], "")

    def test_staged_requires_explicit_staged_or_active_choice(self):
        plan = {"entries": [{
            "namespace": "dev", "secret_name": "tls", "status": "READY",
            "ingress_refs": [],
        }], "new_sans": ["*.example.test"]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(w, "ask", return_value=""):
            with self.assertRaisesRegex(m.Stop, "Select STAGED or ACTIVE"):
                w.build_endpoint_maps(plan, Path(tmp))

    def test_friendly_main_menu_exit_never_calls_cluster(self):
        args = types.SimpleNamespace(workspace=None, context=None,
                                     cert=None, key=None, ca_bundle=None,
                                     reviewed_holds=None, review_plan=None)
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "ask", return_value="0"), \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No cluster action")):
            w.main_menu(args)

    def test_main_menu_status_guide_without_any_secret_access(self):
        args = types.SimpleNamespace(workspace=None, context=None,
                                     cert=None, key=None, ca_bundle=None,
                                     reviewed_holds=None, review_plan=None)
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "ask", side_effect=["8", "0"]), \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No cluster action")):
            w.main_menu(args)

    def test_main_menu_compact_default_and_help_are_local_only(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(workspace=None, context=None,
                                     cert=None, key=None, ca_bundle=None,
                                     reviewed_holds=None, review_plan=None)
        w.setup_display(plain=True)
        output = StringIO()
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "recent_plans", return_value=[]), \
             patch.object(w, "ask", side_effect=["?", "", "0"]) as prompts, \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No external calls")), \
             redirect_stdout(output):
            w.main_menu(args)
        screen = output.getvalue()
        self.assertIn("TLS MANAGEMENT", screen)
        self.assertIn("  1. Inventory", screen)
        self.assertNotIn("DISCOVERY & DIAGNOSTICS", screen)
        self.assertNotIn("[DEFAULT]", screen)
        self.assertIn("Renew TLS", screen)
        self.assertIn("  9. Help", screen)
        self.assertIn("PURPOSE", screen)
        self.assertIn("LAUNCH / OPTIONS", screen)
        self.assertIn("signed authorization", screen)
        self.assertIn("--workspace", screen)
        self.assertNotIn("guided from discovery through reporting", screen)
        self.assertEqual(prompts.call_args_list[0].args[1], "1")
        self.assertTrue(screen.isascii(), "Plain mode must not emit Unicode art/text")


    def test_new_create_delete_items_use_original_wizard_menu(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(workspace=None, context=None)
        w.setup_display(plain=True)
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "recent_plans", return_value=[]), \
             patch.object(w, "ask", side_effect=["10", "11", "0"]), \
             patch.object(w, "crud_wizard") as lifecycle, \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No kubectl")), \
             redirect_stdout(StringIO()) as captured:
            w.main_menu(args)
        self.assertEqual([c.args[1] for c in lifecycle.call_args_list],
                         ["create", "delete"])
        self.assertIn("10. Create TLS Secret", captured.getvalue())
        self.assertIn("11. Delete TLS Secret", captured.getvalue())

    def test_guided_recovery_refuses_unknown_journal_before_write(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(context=None)
        data = {"target": "sandbox/demo", "observation": "OBSERVED_ABSENT",
                "journal_status": "MUTATION_UNCERTAIN", "backup_present": True,
                "restore_eligible": False, "plan_id": "testplan"}
        with patch.object(w, "exec_read", return_value="dev-context\n"), \
             patch.object(w, "choose", return_value="dev-context"), \
             patch.object(w, "ask", side_effect=["sandbox", "demo", "/tmp/demo-plan.json"]), \
             patch.object(w.Path, "is_file", return_value=True), \
             patch.object(w, "local_recovery_identity",
                          side_effect=AssertionError("No recovery key for HOLD")), \
             patch.object(w, "crud_command", return_value=data) as call, \
             redirect_stdout(StringIO()):
            result = w.delete_recovery_wizard(args)
        self.assertFalse(result["restore_eligible"])
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[1], "reconcile-delete")

    def test_crud_engine_uses_no_arbitrary_mutation_timeout(self):
        with patch.object(w.subprocess, "run") as runner, \
             patch.object(w.Path, "is_file", return_value=True):
            runner.return_value.returncode = 0
            runner.return_value.stdout = '{"status":"COMPLETE"}'
            runner.return_value.stderr = ""
            self.assertEqual(w.crud_command("ctx", "delete", "--namespace", "dev"),
                             {"status": "COMPLETE"})
            self.assertIsNone(runner.call_args.kwargs.get("timeout"))
            self.assertIn("tls_crud.py", " ".join(str(x) for x in runner.call_args.args[0]))

    def test_crud_bad_command_fails_closed_without_kubernetes(self):
        with patch.object(w.Path, "is_file", return_value=False), \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No subprocess")):
            with self.assertRaisesRegex(m.Stop, "CRUD engine is unavailable"):
                w.crud_command("ctx", "plan-create", "--namespace", "dev")

    def test_main_menu_numbers_are_sequential_and_default_is_safe_inventory(self):
        from contextlib import redirect_stdout
        from io import StringIO
        import re
        args = types.SimpleNamespace(workspace=None, context=None)
        w.setup_display(plain=True)
        output = StringIO()
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "recent_plans", return_value=[]), \
             patch.object(w, "ask", return_value="0"), \
             patch.object(w, "helper", side_effect=AssertionError("No Kubernetes writes")), \
             redirect_stdout(output):
            w.main_menu(args)
        home = output.getvalue()
        entries = re.findall(r"^\s+(\d+)\.\s+(.+)$", home, flags=re.MULTILINE)
        self.assertEqual([int(n) for n, _ in entries], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0])
        self.assertTrue(entries[0][1].startswith("Inventory"))
        self.assertNotIn("[DEFAULT]", home)
        self.assertNotRegex(home, r"(?m)^\s+[1-9]\s+[-◉◷⚙↻✓]")
        self.assertTrue(home.isascii())

    def test_home_menu_grammar_and_operation_spacing(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(workspace=None, context=None)
        w.setup_display(plain=True)
        for count, phrase in ((0, "0 saved runs"), (1, "1 saved run"),
                              (7, "7 saved runs")):
            with self.subTest(count=count), \
                 patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "recent_plans", return_value=[None] * count), \
                 patch.object(w, "ask", return_value="0"), \
                 patch.object(w, "helper", side_effect=AssertionError("No kubectl")), \
                 redirect_stdout(StringIO()) as captured:
                w.main_menu(args)
            home = captured.getvalue()
            self.assertIn(phrase + "  |  Default: Inventory (read-only)", home)
            self.assertRegex(
                home,
                r"(?m)^ *4\. Reverify HTTPS\n\n *5\. Renew TLS\n"
                r" *6\. Review HOLD\n\n *7\. Run history$",
            )

    def test_home_menu_ansi_semantics_and_plain_fallback(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with patch.object(w, "USE_COLOR", True), redirect_stdout(StringIO()) as out:
            w.menu_entry("1", "Inventory", default=True)
            w.menu_entry("2", "Expiry audit")
            w.menu_entry("5", "Renew TLS", caution=True)
        text = out.getvalue()
        self.assertIn("\x1b[36m   1. Inventory\x1b[0m", text)
        self.assertIn("   2. Expiry audit\n", text)
        self.assertIn("\x1b[33m   5. Renew TLS\x1b[0m", text)
        self.assertNotIn("\x1b[0m   2.", text)
        with patch.object(w, "USE_COLOR", False), redirect_stdout(StringIO()) as plain:
            w.menu_entry("1", "Inventory", default=True)
            w.menu_entry("5", "Renew TLS", caution=True)
        self.assertNotIn("\x1b[", plain.getvalue())
        self.assertIn("   5. Renew TLS", plain.getvalue())

    def test_terminal_color_respects_environment_and_tty(self):
        with patch.object(w.sys.stdout, "isatty", return_value=True), \
             patch.dict(w.os.environ, {"TERM": "xterm-256color"}, clear=True):
            w.setup_display(plain=False)
            self.assertTrue(w.USE_COLOR)
            w.setup_display(plain=True)
            self.assertFalse(w.USE_COLOR)
            with patch.dict(w.os.environ, {"NO_COLOR": ""}):
                w.setup_display(plain=False)
                self.assertFalse(w.USE_COLOR)
            with patch.dict(w.os.environ, {"CLICOLOR": "0"}):
                w.setup_display(plain=False)
                self.assertFalse(w.USE_COLOR)
            with patch.dict(w.os.environ, {"TERM": "dumb"}):
                w.setup_display(plain=False)
                self.assertFalse(w.USE_COLOR)
        with patch.object(w.sys.stdout, "isatty", return_value=False), \
             patch.dict(w.os.environ, {"TERM": "xterm"}, clear=True):
            w.setup_display(plain=False)
            self.assertFalse(w.USE_COLOR)

    def test_sequential_shortcuts_dispatch_correctly_without_real_cluster(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(workspace=None, context=None,
                                     cert=None, key=None, ca_bundle=None,
                                     reviewed_holds=None, review_plan=None)
        commands = {
            1: "tls_discovery_dashboard",
            2: "audit_secret_validity",
            3: "toolkit_menu",
            4: "reverify_existing_run",
            5: "wizard",
        }
        for number, func in commands.items():
            with self.subTest(number=number), \
                 patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "recent_plans", return_value=[]), \
                 patch.object(w, "ask", side_effect=[str(number), "0"]), \
                 patch.object(w, func) as called, \
                 patch.object(w, "exec_read", side_effect=AssertionError("No real kubectl")), \
                 redirect_stdout(StringIO()):
                w.main_menu(args)
                called.assert_called_once_with(args)
        for number in (6, 7):
            with self.subTest(number=number), \
                 patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "recent_plans", return_value=[]), \
                 patch.object(w, "ask", side_effect=[str(number), "0"]), \
                 patch.object(w, "choose_previous_plan", return_value=None) as select, \
                 patch.object(w, "exec_read", side_effect=AssertionError("No real kubectl")), \
                 redirect_stdout(StringIO()):
                w.main_menu(args)
                self.assertEqual(select.call_args.kwargs.get("held_only", False), number == 6)
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "recent_plans", return_value=[]), \
             patch.object(w, "ask", side_effect=["8", "0"]), \
             patch.object(w, "status_help") as guidance, \
             redirect_stdout(StringIO()):
            w.main_menu(args)
            self.assertEqual(guidance.call_count, len(w.STATUS_GUIDE))

    def test_operator_help_number_and_shortcut_do_not_discover(self):
        from contextlib import redirect_stdout
        from io import StringIO
        args = types.SimpleNamespace(workspace=None, context=None)
        for choice in ("9", "H", "HELP"):
            with self.subTest(choice=choice), \
                 patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "recent_plans", return_value=[]), \
                 patch.object(w, "ask", side_effect=[choice, "", "0"]), \
                 patch.object(w, "helper", side_effect=AssertionError("No helper call")), \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl call")), \
                 redirect_stdout(StringIO()) as captured:
                w.main_menu(args)
                self.assertIn("HELP  /  TLS SECRET MANAGER", captured.getvalue())

    def test_banner_ascii_narrow_terminal_and_menu_ctrl_c(self):
        from contextlib import redirect_stdout
        from io import StringIO
        w.setup_display(plain=True)
        output = StringIO()
        with patch.object(w.render_header.__globals__["shutil"], "get_terminal_size",
                          return_value=types.SimpleNamespace(columns=54)), \
             redirect_stdout(output):
            w.brand_banner()
        self.assertIn("  TLS MANAGEMENT", output.getvalue())
        self.assertNotIn("OPS  /  TLS", output.getvalue())
        self.assertIn("[KAORI]", output.getvalue())
        self.assertIn("  KAORI", output.getvalue())
        self.assertTrue(output.getvalue().isascii())
        args = types.SimpleNamespace(workspace=None)
        with patch.object(w.sys.stdin, "isatty", return_value=True), \
             patch.object(w, "recent_plans", return_value=[]), \
             patch.object(w, "ask", side_effect=KeyboardInterrupt), \
             patch.object(w.subprocess, "run", side_effect=AssertionError("No external calls")), \
             redirect_stdout(StringIO()) as captured:
            w.main_menu(args)
        self.assertIn("Menu closed", captured.getvalue())

    def test_brand_logo_uses_approved_cli_png_on_iterm(self):
        from io import StringIO
        class TtyBuffer(StringIO):
            def isatty(self):
                return True
        output = TtyBuffer()
        with patch.object(w.sys, "stdout", output), \
             patch.object(w, "USE_COLOR", True), \
             patch.object(w, "USE_ICONS", True), \
             patch.dict(w.os.environ, {"TERM_PROGRAM": "iTerm.app", "TERM": "xterm-256color"},
                        clear=False):
            w.brand_banner()
        self.assertIn("\x1b]1337;File=inline=1;", output.getvalue())
        self.assertIn("KAORI  |  TLS MANAGEMENT", output.getvalue())

    def test_brand_logo_never_emits_control_sequences_in_plain_mode(self):
        from contextlib import redirect_stdout
        from io import StringIO
        w.setup_display(plain=True)
        with patch.dict(w.os.environ, {"TERM_PROGRAM": "iTerm.app"}, clear=False), \
             redirect_stdout(StringIO()) as out:
            w.brand_banner()
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("TLS MANAGEMENT", out.getvalue())
        self.assertIn("[KAORI]", out.getvalue())

    def test_brand_falls_back_to_colored_pixel_mark_without_iterm(self):
        from io import StringIO
        class TtyBuffer(StringIO):
            def isatty(self):
                return True
        output = TtyBuffer()
        with patch.object(w.sys, "stdout", output), \
             patch.object(w, "USE_COLOR", True), \
             patch.object(w, "USE_ICONS", True), \
             patch.dict(w.os.environ, {"TERM_PROGRAM": "vscode", "TERM": "xterm-256color"},
                        clear=False):
            w.brand_banner()
        self.assertIn("\x1b[", output.getvalue())
        self.assertIn("▀", output.getvalue())
        self.assertIn("TLS MANAGEMENT", output.getvalue())
        self.assertNotIn("\x1b]1337", output.getvalue())
        self.assertNotIn(".------.", output.getvalue())

    def test_toolbox_menu_help_never_checks_cluster(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp)
            with patch.object(w, "ask", side_effect=["?", "", "0"]), \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl calls")), \
                 patch.object(w.subprocess, "run", side_effect=AssertionError("No subprocess calls")), \
                 redirect_stdout(StringIO()) as captured:
                w.toolkit_menu(args)
            text = captured.getvalue()
            self.assertIn("TLS TOOLBOX HELP", text)
            self.assertIn("Multi-IP drift", text)
            self.assertIn("no Kubernetes Secret mutation", text)

    def test_submenus_are_numeric_and_explain_read_only_side_effects(self):
        from contextlib import redirect_stdout
        from io import StringIO
        w.setup_display(plain=True)
        with patch.object(w, "helper", side_effect=AssertionError("No kubectl helper")), \
             patch.object(w, "exec_read", side_effect=AssertionError("No Kubernetes API")), \
             redirect_stdout(StringIO()) as output:
            w.submenu_entry("1", "Filter")
            w.submenu_entry("?", "Help")
            w.submenu_entry("0", "Back")
            w.inventory_help()
            w.toolbox_help()
        text = output.getvalue()
        self.assertIn("   1. Filter", text)
        self.assertIn("   ?. Help", text)
        self.assertIn("   0. Back", text)
        self.assertIn("INVENTORY HELP / READ ONLY", text)
        self.assertIn("advisory CSV; NOT a renewal plan", text)
        self.assertIn("no Kubernetes Secret mutation", text)
        self.assertIn("Multi-IP", text)
        self.assertTrue(text.isascii())

    def test_toolbox_default_returns_before_kubectl(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp, context=None)
            with patch.object(w, "ask", return_value="0") as prompts, \
                 patch.object(w, "exec_read",
                              side_effect=AssertionError("No kubectl")), \
                 patch.object(w, "helper",
                              side_effect=AssertionError("No helper")), \
                 redirect_stdout(StringIO()) as out:
                w.toolkit_menu(args)
            self.assertIn("   7. Multi-IP drift", out.getvalue())
            self.assertIn("   0. Back", out.getvalue())
            self.assertEqual(prompts.call_args.args[1], "0")

    def test_actual_input_returns_explicit_submenu_default(self):
        with patch("builtins.input", return_value="") as prompt:
            self.assertEqual(w.ask("Tool (? for Help)", "0"), "0")
            prompt.assert_called_once_with("Tool (? for Help) [0]: ")

    def test_renewal_step_progress_is_plain_accessible_and_keeps_safety(self):
        from contextlib import redirect_stdout
        from io import StringIO
        w.setup_display(plain=True)
        with redirect_stdout(StringIO()) as progress:
            w.step(7, 9, "Review and authorize changes",
                   "No Kubernetes Secrets written yet.")
            w.renewal_help()
        text = progress.getvalue()
        self.assertIn("STEP 7/9  Review and authorize changes", text)
        self.assertIn("Note: No Kubernetes Secrets written yet.", text)
        self.assertIn("AUTHORI" + "ZED", text)
        self.assertIn("independent signature", text)
        self.assertTrue(text.isascii())

    def test_choose_namespaces_numeric_requires_confirmation(self):
        with patch.object(w, "ask", side_effect=["1,3", "YES"]):
            self.assertEqual(w.choose_namespaces(["alpha", "beta", "gamma"]),
                             ["alpha", "gamma"])

    def test_choose_namespaces_all_needs_explicit_approval(self):
        with patch.object(w, "ask", side_effect=["ALL", "NO"]):
            with self.assertRaisesRegex(m.Stop, "cancelled"):
                w.choose_namespaces(["alpha", "beta"])

    def test_read_previous_run_hints_when_journal_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "renewal-plan.json"
            plan = {
                "schema_version": 1, "context": "dev",
                "entries": [
                    {"namespace": "dev", "secret_name": "tls", "status": "HOLD"}
                ]
            }
            plan["plan_id"] = m.plan_id(plan)
            path.write_text(json.dumps(plan))
            with patch.object(w.subprocess, "run",
                              side_effect=AssertionError("No cluster action")):
                w.show_run_status(str(path))

    def test_plain_status_guidance_contains_real_file_names(self):
        w.setup_display(plain=True)
        self.assertIn("held-targets.csv", w.STATUS_GUIDE["HOLD"][1])
        self.assertIn("execution-journal.json",
                      w.STATUS_GUIDE["COMPLETE_ENDPOINT_UNVERIFIED"][1])
        self.assertEqual(w.icon("warn"), "[WARN]")

    def test_recent_runs_are_numbered_and_hold_filter_reads_only_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for folder, state in (("run-1", "HOLD"), ("run-2", "SKIPPED")):
                directory = root / folder / "runs" / "plan-1"
                directory.mkdir(parents=True)
                plan = {"schema_version": 1, "context": "dev",
                        "entries": [{"namespace": "dev", "secret_name": "tls",
                                     "status": state}]}
                plan["plan_id"] = m.plan_id(plan)
                (directory / "renewal-plan.json").write_text(json.dumps(plan))
            args = types.SimpleNamespace(workspace=str(root))
            with patch.object(w.subprocess, "run", side_effect=AssertionError("No cluster calls")):
                self.assertEqual(len(w.recent_plans(args)), 2)
                self.assertEqual(len(w.recent_plans(args, held_only=True)), 1)
                with patch.object(w, "ask", return_value="1"):
                    chosen = w.choose_previous_plan(args, held_only=True)
            self.assertIn("run-1", chosen)

    def test_previous_run_selection_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp)
            with patch.object(w, "ask", return_value="QUIT"):
                self.assertIsNone(w.choose_previous_plan(args))

    def test_no_saved_run_enter_returns_without_cluster_requests(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp)
            screen = StringIO()
            with patch.object(w, "ask", return_value="") as ask, \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl")), \
                 patch.object(w, "helper", side_effect=AssertionError("No renewal")), \
                 redirect_stdout(screen):
                self.assertIsNone(w.reverify_existing_run(args))
            self.assertEqual(ask.call_count, 1)
            self.assertIn("No matching saved renewal runs", screen.getvalue())
            self.assertIn("Main menu 5 > Renew TLS creates renewal-plan.json", screen.getvalue())
            self.assertIn("journal from an executed renewal", screen.getvalue())
            self.assertIn("Do not renew just to test HTTPS", screen.getvalue())
            self.assertIn("TLS Doctor", screen.getvalue())
            self.assertIn("Enter or type 0/QUIT", screen.getvalue())

    def test_saved_run_selector_accepts_zero_to_cancel(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp)
            with patch.object(w, "ask", return_value="0") as ask, \
                 redirect_stdout(StringIO()):
                self.assertIsNone(w.choose_previous_plan(args))
            self.assertEqual(ask.call_count, 1)

    def test_manual_plan_path_still_works_without_indexed_history(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "renewal-plan.json"
            path.write_text("{}", encoding="utf-8")
            args = types.SimpleNamespace(workspace=str(Path(tmp) / "empty-workspace"))
            with patch.object(w, "ask", return_value=str(path)), \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl")), \
                 redirect_stdout(StringIO()):
                self.assertEqual(w.choose_previous_plan(args), str(path.resolve()))

    def test_tls_doctor_results_are_not_accepted_as_renewal_plan(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "toolkit-reports" / "doctor-example" / "results.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text('{"stored":{"status":"VALID"}}', encoding="utf-8")
            args = types.SimpleNamespace(workspace=str(root / "empty-renewal-runs"))
            screen = StringIO()
            with patch.object(w, "ask", return_value=str(evidence)) as ask, \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl")), \
                 patch.object(w, "helper", side_effect=AssertionError("No helper")), \
                 redirect_stdout(screen):
                self.assertIsNone(w.reverify_existing_run(args))
            self.assertEqual(ask.call_count, 1, "Empty history must not trap operator")
            self.assertIn("diagnostic report, not a renewal-plan.json", screen.getvalue())
            self.assertIn("Returning to the main menu", screen.getvalue())

    def test_missing_manual_plan_returns_after_one_attempt_when_no_saved_runs(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(workspace=tmp)
            screen = StringIO()
            with patch.object(w, "ask", return_value="/tmp/not-existing-report.json") as ask, \
                 patch.object(w, "exec_read", side_effect=AssertionError("No kubectl")), \
                 redirect_stdout(screen):
                self.assertIsNone(w.choose_previous_plan(args, purpose="reverify"))
            self.assertEqual(ask.call_count, 1)
            self.assertIn("No valid renewal-plan.json", screen.getvalue())

    def test_validity_report_shows_date_and_days_without_renewal(self):
        rows = [{
            "namespace": "dev", "secret_name": "tls", "status": "EXPIRING",
            "not_after": "2026-11-01T00:00:00+00:00", "days_remaining": "18",
            "san": "*.example.test", "ingress_count": "1"
        }]
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            from io import StringIO
            from contextlib import redirect_stdout
            output = StringIO()
            with redirect_stdout(output):
                w.print_validity_inventory(rows, report_dir, 30)
            data = output.getvalue()
            self.assertIn("2026-11-01", data)
            self.assertIn("18", data)
            self.assertIn("EXPIRING", data)
            self.assertIn("inventory.csv", data)
            self.assertIn("no secrets", data.lower())

    def test_validity_audit_discovers_only_and_never_mutates_cluster(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = types.SimpleNamespace(context=None, workspace=tmp)
            commands = []
            outputs = [
                "k8s-development\n",
                json.dumps({"items": [{"metadata": {"name": "dev"}}]})
            ]
            def fake_exec(argv):
                self.assertEqual(argv[0], "kubectl")
                return outputs.pop(0)
            def fake_helper(ctx, *argv):
                self.assertEqual(ctx, "k8s-development")
                self.assertEqual(argv[0], "discover")
                self.assertEqual(argv[-2], "--warn-days")
                self.assertEqual(argv[-1], "30")
                commands.append(argv[0])
                root = Path(argv[argv.index("--runs-dir")+1])
                folder = root / "audit-example"
                folder.mkdir(parents=True)
                (folder / "inventory.csv").write_text(
                    "namespace,secret_name,status,not_after,days_remaining,san,ingress_count\n"
                    "dev,tls,VALID,2027-04-01T00:00:00+00:00,169,*.example.test,1\n"
                )
                (folder / "ingress-references.csv").write_text(
                    "namespace,secret_name,ingress,host\n"
                )
                return f"DISCOVERY: 1 TLS Secrets; reports: {folder}\n"
            with patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "choose", return_value="k8s-development"), \
                 patch.object(w, "choose_namespaces", return_value=["dev"]), \
                 patch.object(w, "ask", return_value="30"), \
                 patch.object(w, "exec_read", side_effect=fake_exec), \
                 patch.object(w, "helper", side_effect=fake_helper):
                w.audit_secret_validity(args)
            self.assertEqual(commands, ["discover"])
            self.assertFalse(outputs)

    def test_existing_subject_only_held_plan_gets_minimal_review_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_subject = "CN=old.example.test"
            new_subject = "CN=*.example.test"
            entry = {
                "namespace": "dev", "secret_name": "app-tls",
                "status": "HOLD", "base_status": "READY",
                "message": "Identity review required: SUBJECT_CHANGED",
                "old_fingerprint": OLD, "old_sans": ["*.example.test"],
                "ingress_refs": [{"host": "app.example.test"}],
                "certificate_comparison": {
                    "old_subject": old_subject, "new_subject": new_subject,
                    "subject_match": False, "san_match": True, "issuer_match": True,
                    "public_key_match": False,
                }
            }
            plan = {"schema_version": 1, "context": "dev",
                    "cluster_uid": "cluster-uid", "new_fingerprint": NEW,
                    "selection_policy": {"expected_old_fingerprint": OLD},
                    "entries": [entry]}
            plan["plan_id"] = m.plan_id(plan)
            plan_path = root / "renewal-plan.json"
            plan_path.write_text(json.dumps(plan))
            args = types.SimpleNamespace(review_plan=str(plan_path), workspace=str(root))
            with patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "ask", side_effect=[
                     "REVIEW", OLD,
                     "Owner approved a legitimate Subject change for the service"
                 ]):
                result = w.review_hold_plan(args)
            with Path(result).open(newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["approval_scope"], "SUBJECT_ONLY")
            self.assertEqual(row["old_subject"], old_subject)
            self.assertEqual(row["new_subject"], new_subject)

    def test_existing_held_plan_without_baseline_cannot_claim_subject_only_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = {
                "namespace": "dev", "secret_name": "app-tls",
                "status": "HOLD", "base_status": "READY",
                "message": "Identity review required: SUBJECT_CHANGED",
                "old_fingerprint": OLD, "old_sans": ["*.example.test"],
                "ingress_refs": [{"host": "app.example.test"}],
                "certificate_comparison": {
                    "old_subject": "CN=old.example.test",
                    "new_subject": "CN=*.example.test",
                    "subject_match": False, "san_match": True, "issuer_match": True
                }
            }
            plan = {"schema_version": 1, "context": "dev",
                    "cluster_uid": "cluster-uid", "new_fingerprint": NEW,
                    "selection_policy": {"expected_old_fingerprint": None},
                    "entries": [entry]}
            plan["plan_id"] = m.plan_id(plan)
            path = root / "renewal-plan.json"
            path.write_text(json.dumps(plan))
            args = types.SimpleNamespace(review_plan=str(path), workspace=str(root))
            with patch.object(w.sys.stdin, "isatty", return_value=True), \
                 patch.object(w, "ask", side_effect=[
                     "REVIEW", OLD,
                     "Owner approved the certificate identity after manual inspection"
                 ]):
                result = w.review_hold_plan(args)
            with Path(result).open(newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["approval_scope"], "IDENTITY")

    def test_subject_only_review_interactive_creates_bound_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = {"fingerprint": NEW, "subject": "CN=*.example.test",
                      "issuer": "CN=Issuer", "sans": ["*.example.test"]}
            selected = [{
                "namespace": "chatbot-development", "secret_name": "tls-secret",
                "status": "VALID", "fingerprint_sha256": OLD,
                "subject": "CN=chatbot.example.test",
                "issuer": "CN=Issuer", "san": "*.example.test", "ingress_count": "1"
            }]
            with patch.object(w, "ask", side_effect=[
                    "SUBJECT", OLD,
                    "Approved legitimate Subject-only renewal for chatbot service"]), \
                 patch("tls_secret_manager.cluster_id", return_value="cluster-uid"):
                approval = w.prepare_subject_review("ctx", selected, source,
                                                    Path(tmp), OLD)
            self.assertIsNotNone(approval)
            with Path(approval).open(newline="") as stream:
                record = next(csv.DictReader(stream))
            self.assertEqual(record["approval_scope"], "SUBJECT_ONLY")
            self.assertEqual(record["old_subject"], "CN=chatbot.example.test")
            self.assertEqual(record["new_subject"], "CN=*.example.test")
            self.assertEqual(record["cluster_uid"], "cluster-uid")
            self.assertEqual(record["old_fingerprint"], OLD)
            self.assertEqual(record["new_fingerprint"], NEW)

    def test_subject_only_review_declined_remains_hold_without_approval_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = [{
                "namespace": "dev", "secret_name": "tls", "status": "VALID",
                "fingerprint_sha256": OLD, "subject": "CN=old.example.test",
                "issuer": "CN=Issuer", "san": "*.example.test", "ingress_count": "1"
            }]
            source = {"fingerprint": NEW, "subject": "CN=*.example.test",
                      "issuer": "CN=Issuer", "sans": ["*.example.test"]}
            with patch.object(w, "ask", return_value=""):
                approval = w.prepare_subject_review("ctx", selected, source,
                                                    Path(tmp), OLD)
            self.assertIsNone(approval)
            self.assertFalse(list(Path(tmp).glob("*reviewed.csv")))

    def test_subject_only_review_refuses_unknown_issuer_or_unapproved_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = [{
                "namespace": "dev", "secret_name": "tls", "status": "VALID",
                "fingerprint_sha256": OLD, "subject": "CN=old.example.test",
                "issuer": "CN=DifferentIssuer", "san": "*.example.test",
                "ingress_count": "1"
            }]
            source = {"fingerprint": NEW, "subject": "CN=*.example.test",
                      "issuer": "CN=Issuer", "sans": ["*.example.test"]}
            with patch.object(w, "ask", side_effect=AssertionError("No approval prompt")):
                self.assertIsNone(w.prepare_subject_review(
                    "ctx", selected, source, Path(tmp), OLD))
                selected[0]["issuer"] = "CN=Issuer"
                self.assertIsNone(w.prepare_subject_review(
                    "ctx", selected, source, Path(tmp), None))
                self.assertIsNone(w.prepare_subject_review(
                    "ctx", selected, source, Path(tmp), "c" * 64))

    def test_subject_review_can_merge_existing_staged_review_without_dropping_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            staging = root / "staging.csv"
            with staging.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "context", "cluster_uid", "new_fingerprint", "namespace",
                    "secret_name", "old_fingerprint", "reason", "approval_scope",
                    "old_subject", "new_subject"])
                writer.writeheader()
                writer.writerow({
                    "context": "ctx", "cluster_uid": "cluster-uid",
                    "new_fingerprint": NEW, "namespace": "dev",
                    "secret_name": "staged-tls", "old_fingerprint": OLD,
                    "reason": "Staged approval from application owner",
                    "approval_scope": "STAGED_ONLY"})
            selected = [{
                "namespace": "dev", "secret_name": "active-tls", "status": "VALID",
                "fingerprint_sha256": OLD, "subject": "CN=old.example.test",
                "issuer": "CN=Issuer", "san": "*.example.test", "ingress_count": "1"}]
            source = {"fingerprint": NEW, "subject": "CN=*.example.test",
                      "issuer": "CN=Issuer", "sans": ["*.example.test"]}
            with patch.object(w, "ask", side_effect=[
                    "SUBJECT", OLD,
                    "Owner approved the subject-only renewal for active TLS"]), \
                 patch("tls_secret_manager.cluster_id", return_value="cluster-uid"):
                result = w.prepare_subject_review(
                    "ctx", selected, source, root, OLD, str(staging))
            with Path(result).open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 2)
            self.assertEqual({r["approval_scope"] for r in rows},
                             {"STAGED_ONLY", "SUBJECT_ONLY"})

    def test_staged_preplan_review_requires_exact_secret_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = [{"namespace": "dev", "secret_name": "pending-tls",
                "fingerprint_sha256": OLD, "ingress_count": "0", "san": "*.example.test"}]
            with patch.object(w, "ask", side_effect=[
                    "STAGED", "pending-tls",
                    "Future service Secret approved by application owner"]), \
                 patch("tls_secret_manager.cluster_id", return_value="cluster-uid"):
                file_path, intents = w.prepare_staged_review(
                    "ctx", selected, {"fingerprint": NEW}, Path(tmp))
            self.assertEqual(intents[("dev", "pending-tls")],
                             "Future service Secret approved by application owner")
            with Path(file_path).open(newline="") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["approval_scope"], "STAGED_ONLY")
            self.assertEqual(row["new_fingerprint"], NEW)
            self.assertEqual(row["cluster_uid"], "cluster-uid")

    def test_staged_preplan_mismatched_confirmation_fails_without_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = [{"namespace": "dev", "secret_name": "pending-tls",
                "fingerprint_sha256": OLD, "ingress_count": "0", "san": "*.example.test"}]
            with patch.object(w, "ask", side_effect=["STAGED", "wrong-name"]):
                with self.assertRaisesRegex(m.Stop, "does not match"):
                    w.prepare_staged_review("ctx", selected, {"fingerprint": NEW}, Path(tmp))
            self.assertFalse(list(Path(tmp).glob("*reviewed.csv")))

    def test_staged_preplan_skips_secrets_already_on_new_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = [{"namespace": "dev", "secret_name": "pending-tls",
                "fingerprint_sha256": NEW, "ingress_count": "0", "san": "*.example.test"}]
            with patch.object(w, "ask", side_effect=AssertionError("No prompts")):
                path, intents = w.prepare_staged_review(
                    "ctx", selected, {"fingerprint": NEW}, Path(tmp))
            self.assertIsNone(path)
            self.assertEqual(intents, {})

    def test_wizard_mutation_has_no_arbitrary_global_timeout(self):
        p = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(w.subprocess, "run", return_value=p) as sub:
            w.helper("ctx", "renew", "--plan", "/tmp/example")
            self.assertIsNone(sub.call_args.kwargs["timeout"])
        with patch.object(w.subprocess, "run", return_value=p) as sub:
            w.helper("ctx", "verify", "--plan", "/tmp/example")
            self.assertEqual(sub.call_args.kwargs["timeout"], 1200)

    def test_endpoint_reverify_never_invokes_renew(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            plan_dir = workspace / "runs" / "plan-id"
            plan_dir.mkdir(parents=True)
            plan = {"schema_version": 1, "context": "dev", "cluster_uid": "uid",
                    "entries": [{"status": "READY", "namespace": "dev",
                                 "secret_name": "web-tls"}]}
            plan["plan_id"] = m.plan_id(plan)
            path = plan_dir / "renewal-plan.json"
            path.write_text(json.dumps(plan))
            (plan_dir / "execution-journal.json").write_text(json.dumps({
                "plan_id": plan["plan_id"], "status": "COMPLETE_ENDPOINT_UNVERIFIED",
                "items": []
            }))
            (workspace / "endpoints.csv").write_text(
                "namespace,secret_name,hostname\ndev,web-tls,web.example.test\n")
            commands = []
            def fake_helper(ctx, *argv):
                commands.append(argv[0])
                return ""
            args = types.SimpleNamespace()
            with patch.object(w, "choose_previous_plan", return_value=str(path)), \
                 patch.object(w, "exec_read", return_value="dev\n"), \
                 patch.object(w, "ask", side_effect=["VERIFY", ""]), \
                 patch.object(w, "helper", side_effect=fake_helper):
                w.reverify_existing_run(args)
            self.assertEqual(commands, ["verify", "verify-endpoints", "report"])
            self.assertNotIn("renew", commands)

    def test_operator_back_action_does_not_start_cluster_operation(self):
        with patch("builtins.input", return_value="BACK"):
            with self.assertRaisesRegex(m.Stop, "return to the main menu"):
                w.ask("Enter TLS Secret name")

    def test_secret_search_preserves_original_selection_indices(self):
        rows = [{"namespace": "monitoring", "secret_name": "alertmanager-tls",
                 "fingerprint_sha256": OLD, "ingress_count": "1",
                 "san": "*.example.test", "status": "VALID"},
                {"namespace": "development", "secret_name": "api-tls",
                 "fingerprint_sha256": OLD, "ingress_count": "1",
                 "san": "*.example.test", "status": "VALID"}]
        with patch.object(w, "ask", side_effect=["FIND api", "2", "YES"]):
            found = w.choose_indices(rows)
        self.assertEqual(found[0]["secret_name"], "api-tls")

    def test_shell_launcher_wizard_help_and_existing_cli_help(self):
        wrapper = TOOLDIR / "tls-secret-manager.sh"
        guided = subprocess.run(["bash", str(wrapper), "wizard", "--help"],
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(guided.returncode, 0, guided.stderr)
        self.assertIn("--plain", guided.stdout)
        self.assertIn("--review-plan", guided.stdout)
        existing = subprocess.run(["bash", str(wrapper), "--help"],
                                  capture_output=True, text=True, timeout=12)
        self.assertEqual(existing.returncode, 0, existing.stderr)
        self.assertIn("verify-endpoints", existing.stdout)

    def test_shell_no_arguments_requires_real_terminal_and_never_writes(self):
        wrapper = TOOLDIR / "tls-secret-manager.sh"
        result = subprocess.run(["bash", str(wrapper)],
                                capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=12)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Interactive TTY required", result.stderr)

    def test_plan_path_parser_uses_final_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = "CERTIFICATE COMPARISON: 2 warnings\nPLAN ID: abc {'READY': 1} in " + tmp
            self.assertEqual(w.run_path(result, " in "), Path(tmp))


if __name__ == "__main__":
    unittest.main()
