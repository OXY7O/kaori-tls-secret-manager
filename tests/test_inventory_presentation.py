"""Presentation contracts for the read-only KAORI Inventory UI.

These tests do not use kubectl or mutate Kubernetes or local secret evidence.
"""
from contextlib import redirect_stdout
from io import StringIO
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

MODULES = Path(__file__).resolve().parents[1] / "scripts/kubernetes/tls-secret-manager"
sys.path.insert(0, str(MODULES))
import tls_secret_wizard as wizard


class InventoryPresentationTests(unittest.TestCase):
    def setUp(self):
        wizard.setup_display(plain=True)
        self.rows = [
            {"namespace": "development-with-long-namespace-name",
             "secret_name": "a-long-application-tls-secret-name",
             "ingress_hostnames": "very-long-ingress-subdomain.example.test",
             "ingress_usage": "HAS_INGRESS_REFERENCE",
             "expires_at_utc": "2027-04-09T00:00:00+00:00",
             "days_remaining": "0", "status": "VALID"},
            {"namespace": "monitoring", "secret_name": "old-tls",
             "ingress_hostnames": "-",
             "ingress_usage": "NO_INGRESS_REFERENCE",
             "expires_at_utc": "2026-01-01T00:00:00+00:00",
             "days_remaining": "-10", "status": "EXPIRED"},
        ]

    def screen(self, width, rows=None, **kw):
        buffer = StringIO()
        with patch.object(shutil, "get_terminal_size",
                          return_value=os.terminal_size((width, 24))), \
             redirect_stdout(buffer):
            wizard.display_tls_overview(self.rows if rows is None else rows,
                                        [], context="dev", **kw)
        return buffer.getvalue()

    def test_wide_table_has_section_spacing_and_respects_terminal_width(self):
        output = self.screen(110)
        for section in ("SCOPE", "SUMMARY", "DISCOVERY NOTES", "RESULTS"):
            self.assertIn("\n  " + section + "\n", output)
        self.assertIn("TLS Secret", output)
        self.assertIn("Showing 2 of 2 TLS Secret(s).", output)
        self.assertTrue(all(len(line) <= 110 for line in output.splitlines()),
                        "Wide inventory must not wrap terminal table columns")

    def test_narrow_terminal_uses_stacked_details_not_clipped_table(self):
        output = self.screen(84)
        self.assertIn("development-with-long-namespace-name/", output)
        self.assertIn("Ingress: very-long-ingress-subdomain.example.test", output)
        self.assertIn("Days remaining: 0", output)
        self.assertNotIn("  #  Namespace", output)

    def test_filtered_counts_and_active_filters_are_explicit(self):
        output = self.screen(120, rows=self.rows[:1], total_rows=2,
                             filters={"Namespace": "dev", "Status": "VALID",
                                      "Search": "long"})
        self.assertIn("Showing 1 of 2 TLS Secret(s).", output)
        self.assertIn("\n  ACTIVE FILTERS\n", output)
        self.assertIn("Namespace   : dev", output)
        self.assertIn("Status      : VALID", output)
        self.assertIn("Search      : long", output)

    def test_no_matching_rows_still_shows_navigation_context(self):
        output = self.screen(100, rows=[], total_rows=2,
                             filters={"Search": "not-present"})
        self.assertIn("No TLS Secrets match the current filters.", output)
        self.assertIn("Showing 0 of 2 TLS Secret(s).", output)

    def test_help_distinguishes_full_reports_from_candidate_shortlist(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            wizard.inventory_help()
        output = buffer.getvalue()
        self.assertIn("full, unfiltered CSV, JSON and Markdown", output)
        self.assertIn("advisory CSV; NOT a renewal plan", output)
        self.assertIn("Filtering never changes", output)
        self.assertNotIn("\x1b[", output)


if __name__ == "__main__":
    unittest.main()
