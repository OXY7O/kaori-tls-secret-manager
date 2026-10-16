"""Protect the current product scope and explicit operator approval wording."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

CURRENT_DOCS = (
    "README.md", "SECURITY.md", "GOVERNANCE.md", "SUPPORT.md",
    "docs/ARCHITECTURE.md", "docs/BRANDING.md", "docs/COMMAND-REFERENCE.md",
    "docs/FAQ.md", "docs/INSTALLATION.md", "docs/OPERATOR-GUIDE.md",
    "docs/RELEASE-POLICY.md", "docs/SCOPE-AND-AUTHORIZATION.md",
)
WIZARD = ROOT / "scripts/kubernetes/tls-secret-manager/tls_secret_wizard.py"
DEPRECATED = (
    "KAORI TLS Management", "KAORI TLS Certificate Manager",
    "Safer Kubernetes TLS certificate management.",
    "Use only in authorized DEV/UAT. Approval is required before a write.",
)


class ScopeTerminologyTests(unittest.TestCase):
    def test_readme_and_scope_identify_exact_managed_kubernetes_resource(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        scope = (ROOT / "docs/SCOPE-AND-AUTHORIZATION.md").read_text(encoding="utf-8")
        self.assertIn("KAORI TLS Secret Manager", readme)
        self.assertIn("Safer Kubernetes TLS Secret management.", readme)
        self.assertIn("kubernetes.io/tls", readme)
        self.assertIn("does **not** issue", readme)
        self.assertIn("type: kubernetes.io/tls", scope)

    def test_active_product_copy_does_not_reintroduce_ambiguous_product_names(self):
        for path in CURRENT_DOCS:
            content = (ROOT / path).read_text(encoding="utf-8")
            for phrase in DEPRECATED:
                # Glossary alone may quote forbidden historical titles
                # to tell writers not to use them.
                if path == "docs/SCOPE-AND-AUTHORIZATION.md":
                    continue
                with self.subTest(path=path, phrase=phrase):
                    self.assertNotIn(phrase, content)

    def test_renewal_guidance_matches_actual_signing_rules(self):
        wizard = WIZARD.read_text(encoding="utf-8")
        self.assertIn("Use only a Kubernetes context and namespaces you are authorized", wizard)
        self.assertIn("Single-target renewal: type AUTHORIZED", wizard)
        self.assertIn("Multi-target/external-TLS renewal: independent signed approval", wizard)
        self.assertNotIn("Use only in authorized DEV/UAT. Approval is required before a write.", wizard)
        self.assertIn("counts['READY'] > 1", wizard)
        self.assertIn('row.get("verification_mode") == "EXTERNAL_TERMINATION"', wizard)
        self.assertIn('ask("Type AUTHORIZED after approving scope', wizard)
        self.assertIn('ask("Type the exact PLAN ID to execute")', wizard)

    def test_versioned_release_notes_include_current_scope(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\\d+\\.\\d+\\.\\d+$")
        notes = (ROOT / f"docs/releases/v{version}.md").read_text(encoding="utf-8")
        self.assertIn("KAORI TLS Secret Manager", notes)

    def test_png_wordmark_has_canonical_metadata(self):
        data = (ROOT / "assets/kaori-logo.png").read_bytes()
        self.assertIn(b"Title\x00KAORI TLS Secret Manager", data)
        self.assertNotIn(b"TLS Certificate Manager", data)


if __name__ == "__main__":
    unittest.main()
