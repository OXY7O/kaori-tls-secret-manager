"""Documentation integrity and current release messaging checks."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]+\")?\)")
HTML_SRC = re.compile(r"\b(?:href|src)=\"([^\"]+)\"")

PUBLIC_GUIDES = [
    "README.md",
    "SUPPORT.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/ARCHITECTURE.md",
    "docs/INSTALLATION.md",
    "docs/OPERATOR-GUIDE.md",
    "docs/FAQ.md",
    "docs/RELEASE-POLICY.md",
]

ARCHIVED_REFERENCES = (
    "LOCAL-TEST.md",
    "RELEASE-CHECKLIST.md",
    "COMMUNITY-SETUP.md",
    "MIGRATION.md",
)


class DocumentationIntegrityTests(unittest.TestCase):
    def test_no_broken_relative_markdown_links(self):
        for file in ROOT.rglob("*.md"):
            if ".git" in file.parts:
                continue
            data = file.read_text(encoding="utf-8")
            with self.subTest(file=str(file.relative_to(ROOT))):
                links = [match.group(1) for match in MARKDOWN_LINK.finditer(data)]
                links += [match.group(1) for match in HTML_SRC.finditer(data)]
                for raw in links:
                    path = unquote(raw.split("#", 1)[0])
                    if not path or path.startswith(("/", "https:", "http:", "mailto:", "data:", "plugin:")):
                        continue
                    # Treat links like ../SECURITY.md as paths relative to their Markdown file.
                    target = (file.parent / path).resolve()
                    self.assertTrue(
                        target.is_relative_to(ROOT.resolve()),
                        f"{file}: link escapes repository: {raw}"
                    )
                    self.assertTrue(target.exists(), f"{file}: missing link target: {raw}")

    def test_published_release_is_default_in_user_guides(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        current_version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(current_version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f"v{current_version}", readme)
        self.assertIn(f"docs/releases/v{current_version}.md", readme)
        self.assertIn("docs/INSTALLATION.md", readme)
        self.assertIn("Quality Gate", readme)
        self.assertNotIn("development preview", readme.lower())

    def test_old_handoff_documents_are_not_required(self):
        for name in ARCHIVED_REFERENCES:
            for file in ROOT.rglob("*.md"):
                if file.name in ("v0.1.0-rc.1.md",):
                    continue
                with self.subTest(file=str(file.relative_to(ROOT)), archived=name):
                    self.assertNotIn(name, file.read_text(encoding="utf-8"))

    def test_operator_docs_present_current_scope(self):
        stale = ("dev/uat only", "only in authorized dev/uat", "prototype",
                 "development preview", "migration pending", "local test")
        for name in PUBLIC_GUIDES:
            content = (ROOT / name).read_text(encoding="utf-8").lower()
            for phrase in stale:
                with self.subTest(file=name, phrase=phrase):
                    self.assertNotIn(phrase, content)


if __name__ == "__main__":
    unittest.main()
