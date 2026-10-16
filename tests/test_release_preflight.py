"""Synthetic, network-free checks for immutable release eligibility."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/ci/release_preflight.py"
spec = importlib.util.spec_from_file_location("kaori_release_preflight", SOURCE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
REPO = "OXY7O/kaori-tls-secret-manager"
TOKEN = "synthetic-only-do-not-use"


def metadata(base, version="0.1.2"):
    base = Path(base)
    (base / "VERSION").write_text(version + "\n", encoding="utf-8")
    (base / "CHANGELOG.md").write_text(
        "# Changelog\n\n## [" + version + "] - 2026-10-16\n", encoding="utf-8"
    )
    (base / "docs/releases").mkdir(parents=True)
    (base / "docs/releases" / ("v" + version + ".md")).write_text(
        "# Synthetic release\n", encoding="utf-8"
    )
    (base / "assets").mkdir()
    for asset in ("kaori-logo.png", "kaori-mark.png"):
        (base / "assets" / asset).write_bytes(b"synthetic asset")


def published(version="0.1.2"):
    return {"draft": False, "prerelease": False,
            "assets": [{"name": "kaori-tls-secret-manager-v" + version + ".tar.gz"},
                       {"name": "SHA256SUMS"}]}


class ReleasePreflightTests(unittest.TestCase):
    def test_release_workflow_uses_canonical_name_for_title_and_archive(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('KAORI TLS Secret Manager ${TAG}', workflow)
        self.assertIn('kaori-tls-secret-manager-${TAG}.tar.gz', workflow)
        self.assertNotIn("KAORI TLS Management", workflow)
        self.assertNotIn("kaori-tls-management-", workflow)

    def test_published_version_skips_packaging_without_tag_probe(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate, "github_get", return_value=(200, published())
        ) as api:
            metadata(tmp)
            result = gate.decide(Path(tmp), repository=REPO, token=TOKEN)
        self.assertFalse(result["publish"])
        self.assertEqual(result["tag"], "v0.1.2")
        api.assert_called_once()

    def test_new_version_requires_both_release_and_tag_absent(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate, "github_get", side_effect=[(404, None), (404, None)]
        ) as api:
            metadata(tmp)
            result = gate.decide(Path(tmp), repository=REPO, token=TOKEN)
        self.assertTrue(result["publish"])
        self.assertEqual(api.call_args_list[1].args[0], "git/ref/tags/v0.1.2")

    def test_existing_tag_without_release_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate, "github_get", side_effect=[(404, None), (200, {})]
        ):
            metadata(tmp)
            with self.assertRaisesRegex(ValueError, "refusing to repurpose"):
                gate.decide(Path(tmp), repository=REPO, token=TOKEN)

    def test_incomplete_existing_release_blocks_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            metadata(tmp)
            for incomplete in [
                {"draft": True, "prerelease": False, "assets": published()["assets"]},
                {"draft": False, "prerelease": True, "assets": published()["assets"]},
                {"draft": False, "prerelease": False, "assets": [{"name": "SHA256SUMS"}]},
            ]:
                with self.subTest(release=incomplete), patch.object(
                    gate, "github_get", return_value=(200, incomplete)
                ):
                    with self.assertRaisesRegex(ValueError, "manual review"):
                        gate.decide(Path(tmp), repository=REPO, token=TOKEN)

    def test_invalid_version_and_missing_release_files_fail_before_api(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate, "github_get"
        ) as api:
            metadata(tmp)
            (Path(tmp) / "VERSION").write_text("0.1.2-rc.1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "MAJOR.MINOR.PATCH"):
                gate.decide(Path(tmp), repository=REPO, token=TOKEN)
            (Path(tmp) / "VERSION").write_text("0.1.2\n", encoding="utf-8")
            (Path(tmp) / "docs/releases/v0.1.2.md").unlink()
            with self.assertRaisesRegex(ValueError, "Missing release metadata"):
                gate.decide(Path(tmp), repository=REPO, token=TOKEN)
        api.assert_not_called()

    def test_unexpected_api_status_must_not_look_like_no_release(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            gate, "github_get", return_value=(403, {})
        ):
            metadata(tmp)
            with self.assertRaisesRegex(RuntimeError, "Unexpected release API"):
                gate.decide(Path(tmp), repository=REPO, token=TOKEN)

    def test_http_403_fails_closed_and_404_is_explicitly_absent(self):
        def fail(code):
            return urllib.error.HTTPError("https://api.github.com/fixture", code,
                                         "Synthetic", {}, io.BytesIO(b"{}"))

        with patch.object(gate.urllib.request, "urlopen", side_effect=fail(403)):
            with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
                gate.github_get("releases/tags/v0.1.2", repository=REPO, token=TOKEN)
        with patch.object(gate.urllib.request, "urlopen", side_effect=fail(404)):
            self.assertEqual(
                gate.github_get("releases/tags/v0.1.2", repository=REPO, token=TOKEN),
                (404, None))

    def test_repository_and_token_are_required(self):
        for repository, token in [("../unsafe", TOKEN), (REPO, ""), ("", TOKEN)]:
            with self.subTest(repository=repository, token=bool(token)):
                with self.assertRaisesRegex(ValueError, "repository/token"):
                    gate.github_get("releases/tags/v0.1.2", repository=repository,
                                    token=token)

    def test_workflow_will_not_start_publisher_for_existing_release(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: Quality Gate", workflow)
        self.assertIn("name: Release Preflight", workflow)
        self.assertIn("name: Publish Release", workflow)
        publisher = workflow.split("\n  publish_release:", 1)[1]
        self.assertIn("needs.release_preflight.outputs.publish == 'true'", publisher)
        self.assertIn("contents: write", publisher)
        self.assertIn("if: steps.recheck.outputs.publish == 'true'", publisher)
        preflight = workflow.split("\n  release_preflight:", 1)[1].split(
            "\n  publish_release:", 1)[0]
        self.assertIn("contents: read", preflight)
        self.assertNotIn("contents: write", preflight)
        self.assertNotIn("git archive", preflight)

    def test_release_preflight_is_never_a_required_pr_check(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn(
            "if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}",
            workflow)
        self.assertIn("needs: quality_gate", workflow)

    def test_active_repository_has_a_complete_immutable_release(self):
        # No network: verifies the checked-out version, changelog and local assets.
        self.assertEqual(gate.release_version(ROOT), "0.2.7")


if __name__ == "__main__":
    unittest.main()
