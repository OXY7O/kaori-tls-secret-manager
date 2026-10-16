"""Synthetic checks for the approved, reusable KAORI terminal-only brand."""
import base64
import importlib.util
from io import StringIO
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts/kubernetes/tls-secret-manager/terminal_branding.py"
spec = importlib.util.spec_from_file_location("kaori_terminal_branding", MODULE)
brand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brand)


class TtyStream(StringIO):
    def isatty(self):
        return True


class TerminalBrandTests(unittest.TestCase):
    def test_approved_png_is_square_valid_and_not_the_readme_wordmark(self):
        path = ROOT / "assets/kaori-cli-mark.png"
        data = path.read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (128, 128))
        self.assertLess(len(data), 100_000)
        self.assertNotEqual(data, (ROOT / "assets/kaori-mark.png").read_bytes())
        self.assertEqual(brand.ICON_FILE, path)

    def test_iterm_embeds_real_approved_icon_instead_of_old_wordmark(self):
        output = TtyStream()
        env = {"TERM": "xterm-256color", "TERM_PROGRAM": "iTerm.app"}
        mode = brand.render_header(stream=output, environ=env, width=80)
        self.assertEqual(mode, "iterm")
        result = output.getvalue()
        self.assertIn("File=inline=1;width=18;height=11;", result)
        encoded = result.split(":", 1)[1].split("\x07", 1)[0]
        self.assertEqual(base64.b64decode(encoded), brand.ICON_FILE.read_bytes())
        self.assertIn("\x1b7", result)
        self.assertIn("\x1b8", result)
        self.assertIn("■", result)
        self.assertIn("▪", result)
        self.assertIn(" │ ", result)

    def test_ansi_fallback_uses_pixel_art_from_new_icon_for_any_color_tty(self):
        for env in (
            {"TERM": "xterm-256color", "COLORTERM": "truecolor"},
            {"TERM": "xterm-256color"},
            {"TERM": "xterm-256color", "TERM_PROGRAM": "iTerm.app",
             "KAORI_NO_IMAGE": "1"},
        ):
            with self.subTest(env=env):
                output = TtyStream()
                mode = brand.render_header(stream=output, environ=env, width=80)
                self.assertEqual(mode, "ansi")
                rendered = output.getvalue()
                self.assertIn("▀", rendered)
                self.assertIn("\x1b[", rendered)
                self.assertIn("■", rendered)
                self.assertIn("▪", rendered)
                self.assertIn(" │ ", rendered)
                self.assertNotIn("\x1b]1337", rendered)
                self.assertNotIn(".------.", rendered)

    def test_block_font_encodes_both_exact_titles(self):
        large = brand.block_text_rows("KAORI", brand.TITLE_FONT, "■")
        small = brand.block_text_rows("TLS MANAGEMENT", brand.SUBTITLE_FONT, "▪")
        self.assertEqual(len(large), 5)
        self.assertEqual(len(small), 5)
        self.assertTrue(any("■" in row for row in large))
        self.assertTrue(any("▪" in row for row in small))
        self.assertIsNone(brand.block_brand_rows("KAORI", "UNSUPPORTED?"))
        self.assertEqual(len(brand.block_brand_rows("KAORI", "TLS MANAGEMENT")), 11)

    def test_80_column_terminal_never_wraps_the_pixel_title(self):
        import re
        output = TtyStream()
        mode = brand.render_header(
            stream=output, environ={"TERM": "xterm-256color"},
            width=80)
        self.assertEqual(mode, "ansi")
        lines = output.getvalue().splitlines()
        cleaned = [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in lines]
        self.assertLess(max(len(line) for line in cleaned), 80)
        self.assertEqual(sum("■" in line for line in cleaned), 5)
        self.assertEqual(sum("▪" in line for line in cleaned), 5)

    def test_smaller_color_tty_preserves_icon_and_readable_text(self):
        output = TtyStream()
        mode = brand.render_header(
            stream=output, environ={"TERM": "xterm-256color"},
            width=70)
        self.assertEqual(mode, "ansi")
        self.assertIn("KAORI", output.getvalue())
        self.assertIn("TLS MANAGEMENT", output.getvalue())
        self.assertNotIn("■", output.getvalue())

    def test_ansi_grid_dimensions_and_terminal_escape_reset(self):
        rows = brand.pixel_rows(truecolor=True)
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(row.endswith("\x1b[0m") for row in rows))
        self.assertTrue(all(row.count("▀") == 20 for row in rows))
        self.assertTrue(any("\x1b[38;2;" in row for row in rows))

    def test_plain_no_color_dumb_redirect_or_narrow_are_escape_free(self):
        conditions = [
            (StringIO(), {"TERM": "xterm-256color"}, 80, True),
            (TtyStream(), {"NO_COLOR": "", "TERM": "xterm-256color"}, 80, True),
            (TtyStream(), {"TERM": "dumb"}, 80, True),
            (TtyStream(), {"TERM": "xterm-256color"}, 80, False),
            (TtyStream(), {"TERM": "xterm-256color"}, 36, True),
        ]
        for stream, env, width, color in conditions:
            with self.subTest(env=env, width=width, color=color):
                mode = brand.render_header(stream=stream, environ=env,
                                           width=width, color=color)
                self.assertEqual(mode, "plain")
                result = stream.getvalue()
                self.assertNotIn("\x1b", result)
                self.assertTrue(result.isascii())
                self.assertIn("KAORI", result)
                self.assertIn("TLS MANAGEMENT", result)

    def test_invalid_or_missing_png_falls_back_without_osc_sequence(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "invalid.png"
            for data in (None, b"not a PNG"):
                if data is not None:
                    target.write_bytes(data)
                output = TtyStream()
                mode = brand.render_header(stream=output, image_file=target,
                                           environ={"TERM": "xterm-256color",
                                                    "TERM_PROGRAM": "iTerm.app"},
                                           width=80)
                self.assertEqual(mode, "ansi")
                self.assertIn("▀", output.getvalue())
                self.assertNotIn("\x1b]1337", output.getvalue())
                if target.exists():
                    target.unlink()

    def test_header_never_touches_cluster_or_executes_commands(self):
        output = TtyStream()
        with patch.object(brand, "inline_iterm_icon", return_value=False):
            brand.render_header(stream=output, environ={"TERM": "xterm-256color"}, width=80)
        self.assertIn("■", output.getvalue())


if __name__ == "__main__":
    unittest.main()
