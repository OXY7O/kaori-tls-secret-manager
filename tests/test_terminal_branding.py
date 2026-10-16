"""Offline tests for the readable KAORI terminal-only branding."""
import base64
import importlib.util
from io import StringIO
from pathlib import Path
import re
import struct
import tempfile
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

    def test_iterm_embeds_real_icon_and_readable_two_line_title(self):
        output = TtyStream()
        env = {"TERM": "xterm-256color", "TERM_PROGRAM": "iTerm.app"}
        mode = brand.render_header(stream=output, environ=env, width=80)
        self.assertEqual(mode, "iterm")
        rendered = output.getvalue()
        self.assertIn("File=inline=1;width=16;height=8;", rendered)
        encoded = rendered.split(":", 1)[1].split("\x07", 1)[0]
        self.assertEqual(base64.b64decode(encoded), brand.ICON_FILE.read_bytes())
        self.assertIn("\x1b7", rendered)
        self.assertIn("\x1b8", rendered)
        self.assertIn(" │ ", rendered)
        self.assertIn("KAORI", rendered)
        self.assertIn("TLS Secret Management", rendered)
        self.assertNotIn("■", rendered)
        self.assertNotIn("▪", rendered)

    def test_ansi_preserves_icon_and_readable_labels_in_color_ttys(self):
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
                self.assertIn("KAORI", rendered)
                self.assertIn("TLS Secret Management", rendered)
                self.assertIn(" │ ", rendered)
                self.assertNotIn("\x1b]1337", rendered)
                self.assertNotIn("■", rendered)
                self.assertNotIn("▪", rendered)

    def test_80_column_terminal_does_not_wrap(self):
        output = TtyStream()
        mode = brand.render_header(stream=output, environ={"TERM": "xterm-256color"},
                                   width=80)
        self.assertEqual(mode, "ansi")
        cleaned = [re.sub(r"\x1b\[[0-9;]*m", "", line)
                   for line in output.getvalue().splitlines()]
        self.assertLess(max(len(line) for line in cleaned), 80)
        self.assertEqual(sum("KAORI" in line for line in cleaned), 1)
        self.assertEqual(sum("TLS Secret Management" in line for line in cleaned), 1)
        title = next(i for i, line in enumerate(cleaned) if "KAORI" in line)
        subtitle = next(i for i, line in enumerate(cleaned)
                        if "TLS Secret Management" in line)
        self.assertEqual(subtitle - title, 2)
        self.assertEqual(sum(' │ ' in line for line in cleaned), 8)

    def test_custom_title_is_readable_and_not_glyph_limited(self):
        output = TtyStream()
        mode = brand.render_header("KAORI", "Custom CLI Tool", stream=output,
                                   environ={"TERM": "xterm-256color"}, width=80)
        self.assertEqual(mode, "ansi")
        self.assertIn("Custom CLI Tool", output.getvalue())

    def test_terminal_too_narrow_for_long_title_uses_safe_fallback(self):
        output = TtyStream()
        mode = brand.render_header(
            "KAORI", "A longer subtitle that cannot fit within 53 columns",
            stream=output, environ={"TERM": "xterm-256color"}, width=53)
        self.assertEqual(mode, "plain")
        self.assertNotIn("\x1b", output.getvalue())

    def test_ansi_grid_keeps_correct_dimensions_and_reset(self):
        rows = brand.pixel_rows(truecolor=True)
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row.endswith("\x1b[0m") for row in rows))
        self.assertTrue(all(row.count("▀") == 16 for row in rows))
        self.assertTrue(any("\x1b[38;2;" in row for row in rows))

    def test_plain_no_color_dumb_redirect_narrow_and_disabled_unicode(self):
        conditions = [
            (StringIO(), {"TERM": "xterm-256color"}, 80, True, True),
            (TtyStream(), {"NO_COLOR": "", "TERM": "xterm-256color"}, 80, True, True),
            (TtyStream(), {"TERM": "dumb"}, 80, True, True),
            (TtyStream(), {"CLICOLOR": "0", "TERM": "xterm-256color"}, 80, True, True),
            (TtyStream(), {"TERM": "xterm-256color"}, 80, False, True),
            (TtyStream(), {"TERM": "xterm-256color"}, 80, True, False),
            (TtyStream(), {"TERM": "xterm-256color"}, 36, True, True),
        ]
        for stream, env, width, color, unicode in conditions:
            with self.subTest(env=env, width=width, color=color, unicode=unicode):
                mode = brand.render_header(stream=stream, environ=env,
                                           width=width, color=color, unicode=unicode)
                self.assertEqual(mode, "plain")
                rendered = stream.getvalue()
                self.assertNotIn("\x1b", rendered)
                self.assertTrue(rendered.isascii())
                self.assertIn("KAORI", rendered)
                self.assertIn("TLS Secret Management", rendered)

    def test_missing_or_invalid_iterm_png_uses_ansi_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.png"
            for data in (None, b"not a PNG"):
                if data is not None:
                    path.write_bytes(data)
                output = TtyStream()
                mode = brand.render_header(stream=output, image_file=path,
                                           environ={"TERM": "xterm-256color",
                                                    "TERM_PROGRAM": "iTerm.app"}, width=80)
                self.assertEqual(mode, "ansi")
                self.assertIn("▀", output.getvalue())
                self.assertIn("TLS Secret Management", output.getvalue())
                self.assertNotIn("\x1b]1337", output.getvalue())
                if path.exists():
                    path.unlink()

    def test_header_has_no_cluster_or_shell_side_effects(self):
        output = TtyStream()
        with patch.object(brand, "inline_iterm_icon", return_value=False):
            brand.render_header(stream=output,
                                environ={"TERM": "xterm-256color"}, width=80)
        self.assertIn("TLS Secret Management", output.getvalue())


if __name__ == "__main__":
    unittest.main()
