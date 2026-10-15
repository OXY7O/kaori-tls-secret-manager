"""Offline integrity checks for the PNGs distributed with the KAORI utility."""
from pathlib import Path
import struct
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def inspect_png(path):
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid PNG signature")
    offset = len(PNG_SIGNATURE)
    image_data = bytearray()
    dimensions = None
    finished = False
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("Truncated PNG chunk")
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        first = offset + 8
        end = first + size
        if end + 4 > len(data):
            raise ValueError("Invalid PNG chunk size")
        payload = data[first:end]
        expected = struct.unpack_from(">I", data, end)[0]
        actual = zlib.crc32(kind + payload) & 0xFFFFFFFF
        if actual != expected:
            raise ValueError("PNG CRC mismatch")
        if kind == b"IHDR":
            dimensions = struct.unpack_from(">IIBBBBB", payload)
        if kind == b"IDAT":
            image_data.extend(payload)
        if kind == b"IEND":
            finished = True
            if end + 4 != len(data):
                raise ValueError("Unexpected trailing PNG bytes")
        offset = end + 4
    if not finished or dimensions is None:
        raise ValueError("Incomplete PNG image")
    width, height, depth, color, _, _, _ = dimensions
    if depth != 8 or color != 3:
        raise ValueError("Expected indexed PNG with 8-bit palette")
    decoded = zlib.decompress(image_data)
    if len(decoded) != height * (width + 1):
        raise ValueError("PNG pixel length is inconsistent")
    if any(decoded[y * (width + 1)] != 0 for y in range(height)):
        raise ValueError("Unexpected PNG scanline filter")
    return width, height


class BrandingAssetTests(unittest.TestCase):
    def test_wordmark_png_has_valid_content(self):
        width, height = inspect_png(ASSETS / "kaori-logo.png")
        self.assertGreaterEqual(width, 600)
        self.assertGreaterEqual(height, 150)

    def test_square_icon_png_has_valid_content(self):
        width, height = inspect_png(ASSETS / "kaori-mark.png")
        self.assertEqual(width, height)
        self.assertGreaterEqual(width, 128)

    def test_readme_references_distributed_png_not_svg(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('src="assets/kaori-logo.png"', readme)
        self.assertNotIn('src="assets/kaori-logo.svg"', readme)


if __name__ == "__main__":
    unittest.main()
