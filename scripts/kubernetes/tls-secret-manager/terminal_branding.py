"""Reusable KAORI brand mark for interactive terminal-only headers.

The indexed pixel grid below was sampled from assets/kaori-cli-mark.png,
the approved purple four-petal mark. It renders without Pillow, chafa,
terminal images, or any Kubernetes access.
"""
import base64
import os
from pathlib import Path
import shutil
import sys

ICON_FILE = Path(__file__).resolve().parents[3] / "assets" / "kaori-cli-mark.png"
# Black terminal background, violet petals, lavender frame, white center.
PALETTE = (
    (0, 0, 0), (55, 16, 108), (88, 18, 178), (105, 32, 208),
    (133, 58, 240), (171, 126, 250), (214, 194, 255), (248, 247, 252),
)
ANSI_256 = (16, 54, 92, 98, 135, 183, 225, 255)
PIXELS = (
    "00000000000000000000",
    "00011111100011111000",
    "00565555500344434200",
    "00555555510433333300",
    "00555555511443333300",
    "00555666666666533300",
    "00555665511435533300",
    "00555665555435533300",
    "00255655677644533100",
    "00000513777721500000",
    "00011533677633511000",
    "00243553566534533200",
    "00333542311324523300",
    "00333565534555523300",
    "00333455533555333300",
    "00333332300322333300",
    "00333333411333333300",
    "00122222100122222100",
    "00000000000000000000",
    "00000000000000000000",
)


def _color_code(index, *, background, truecolor):
    if truecolor:
        red, green, blue = PALETTE[index]
        return f"\x1b[{48 if background else 38};2;{red};{green};{blue}m"
    return f"\x1b[{48 if background else 38};5;{ANSI_256[index]}m"


def pixel_rows(*, truecolor=False):
    """One Unicode half-block is two source pixels; rows occupy 20 columns."""
    lines = []
    for top, bottom in zip(PIXELS[::2], PIXELS[1::2]):
        segments = []
        previous = None
        for upper, lower in zip(top, bottom):
            pair = (int(upper), int(lower))
            if pair != previous:
                segments.append(_color_code(pair[0], background=False, truecolor=truecolor))
                segments.append(_color_code(pair[1], background=True, truecolor=truecolor))
                previous = pair
            segments.append("▀")
        segments.append("\x1b[0m")
        lines.append("".join(segments))
    return lines


# Five rows of individual terminal-cell squares, not a decorative image/font.
# Keep these glyphs local and dependency-free so all KAORI CLIs can reuse them.
TITLE_FONT = {
    "K": ("10001", "10010", "11100", "10010", "10001"),
    "A": ("01110", "10001", "11111", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "01110"),
    "R": ("11110", "10001", "11110", "10100", "10010"),
    "I": ("11111", "00100", "00100", "00100", "11111"),
}
SUBTITLE_FONT = {
    "A": ("010", "101", "111", "101", "101"),
    "E": ("111", "100", "110", "100", "111"),
    "G": ("011", "100", "101", "101", "011"),
    "L": ("100", "100", "100", "100", "111"),
    "M": ("101", "111", "111", "101", "101"),
    "N": ("101", "111", "111", "111", "101"),
    "S": ("011", "100", "010", "001", "110"),
    "T": ("111", "010", "010", "010", "010"),
}


def block_text_rows(text, alphabet, tile="■"):
    """Return 5 rows of square-tile text; unsupported names stay legible.

    A character takes its glyph width plus one blank cell; word spacing
    takes two cells. Single-cell symbols avoid double-width Unicode art.
    """
    if any(char != " " and char not in alphabet for char in text.upper()):
        return None
    lines = []
    for line_number in range(5):
        parts = [("  " if char == " " else
                  "".join(tile if pixel == "1" else " " for pixel in alphabet[char][line_number]))
                 for char in text.upper()]
        lines.append(" ".join(parts).rstrip())
    return lines


def block_brand_rows(product, subtitle):
    """11-row header: large game-style title, spacer, small game subtitle."""
    title = block_text_rows(product, TITLE_FONT, "■")
    small = block_text_rows(subtitle, SUBTITLE_FONT, "▪")
    return title + [""] + small if title is not None and small is not None else None


def inline_iterm_icon(stream, image_file=ICON_FILE, *, environ=None, newline=True):
    """Use the approved purple PNG only in an explicitly supported iTerm2 TTY."""
    env = os.environ if environ is None else environ
    if (not stream.isatty() or env.get("TERM_PROGRAM") != "iTerm.app"
            or env.get("KAORI_NO_IMAGE") == "1" or env.get("TERM") == "dumb"
            or "NO_COLOR" in env or env.get("CLICOLOR") == "0"):
        return False
    try:
        data = Path(image_file).read_bytes()
    except OSError:
        return False
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 100_000:
        return False
    encoded = base64.b64encode(data).decode("ascii")
    stream.write("\x1b]1337;File=inline=1;width=18;height=11;preserveAspectRatio=1:"
                 + encoded + "\x07")
    if newline:
        stream.write("\n")
    return True


def _divider(columns, unicode):
    return "  " + ("─" if unicode else "-") * max(12, min(56, columns - 4)) + "\n"


def render_header(product="KAORI", subtitle="TLS MANAGEMENT", *,
                  color=True, unicode=True, image_file=ICON_FILE,
                  stream=None, environ=None, width=None):
    """Render the shared terminal-only mark and an optional 8-bit game title.

    No coloring or image escapes in redirected, plain, narrow or dumb output.
    Render only inside a human-interactive menu, never in machine-readable CLI.
    """
    output = sys.stdout if stream is None else stream
    env = os.environ if environ is None else environ
    columns = shutil.get_terminal_size(fallback=(80, 24)).columns if width is None else width
    tty = output.isatty()
    enabled = (tty and color and "NO_COLOR" not in env
               and env.get("CLICOLOR") != "0" and env.get("TERM") != "dumb")
    utf = unicode and (getattr(output, "encoding", None) or "utf-8").lower().startswith("utf")
    output.write("\n")
    if not enabled or not utf or columns < 53:
        output.write(f"  [KAORI]  {product}\n")
        output.write(f"           {subtitle}\n")
        output.write(_divider(columns, False))
        return "plain"

    logo_rows = pixel_rows(
        truecolor=(env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
                   or env.get("TERM_PROGRAM") in ("vscode", "Apple_Terminal", "WezTerm", "iTerm.app")
                   or bool(env.get("WT_SESSION"))))
    tile_rows = block_brand_rows(product, subtitle)
    # Leave at least one spare terminal column to prevent automatic wrap.
    pixel_title = (tile_rows is not None and
                   2 + 20 + len(" │ ") + max(len(row) for row in tile_rows) < columns)
    if pixel_title and env.get("TERM_PROGRAM") == "iTerm.app":
        # Save the cursor and draw the PNG on the left. Restore the cursor
        # before printing aligned block glyphs to the right of the image.
        # Never send this protocol to terminals that do not advertise iTerm2.
        output.write("  \x1b7")
        if inline_iterm_icon(output, image_file, environ=env, newline=False):
            output.write("\x1b8")
            for line in tile_rows:
                output.write("  " + " " * 20 + " │ "
                             + ("\x1b[97m" if line in tile_rows[:5] else "\x1b[37m")
                             + line + "\x1b[0m\n")
            output.write(_divider(columns, True))
            return "iterm"
        output.write("\x1b8")

    labels = tile_rows if pixel_title else [""] * 10
    if not pixel_title:
        labels[3] = product
        labels[6] = subtitle
    for index, graphic in enumerate(logo_rows):
        label = labels[index]
        shade = 97 if index < 5 else 37
        output.write("  " + graphic + " │ "
                     + (f"\x1b[{shade}m{label}\x1b[0m" if label else "")
                     + "\n")
    if pixel_title:
        # The small-font final row occupies one more line than the logo;
        # keep it aligned under the same right-hand text column.
        output.write("  " + " " * 20 + " │ \x1b[37m" + tile_rows[10] + "\x1b[0m\n")
    output.write(_divider(columns, True))
    return "ansi"
