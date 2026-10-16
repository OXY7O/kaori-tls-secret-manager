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


def inline_iterm_icon(stream, image_file=ICON_FILE, *, environ=None):
    """Only iTerm2 may receive OSC 1337; all other terminals use ANSI art."""
    env = os.environ if environ is None else environ
    if (not stream.isatty() or env.get("TERM_PROGRAM") != "iTerm.app"
            or env.get("KAORI_NO_IMAGE") == "1" or env.get("TERM") == "dumb"
            or "NO_COLOR" in env):
        return False
    try:
        data = Path(image_file).read_bytes()
    except OSError:
        return False
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 100_000:
        return False
    encoded = base64.b64encode(data).decode("ascii")
    stream.write("\x1b]1337;File=inline=1;width=18;height=9;preserveAspectRatio=1:"
                 + encoded + "\x07\n")
    return True


def render_header(product="KAORI", subtitle="TLS MANAGEMENT", *,
                  color=True, unicode=True, image_file=ICON_FILE,
                  stream=None, environ=None, width=None):
    """Show the approved mark ONLY in an interactive terminal.

    Use as the common terminal-header renderer for future KAORI CLI tools.
    Non-TTY, --plain, NO_COLOR and dumb terminals stay escape-free.
    This never touches stdout of machine-readable subcommands unless called.
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
        # A compact ASCII-only fallback, never the discontinued orbital-K art.
        output.write(f"  [KAORI]  {product}\n")
        output.write(f"           {subtitle}\n")
        output.write("  " + "-" * max(12, min(48, columns - 4)) + "\n")
        return "plain"
    if inline_iterm_icon(output, image_file, environ=env):
        output.write(f"  {product}  |  {subtitle}\n")
        output.write("  " + "─" * max(12, min(48, columns - 4)) + "\n")
        return "iterm"
    truecolor = (env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
                 or env.get("TERM_PROGRAM") in ("vscode", "Apple_Terminal", "WezTerm", "iTerm.app")
                 or bool(env.get("WT_SESSION")))
    labels = {3: product, 5: subtitle}
    for index, colored in enumerate(pixel_rows(truecolor=truecolor)):
        title = labels.get(index, "")
        output.write("  " + colored + "  │  " + title + "\n")
    output.write("  " + "─" * max(12, min(48, columns - 4)) + "\n")
    return "ansi"
