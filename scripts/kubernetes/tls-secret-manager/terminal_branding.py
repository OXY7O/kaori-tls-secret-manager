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
    stream.write("\x1b]1337;File=inline=1;width=18;height=10;preserveAspectRatio=1:"
                 + encoded + "\x07")
    if newline:
        stream.write("\n")
    return True


def _divider(columns, unicode):
    return "  " + ("─" if unicode else "-") * max(12, min(56, columns - 4)) + "\n"


def render_header(product="KAORI", subtitle="TLS Secret Management", *,
                  color=True, unicode=True, image_file=ICON_FILE,
                  stream=None, environ=None, width=None):
    """Render a readable two-line title beside the approved purple terminal icon.

    Never emit ANSI or image protocols into non-interactive, plain, narrow,
    color-disabled or machine-readable output. This function has no cluster IO.
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

    # One line of text in the right-hand column always remains within
    # a normal terminal width; keep one spare column to prevent auto-wrap.
    left_width = 2 + 20 + len(" │ ")
    if max(len(product), len(subtitle)) + left_width >= columns:
        output.write(f"  [KAORI]  {product}\n")
        output.write(f"           {subtitle}\n")
        output.write(_divider(columns, False))
        return "plain"

    labels = {3: product, 5: subtitle}

    # Use the real PNG only where iTerm2 explicitly advertises support.
    # Cursor save/restore keeps text aligned without rendering a second icon.
    if env.get("TERM_PROGRAM") == "iTerm.app":
        output.write("  \x1b7")
        if inline_iterm_icon(output, image_file, environ=env, newline=False):
            output.write("\x1b8")
            for index in range(10):
                label = labels.get(index, "")
                if label:
                    tone = 97 if index == 3 else 37
                    label = f"\x1b[{tone}m{label}\x1b[0m"
                output.write("  " + " " * 20 + " │ " + label + "\n")
            output.write(_divider(columns, True))
            return "iterm"
        output.write("\x1b8")

    truecolor = (env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
                 or env.get("TERM_PROGRAM") in ("vscode", "Apple_Terminal", "WezTerm", "iTerm.app")
                 or bool(env.get("WT_SESSION")))
    for index, icon_row in enumerate(pixel_rows(truecolor=truecolor)):
        label = labels.get(index, "")
        if label:
            tone = 97 if index == 3 else 37
            label = f"\x1b[{tone}m{label}\x1b[0m"
        output.write("  " + icon_row + " │ " + label + "\n")
    output.write(_divider(columns, True))
    return "ansi"
