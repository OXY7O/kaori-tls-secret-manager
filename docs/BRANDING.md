# KAORI visual identity

**KAORI TLS Management** deliberately separates public documentation branding from the icon used **inside interactive CLI terminals**.

## Assets

| Asset | Scope |
| --- | --- |
| [kaori-logo.png](../assets/kaori-logo.png) | Original README/documentation wordmark; unchanged |
| [kaori-mark.png](../assets/kaori-mark.png) | Original public square orbital-K mark; unchanged |
| [kaori-cli-mark.png](../assets/kaori-cli-mark.png) | **Approved violet four-petal terminal header icon**, optimized from the supplied original |

The new purple mark is the header-icon standard for **future KAORI command-line tools**. It does not replace website, README, or other product imagery.

## Retro square-tile title

The terminal header renders **KAORI** as a 5-by-5 bitmap font and **TLS MANAGEMENT** as compact 3-by-5 square-glyph text. This is **real terminal text**, not an image mockup. The logo remains the same approved violet image or ANSI icon. Width is checked before rendering: a normal 80-column terminal shows the 8-bit type without wrapping, while a narrower terminal displays the readable compact text labels.

The glyphs and geometry are defined in `terminal_branding.py` (`TITLE_FONT`, `SUBTITLE_FONT`, `block_brand_rows`). Unsupported product labels gracefully use compact text rather than rendering invalid characters. Non-interactive output, `--plain`, `NO_COLOR` and `TERM=dumb` keep an escape-free fallback; machine-readable JSON output is unaffected.

## Reusable terminal renderer

[terminal_branding.py](../scripts/kubernetes/tls-secret-manager/terminal_branding.py) exports `render_header(product, subtitle, ...)`. The TLS wizard invokes it; other KAORI terminal tools can reuse the same module or asset and behavior, rather than drawing their own ASCII logos.

- **iTerm2 + interactive color:** embed the approved PNG using supported OSC 1337 inline-image control at a compact `18x9` terminal-cell size.
- **Other interactive color terminals:** use ANSI half-block art derived from the same image, with 24-bit or 256-color palettes and no external Python dependencies.
- **No-color/plain, dumb, narrow, or redirected output:** print a compact ASCII-only header with no escape sequences.
- **`KAORI_NO_IMAGE=1`:** disable native iTerm2 PNG while retaining the colored ANSI pixel-art fallback.
- **`wizard --plain`, `NO_COLOR`, `CLICOLOR=0`:** no inline image or ANSI art.
- Never decorate JSON, subcommand help, pipelines or machine-readable output; the renderer is a UI-only concern.

For future CLI entrypoints:

```python
import sys
from terminal_branding import render_header

# Call only in the interactive human-facing menu.
render_header("KAORI", "MY CLI TOOL",
              color=sys.stdout.isatty(), unicode=True)
```

No branding routine may contact a cluster, install packages or mutate credentials. Test actual color TTY and plain mode before adoption.
