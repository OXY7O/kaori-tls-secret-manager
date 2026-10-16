# KAORI visual identity

**KAORI TLS Secret Manager** deliberately separates public documentation branding from the icon used **inside interactive CLI terminals**.

## Assets

| Asset | Scope |
| --- | --- |
| [kaori-logo.png](../assets/kaori-logo.png) | Corrected README/documentation wordmark: **KAORI TLS Secret Manager**, with the approved purple icon |
| [kaori-mark.png](../assets/kaori-mark.png) | Original public square orbital-K mark; unchanged |
| [kaori-cli-mark.png](../assets/kaori-cli-mark.png) | **Approved violet four-petal terminal header icon**, optimized from the supplied original |

The new purple mark is the header-icon standard for **future KAORI command-line tools**. It does not replace website, README, or other product imagery.

## Readable terminal title

The standard header keeps the approved purple icon at left and uses two clear, ordinary terminal-text lines on the right:

- **KAORI**
- **TLS Secret Management**

A thin vertical separator separates branding from the text, with a horizontal rule under the header. The former square-tile/8-bit title font was removed in **v0.2.3** because it made the product name and subtitle difficult to read. It is not used as a fallback. Other KAORI CLI tools should reuse this simple visual pattern rather than inventing separate pixel-title fonts.

Terminal width is checked so labels do not wrap. On `--plain`, `NO_COLOR`, narrow or redirected terminals, output stays ASCII-only with no graphics control sequences. This affects interactive headers only; machine-readable JSON stays unchanged. The README wordmark is separately updated to the canonical product name.

## Reusable terminal renderer

[terminal_branding.py](../scripts/kubernetes/tls-secret-manager/terminal_branding.py) exports `render_header(product, subtitle, ...)`. The TLS wizard invokes it; other KAORI terminal tools can reuse the same module or asset and behavior, rather than drawing their own ASCII logos.

- **iTerm2 + interactive color:** embed the approved PNG using supported OSC 1337 inline-image control at a compact `16x8` terminal-cell size.
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

## Compact terminal layout (v0.2.6)

Interactive ANSI terminals render the approved violet logo in a 16-cell-wide by 8-row grid, with a vertical rule of equal height and the two-line readable label centered alongside it. iTerm2 uses the original PNG displayed at 16x8 terminal cells. The underlying image assets and README wordmark remain unchanged. This is a human-facing terminal convention only; width-aware, `--plain`, `NO_COLOR` and redirected-output fallbacks stay escape-free.

## Full-height application information panel (v0.2.7)

The interactive terminal displays **eight top-aligned text rows next to the eight-row purple icon**, styled after neofetch. Rather than repeating a two-line title with empty space, the panel includes the product label, subtitle, maintainer organization, checkout version, Kubernetes TLS Secret scope, active Python runtime, detected host platform, and project license.

```text
KAORI
TLS Secret Management
Maintainer : OXY7O
Version    : v0.2.7
Scope      : kubernetes.io/tls
Runtime    : Python 3.x
Platform   : (detected host OS)
License    : Apache-2.0
```

The version is read from the current checkout's `VERSION` file, with a `development` fallback if unavailable. Python and OS information is collected locally. The header **never contacts Kubernetes, reads kubeconfig credentials, or declares a cluster healthy**. The saved-run count and default Inventory (read-only) remain immediately below the header. Non-TTY, `--plain`, `NO_COLOR`, dumb or narrow terminals receive an equivalent escape-free text panel.
