# KAORI visual identity

This repository includes original, scalable branding for **KAORI TLS Certificate Manager**.

| Asset | Purpose |
| --- | --- |
| [assets/kaori-logo.svg](../assets/kaori-logo.svg) | Full wordmark for README, documentation and project presentations |
| [assets/kaori-mark.svg](../assets/kaori-mark.svg) | Square shield-K mark for terminal splash, icon and badges |
| [assets/kaori-terminal.txt](../assets/kaori-terminal.txt) | Monochrome ASCII concept for future terminal-safe integration |

## Design

- **Concept:** a protective Kubernetes TLS shield containing a recognizable **K**, expressing deliberate, guarded certificate lifecycle management.
- **Colors:** deep midnight navy, cyan, blue and soft violet; light text on the full wordmark.
- **Accessibility:** mark and wordmark include meaningful SVG title/description. CLI branding must remain legible with **--plain**, **NO_COLOR**, redirected output and screen readers.
- **Usage:** keep proportions intact; prefer the SVG sources over screenshots or upscaled raster copies. Do not claim endorsement by Kubernetes or another third-party project.

## CLI integration contract

The SVG assets are **branding sources, not executable terminal code**. When adding them to the Python/Bash wizard later, print a compact ANSI/Unicode approximation only for capable TTYs, and fall back to the ASCII label **KAORI TLS Certificate Manager** otherwise. Do not add external rendering libraries or block CLI startup on missing assets. Avoid injecting decoration into machine-readable JSON, status evidence or stderr diagnostics.

Changes to the banner must keep command behavior and automated tests deterministic. Review the current [single-operator CLI behavior](../README.md) before integrating.
