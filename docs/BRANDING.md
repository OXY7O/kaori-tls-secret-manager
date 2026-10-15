# KAORI visual identity

**KAORI TLS Management** uses a distinctive orbital-K identity: a kinetic K monogram with an orbiting connection endpoint. The wordmark and icon are supplied as transparent PNG files.

## PNG assets

| Asset | Purpose |
| --- | --- |
| [kaori-logo.png](../assets/kaori-logo.png) | Official wordmark for the GitHub README and documentation |
| [kaori-mark.png](../assets/kaori-mark.png) | Compact orbital-K icon for community assets and terminal artwork |

The PNG files are the distributed image source of truth; the README uses PNG, not an SVG logo.

## In the utility

The interactive wizard's previous oversized KAORI ASCII wordmark has been replaced by **the actual PNG** when launched in a compatible **iTerm2 terminal**, using the terminal's inline-image protocol. Other terminals automatically display a visually corresponding **orbital-K** text mark without external dependencies, image viewers or Kubernetes access.

- \`--plain\` and \`NO_COLOR\` use a readable ANSI-free text fallback.
- Redirected output, dumb terminals and missing/corrupt logo files never receive inline-image escape sequences.
- \`KAORI_NO_IMAGE=1\` explicitly disables inline PNG rendering when an iTerm2 session needs the text fallback.
- No decorative terminal data is injected into machine-readable CRUD JSON or non-interactive help.

For consistent sizing, use the logo in a wide aspect ratio and the mark for square displays. Never distort their proportions or imply endorsement by another project.
