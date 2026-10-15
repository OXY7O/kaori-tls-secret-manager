#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Zero arguments launches the human-friendly wizard. Explicit CLI commands remain unchanged.
if [[ "$#" -eq 0 || "${1:-}" == "wizard" || "${1:-}" == "--interactive" ]]; then
  if [[ "$#" -gt 0 ]]; then shift; fi
  exec python3 "$DIR/tls_secret_wizard.py" "$@"
fi
exec python3 "$DIR/tls_secret_manager.py" "$@"
