#!/usr/bin/env bash
# Backward-compatible entrypoint; the historical KAORI wizard owns the UI.
set -Eeuo pipefail
BASE="$(cd -- "$(dirname -- "$0")" && pwd)"
exec bash "$BASE/tls-secret-manager.sh" "$@"
