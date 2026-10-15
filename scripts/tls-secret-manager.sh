#!/usr/bin/env bash
# KAORI TLS Secret Manager - original guided menu and guarded CRUD engine.
set -Eeuo pipefail
DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
CORE="$DIR/kubernetes/tls-secret-manager"
if [[ ! -f "$CORE/tls_secret_manager.py" || ! -f "$CORE/tls_secret_wizard.py" ]]; then
  echo 'STOP: KAORI core modules are missing. Re-clone the repository.' >&2
  exit 2
fi
case "${1:-}" in
  crud)
    shift
    exec python3 "$DIR/tls_crud.py" "$@"
    ;;
  doctor)
    echo 'KAORI TLS Secret Manager - local dependencies'
    for tool in python3 openssl age kubectl; do
      if command -v "$tool" >/dev/null 2>&1; then
        printf '  %-8s available\n' "$tool"
      else
        printf '  %-8s missing\n' "$tool"
      fi
    done
    echo '  Original guided wizard and standalone CRUD: included'
    echo '  No cluster API requests performed by doctor.'
    ;;
  *)
    exec bash "$CORE/tls-secret-manager.sh" "$@"
    ;;
esac
