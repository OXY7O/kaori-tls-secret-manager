#!/usr/bin/env bash
# KAORI unified development launcher (never copies private code to public Git).
set -Eeuo pipefail
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Full legacy implementation is selected only via an explicit opt-in path.
# This temporary developer bridge will be retired after audited public migration.
legacy="${KAORI_LEGACY_DIR:-}"
if [[ -n "$legacy" ]]; then
  if [[ "$legacy" != /* ]]; then
    echo 'STOP: KAORI_LEGACY_DIR must be an absolute path.' >&2
    exit 2
  fi
  if [[ ! -f "$legacy/tls_secret_manager.py" || ! -f "$legacy/tls_secret_wizard.py" ]]; then
    echo 'STOP: KAORI_LEGACY_DIR does not contain both historical TLS modules.' >&2
    exit 2
  fi
fi

run_wizard() {
  if [[ -f "$BASE/tls_secret_wizard.py" && -f "$BASE/tls_secret_manager.py" ]]; then
    exec python3 "$BASE/tls_secret_wizard.py" "$@"
  fi
  if [[ -n "$legacy" ]]; then
    exec python3 "$legacy/tls_secret_wizard.py" "$@"
  fi
  echo 'Advanced KAORI wizard unavailable: it has not been migrated into the public repo; supply a local KAORI_LEGACY_DIR.' >&2
  echo 'See docs/LOCAL-LEGACY-TEST.md; this never fetches or publishes private code.' >&2
  exit 2
}

run_legacy() {
  if [[ -f "$BASE/tls_secret_manager.py" ]]; then
    exec python3 "$BASE/tls_secret_manager.py" "$@"
  fi
  if [[ -n "$legacy" ]]; then
    exec python3 "$legacy/tls_secret_manager.py" "$@"
  fi
  echo 'Advanced renewal CLI unavailable: supply an audited local KAORI_LEGACY_DIR.' >&2
  exit 2
}

case "${1:-}" in
  "")
    # The familiar historical nine-option wizard is the default when available.
    if [[ -n "$legacy" || -f "$BASE/tls_secret_wizard.py" ]]; then
      run_wizard
    fi
    exec python3 "$BASE/kaori_cli.py"
    ;;
  wizard|--interactive)
    shift
    run_wizard "$@"
    ;;
  legacy|renewal)
    shift
    run_legacy "$@"
    ;;
  crud)
    shift
    exec python3 "$BASE/tls_crud.py" "$@"
    ;;
  interactive|menu)
    shift
    exec python3 "$BASE/kaori_cli.py" "$@"
    ;;
  doctor)
    echo 'KAORI TLS Manager - local capability check'
    for item in python3 openssl age kubectl; do
      if command -v "$item" >/dev/null 2>&1; then
        echo "  $item: installed"
      else
        echo "  $item: missing"
      fi
    done
    echo '  CRUD: available'
    if [[ -n "$legacy" || -f "$BASE/tls_secret_wizard.py" ]]; then
      echo '  Advanced wizard: local source available (not DEV/UAT accepted)'
    else
      echo '  Advanced wizard: not included (see docs/LOCAL-LEGACY-TEST.md)'
    fi
    echo '  This check makes no Kubernetes API requests.'
    ;;
  --help|-h|help)
    cat <<'HELP'
KAORI TLS SECRET MANAGER - development CLI

  bash scripts/kaori-tls-secret-manager.sh doctor         Offline prerequisites
  bash scripts/kaori-tls-secret-manager.sh                Historical wizard if linked; otherwise safe read/plan menu
  bash scripts/kaori-tls-secret-manager.sh interactive    Safe standalone read/plan console
  bash scripts/kaori-tls-secret-manager.sh wizard         Full historical wizard (if linked)
  bash scripts/kaori-tls-secret-manager.sh legacy ...     Historical advanced renewal/rollback CLI (if linked)
  bash scripts/kaori-tls-secret-manager.sh crud ...       Explicit Create/Read/Update/Delete CLI

  For temporary local testing of the archived, original implementation:
    export KAORI_LEGACY_DIR="$HOME/workspace/ops-runbooks-tls-archive/scripts/kubernetes/tls-secret-manager"

  Explicit CRUD CLI commands must provide --context and scope.
  Mutations require an approved plan and valid independent signature.
  No automatic cluster writes, renewals or deletions are initiated by the menu.
  See docs/LOCAL-LEGACY-TEST.md for offline and read-only steps.
HELP
    ;;
  *)
    # Backward compatibility: direct flags invoke the standalone CRUD CLI.
    exec python3 "$BASE/tls_crud.py" "$@"
    ;;
esac
