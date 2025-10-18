#!/usr/bin/env bash
# tools/backup-monitor.sh - Wrapper to run backups and send email notifications

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/notifications.sh"

_set_log_prefix "backup-monitor"

main() {
  local type="${1:-db}"  # db|full
  local script="" name=""

  case "$type" in
    db)   script="$ROOT_DIR/tools/db-backup.sh";           name="Database" ;;
    full) script="$ROOT_DIR/tools/create-full-backup.sh";  name="Full System" ;;
    *)    _log_error "Unknown backup type: $type (use 'db' or 'full')"; exit 1 ;;
  esac

  local start_ts end_ts
  start_ts="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  send_notification "$name Backup Started" "The automated $name backup started at $start_ts on host $(hostname)."

  local output rc
  set +e
  output="$("$script" 2>&1)"
  rc=$?
  set -e

  end_ts="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  if [[ $rc -eq 0 ]]; then
    _log_success "$name backup completed successfully."
    send_notification "✅ $name Backup Successful" "The automated $name backup completed successfully at $end_ts.\n\nDetails:\n${output}"
    exit 0
  else
    _log_error "$name backup failed with exit code $rc."
    send_notification "❌ $name Backup FAILED" "The automated $name backup FAILED at $end_ts.\n\nExit code: $rc\n\nOutput:\n${output}"
    exit $rc
  fi
}

main "$@"
