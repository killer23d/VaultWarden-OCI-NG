#!/usr/bin/env bash
# check-disk-space.sh - Check Disk Usage


set -euo pipefail
THRESHOLD="${THRESHOLD:-80}"
MOUNTPOINT="${MOUNTPOINT:-/}"

USAGE=$(df -P "$MOUNTPOINT" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
if [ "${USAGE:-0}" -gt "$THRESHOLD" ]; then
  MSG="WARNING: Disk usage on $MOUNTPOINT is ${USAGE}% (threshold ${THRESHOLD}%)"
  echo "$MSG"
  if command -v mail >/dev/null 2>&1; then
    echo "$MSG" | mail -s "Vaultwarden: High Disk Usage on $(hostname)" "admin@$(hostname -d 2>/dev/null || echo example.com)"
  fi
fi
