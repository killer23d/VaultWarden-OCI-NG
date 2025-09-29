#!/usr/bin/env bash
set -euo pipefail

CONTAINER="bw_fail2ban"
RECIPIENT="${REPORT_RECIPIENT:-admin@$(hostname -d 2>/dev/null || echo example.com)}"

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "fail2ban container '${CONTAINER}' not running"
  exit 0
fi

REPORT=$(
  {
    echo "Fail2ban Status Report - $(date)"
    echo
    docker exec "$CONTAINER" fail2ban-client status || true
    echo
    for J in $(docker exec "$CONTAINER" fail2ban-client status | awk -F': ' '/Jail list/ {print $2}' | tr ',' ' '); do
      echo ">>> Jail: $J"
      docker exec "$CONTAINER" fail2ban-client status "$J" || true
      echo
    done
  } 2>&1
)

echo "$REPORT"

if command -v mail >/dev/null 2>&1; then
  echo "$REPORT" | mail -s "Vaultwarden: Weekly Fail2ban Report" "$RECIPIENT"
fi
