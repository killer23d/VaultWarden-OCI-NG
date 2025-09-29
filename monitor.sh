#!/usr/bin/env bash
# monitor.sh - monitor stack status

set -euo pipefail
echo "=== VAULTWARDEN STACK STATUS ==="
date
echo
echo "== Containers =="
docker compose ps
echo
echo "== Resource Usage =="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
echo
echo "== Disk Usage =="
df -h "$HOME/VaultWarden-OCI/data" || true
echo
echo "== Fail2ban (summary) =="
if docker ps --format '{{.Names}}' | grep -q '^bw_fail2ban$'; then
  docker exec bw_fail2ban fail2ban-client status || true
else
  echo "fail2ban not running"
fi
echo
echo "== Recent Vaultwarden logs =="
docker compose logs --tail=50 vaultwarden || true
