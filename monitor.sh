#!/usr/bin/env bash
# monitor.sh - monitor stack status

set -euo pipefail

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Source environment variables
if [[ -f "settings.env" ]]; then
    source "settings.env"
else
    echo -e "${RED}Error: settings.env not found.${NC}"
    exit 1
fi

echo "=== VAULTWARDEN STACK STATUS ==="
date
echo
echo "== Containers (Colorized) =="
docker compose ps | sed -E \
    -e "s/(.*) (running|healthy)(.*)/${GREEN}\1 \2\3${NC}/g" \
    -e "s/(.*) (unhealthy|exited)(.*)/${RED}\1 \2\3${NC}/g" \
    -e "s/(.*) (starting)(.*)/${YELLOW}\1 \2\3${NC}/g"

echo
echo "== Resource Usage =="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
echo
echo "== Disk Usage =="
df -h "$HOME/VaultWarden-OCI/data" || true
echo
echo "== Fail2ban (summary) =="
if docker ps --format '{{.Names}}' | grep -q "^${FAIL2BAN_CONTAINER}$"; then
  docker exec "$FAIL2BAN_CONTAINER" fail2ban-client status || true
else
  echo "fail2ban not running"
fi
echo
echo "== Recent Vaultwarden logs =="
docker compose logs --tail=50 "$VAULTWARDEN_CONTAINER" || true
