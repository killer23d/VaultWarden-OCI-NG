#!/usr/bin/env bash
# diagnose.sh - A script to troubleshoot the Vaultwarden stack.

set -euo pipefail

# ANSI color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "--- Starting Full Stack Diagnostics ---"

# 1. Check Overall Health of All Containers
echo -e "\n## 1. Checking Container Health..."
HEALTH_ISSUES=0
for container in $(docker compose ps -q); do
  name=$(docker inspect --format '{{.Name}}' "$container" | sed 's/^\///')
  status=$(docker inspect --format '{{.State.Status}}' "$container")
  health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no healthcheck{{end}}' "$container")

  printf "%-20s | Status: %-10s | Health: " "$name" "$status"
  if [[ "$health" == "healthy" ]]; then
    echo -e "${GREEN}${health}${NC}"
  elif [[ "$health" == "unhealthy" || "$status" != "running" ]]; then
    echo -e "${RED}${health}${NC}"
    HEALTH_ISSUES=$((HEALTH_ISSUES + 1))
  else
    echo -e "${YELLOW}${health}${NC}"
  fi
done

if [ "$HEALTH_ISSUES" -gt 0 ]; then
    echo -e "\n${RED}Health issues detected. Please check logs below.${NC}"
fi

# 2. Display Recent Logs for Each Container
echo -e "\n## 2. Displaying Last 15 Log Lines for Each Container..."
for service in $(docker compose ps --services); do
  echo -e "\n--- Logs for ${YELLOW}$service${NC} ---"
  docker compose logs --tail="15" "$service" || echo -e "${RED}Could not retrieve logs for $service.${NC}"
done

# 3. Test Network Connectivity
echo -e "\n## 3. Testing Internal Network Connectivity..."

# Test Vaultwarden -> MariaDB
echo -n "Vaultwarden -> MariaDB: "
if docker compose exec -T vaultwarden nc -z -w 5 mariadb 3306; then
  echo -e "${GREEN}SUCCESS${NC}"
else
  echo -e "${RED}FAILURE${NC}"
fi

# Test Vaultwarden -> Redis
echo -n "Vaultwarden -> Redis: "
if docker compose exec -T vaultwarden nc -z -w 5 redis 6379; then
  echo -e "${GREEN}SUCCESS${NC}"
else
  echo -e "${RED}FAILURE${NC}"
fi

# 4. Check Fail2ban Status
echo -e "\n## 4. Checking Fail2ban Status..."
if docker compose ps -q bw_fail2ban &> /dev/null; then
  echo -e "--- Fail2ban Jail Status ---"
  docker compose exec -T bw_fail2ban fail2ban-client status
  echo -e "\n--- Fail2ban Banned IPs ---"
  docker compose exec -T bw_fail2ban fail2ban-client status recidive | grep "Banned IP"
  docker compose exec -T bw_fail2ban fail2ban-client status sshd | grep "Banned IP"
  docker compose exec -T bw_fail2ban fail2ban-client status vaultwarden | grep "Banned IP"
else
    echo -e "${YELLOW}Fail2ban container not running. Skipping check.${NC}"
fi


echo -e "\n--- Diagnostics Complete ---"
