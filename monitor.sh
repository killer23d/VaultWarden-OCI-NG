#!/bin/bash
# monitor.sh - Monitor Vaultwarden stack status and performance

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Vaultwarden Stack Monitor ===${NC}"
echo "Generated at: $(date)"
echo ""

# Function to get container ID dynamically
get_container_id() {
    local service_name=$1
    docker compose ps -q "$service_name" 2>/dev/null || echo ""
}

# Function to check service status
check_service_status() {
    local service_name=$1
    local container_id=$(get_container_id "$service_name")
    
    if [ -z "$container_id" ]; then
        echo -e "${RED}❌ $service_name: NOT RUNNING${NC}"
        return 1
    fi
    
    local status=$(docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null || echo "unknown")
    local health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-health-check{{end}}' "$container_id" 2>/dev/null || echo "unknown")
    
    case $status in
        "running")
            if [ "$health" = "healthy" ]; then
                echo -e "${GREEN}✅ $service_name: RUNNING (HEALTHY)${NC}"
            elif [ "$health" = "unhealthy" ]; then
                echo -e "${YELLOW}⚠️  $service_name: RUNNING (UNHEALTHY)${NC}"
            else
                echo -e "${GREEN}✅ $service_name: RUNNING${NC}"
            fi
            ;;
        "restarting")
            echo -e "${YELLOW}🔄 $service_name: RESTARTING${NC}"
            ;;
        "exited")
            echo -e "${RED}❌ $service_name: EXITED${NC}"
            ;;
        *)
            echo -e "${YELLOW}⚠️  $service_name: $status${NC}"
            ;;
    esac
}

# Check all services
echo -e "${BLUE}📋 Service Status:${NC}"
services=("vaultwarden" "mariadb" "redis" "caddy" "fail2ban" "backup" "watchtower")
for service in "${services[@]}"; do
    check_service_status "$service"
done

echo ""
echo -e "${BLUE}📊 Resource Usage:${NC}"

# Get all running container IDs
running_containers=""
for service in "${services[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        running_containers="$running_containers $container_id"
    fi
done

if [ -n "$running_containers" ]; then
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}" $running_containers
else
    echo "No containers running"
fi

echo ""
echo -e "${BLUE}📝 Recent Logs (last 10 lines):${NC}"

# Show recent logs for each service
for service in "${services[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        echo ""
        echo -e "${YELLOW}--- $service logs ---${NC}"
        docker logs --tail 10 "$container_id" 2>/dev/null || echo "No logs available"
    fi
done

echo ""
echo -e "${BLUE}💾 Disk Usage:${NC}"
df -h ./data/ 2>/dev/null || echo "Data directory not found"

echo ""
echo -e "${BLUE}🌐 Network Status:${NC}"
docker network ls --filter name=vaultward --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"

echo ""
echo -e "${BLUE}📦 Docker Compose Status:${NC}"
docker compose ps

echo ""
echo -e "${GREEN}Monitor complete!${NC}"
