#!/bin/bash
# diagnose.sh - Comprehensive diagnostic script for Vaultwarden stack

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== Vaultwarden Stack Diagnostics ===${NC}"
echo "Generated at: $(date)"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo ""

# Function to get container ID dynamically
get_container_id() {
    local service_name=$1
    docker compose ps -q "$service_name" 2>/dev/null || echo ""
}

# Function to run diagnostic tests
run_diagnostic() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $test_name: PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ $test_name: FAIL${NC}"
        return 1
    fi
}

# System Requirements Check
echo -e "${BLUE}🔍 System Requirements Check:${NC}"
run_diagnostic "Docker installed" "command -v docker"
run_diagnostic "Docker Compose installed" "command -v docker compose"
run_diagnostic "Docker daemon running" "docker info"
run_diagnostic "Sufficient disk space (>2GB free)" "[ \$(df --output=avail . | tail -1) -gt 2097152 ]"
run_diagnostic "Sufficient RAM (>1GB free)" "[ \$(free -m | awk '/^Mem:/{print \$7}') -gt 1024 ]"

echo ""
echo -e "${BLUE}📁 File Structure Check:${NC}"
run_diagnostic "settings.env exists" "[ -f ./settings.env ]"
run_diagnostic "docker-compose.yml exists" "[ -f ./docker-compose.yml ]"
run_diagnostic "Caddyfile exists" "[ -f ./caddy/Caddyfile ]"
run_diagnostic "Fail2ban config exists" "[ -f ./fail2ban/jail.d/jail.local ]"
run_diagnostic "Data directory exists" "[ -d ./data ]"
run_diagnostic "Data directory writable" "[ -w ./data ]"

echo ""
echo -e "${BLUE}🐳 Container Status Check:${NC}"
services=("vaultwarden" "mariadb" "redis" "caddy" "fail2ban" "backup" "watchtower")

for service in "${services[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        status=$(docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null || echo "unknown")
        health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-health-check{{end}}' "$container_id" 2>/dev/null || echo "unknown")
        
        case $status in
            "running")
                if [ "$health" = "healthy" ]; then
                    echo -e "${GREEN}✅ $service: Running and Healthy${NC}"
                elif [ "$health" = "unhealthy" ]; then
                    echo -e "${RED}❌ $service: Running but Unhealthy${NC}"
                    echo "   Health check details:"
                    docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' "$container_id" | tail -3
                else
                    echo -e "${YELLOW}⚠️  $service: Running (no health check)${NC}"
                fi
                ;;
            *)
                echo -e "${RED}❌ $service: $status${NC}"
                echo "   Recent logs:"
                docker logs --tail 5 "$container_id" 2>/dev/null || echo "   No logs available"
                ;;
        esac
    else
        echo -e "${RED}❌ $service: Not found or not running${NC}"
    fi
done

echo ""
echo -e "${BLUE}🌐 Network Connectivity Check:${NC}"

# Test internal connectivity
vaultwarden_id=$(get_container_id "vaultwarden")
if [ -n "$vaultwarden_id" ]; then
    run_diagnostic "Vaultwarden HTTP endpoint" "docker exec $vaultwarden_id curl -f http://localhost:80/ --max-time 10"
fi

mariadb_id=$(get_container_id "mariadb")
if [ -n "$mariadb_id" ]; then
    run_diagnostic "MariaDB connectivity" "docker exec $mariadb_id mysqladmin ping -h localhost --silent"
fi

redis_id=$(get_container_id "redis")
if [ -n "$redis_id" ]; then
    run_diagnostic "Redis connectivity" "docker exec $redis_id redis-cli ping"
fi

# Test external connectivity
run_diagnostic "External DNS resolution" "nslookup google.com"
run_diagnostic "External HTTP connectivity" "curl -f https://httpbin.org/status/200 --max-time 10"

echo ""
echo -e "${BLUE}🔧 Configuration Validation:${NC}"

# Load settings if available
if [ -f ./settings.env ]; then
    source ./settings.env
    
    # Validate key settings
    run_diagnostic "DOMAIN_NAME configured" "[ -n \"\${DOMAIN_NAME:-}\" ]"
    run_diagnostic "DATABASE_URL configured" "[ -n \"\${DATABASE_URL:-}\" ]"
    run_diagnostic "ADMIN_TOKEN configured" "[ -n \"\${ADMIN_TOKEN:-}\" ]"
    
    # Test domain resolution if configured
    if [ -n "${DOMAIN_NAME:-}" ]; then
        run_diagnostic "Domain resolves" "nslookup vault.${DOMAIN_NAME}"
    fi
fi

echo ""
echo -e "${BLUE}📊 Resource Usage:${NC}"
echo "CPU Usage:"
top -bn1 | grep "Cpu(s)" || echo "CPU info not available"

echo ""
echo "Memory Usage:"
free -h

echo ""
echo "Disk Usage:"
df -h ./data/ 2>/dev/null || echo "Data directory not found"

echo ""
echo -e "${BLUE}📝 Recent Error Logs:${NC}"
for service in "${services[@]}"; do
    container_id=$(get_container_id "$service")
    if [ -n "$container_id" ]; then
        echo ""
        echo -e "${YELLOW}--- $service errors ---${NC}"
        docker logs --tail 20 "$container_id" 2>&1 | grep -i error || echo "No recent errors"
    fi
done

echo ""
echo -e "${BLUE}🔗 Useful Commands:${NC}"
echo "View all logs:           ./monitor.sh"
echo "Restart services:        docker compose restart"
echo "View specific logs:      docker compose logs [service_name]"
echo "Update configuration:    ./update-settings.sh"
echo "Manual backup:           docker compose exec backup /backup/backup.sh"

echo ""
echo -e "${GREEN}Diagnostic complete!${NC}"
echo "If issues persist, check the logs above and ensure all requirements are met."
