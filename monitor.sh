#!/usr/bin/env bash
# monitor.sh -- Modular monitoring script for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"

# Source library modules  
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"

# ================================
# MONITORING MODULES
# ================================

# Service status monitoring
show_service_status() {
    echo -e "${BOLD}=== SERVICE STATUS ===${NC}"
    
    perform_health_check
    echo ""
}

# Resource monitoring
show_resource_usage() {
    echo -e "${BOLD}=== RESOURCE USAGE ===${NC}"
    
    if is_stack_running; then
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
    else
        log_warning "No containers running"
    fi
    
    echo ""
}

# Recent logs monitoring
show_recent_logs() {
    local lines="${1:-10}"
    
    echo -e "${BOLD}=== RECENT LOGS (last ${lines} lines) ===${NC}"
    
    for service in "${SERVICES[@]}"; do
        if is_service_running "$service"; then
            echo -e "${YELLOW}--- $service ---${NC}"
            get_service_logs "$service" "$lines"
            echo ""
        fi
    done
}

# Disk usage monitoring
show_disk_usage() {
    echo -e "${BOLD}=== DISK USAGE ===${NC}"
    
    # Overall disk usage
    df -h . 2>/dev/null || echo "Unable to check disk usage"
    
    # Data directory breakdown
    if [[ -d "./data" ]]; then
        echo -e "\n${BLUE}Data Directory Breakdown:${NC}"
        du -sh ./data/* 2>/dev/null | sort -hr || echo "Unable to check data directory"
    fi
    
    echo ""
}

# Network status monitoring  
show_network_status() {
    echo -e "${BOLD}=== NETWORK STATUS ===${NC}"
    
    # Docker networks
    echo -e "${BLUE}Docker Networks:${NC}"
    docker network ls --filter name=vaultwarden --
