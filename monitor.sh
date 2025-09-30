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
    docker network ls --filter name=vaultwarden --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    
    # Internal connectivity
    test_internal_connectivity
    
    echo ""
}

# Show system information
show_system_info() {
    echo -e "${BOLD}=== SYSTEM INFORMATION ===${NC}"
    
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
    
    # Memory summary
    echo -e "\n${BLUE}Memory Summary:${NC}"
    free -h | grep -E '^Mem:|^Swap:'
    
    echo ""
}

# Live monitoring mode
live_monitor() {
    local refresh_interval="${1:-5}"
    
    log_info "Starting live monitor (refresh every ${refresh_interval}s, press Ctrl+C to exit)"
    
    while true; do
        clear
        echo -e "${BOLD}${BLUE}VaultWarden-OCI Live Monitor${NC} - $(date)"
        echo "Refresh interval: ${refresh_interval}s | Press Ctrl+C to exit"
        echo "=================================================================="
        
        show_service_status
        show_resource_usage
        
        sleep "$refresh_interval"
    done
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local show_logs=false
    local log_lines=10
    local live_mode=false
    local refresh_interval=5
    local selected_modules=()
    local run_all=true
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --logs)
                show_logs=true
                shift
                ;;
            --log-lines)
                log_lines="$2"
                shift 2
                ;;
            --live)
                live_mode=true
                shift
                ;;
            --refresh)
                refresh_interval="$2"
                shift 2
                ;;
            --status)
                selected_modules+=("status")
                run_all=false
                shift
                ;;
            --resources)
                selected_modules+=("resources")
                run_all=false
                shift
                ;;
            --disk)
                selected_modules+=("disk")
                run_all=false
                shift
                ;;
            --network)
                selected_modules+=("network")
                run_all=false
                shift
                ;;
            --system)
                selected_modules+=("system")
                run_all=false
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Monitor Script

Usage: $0 [OPTIONS]

Options:
    --logs              Show recent logs
    --log-lines N       Number of log lines to show (default: 10)
    --live              Live monitoring mode
    --refresh N         Refresh interval for live mode (default: 5s)
    --status            Show only service status
    --resources         Show only resource usage
    --disk              Show only disk usage
    --network           Show only network status
    --system            Show only system information
    --help, -h          Show this help message

Examples:
    $0                          # Show all monitoring info
    $0 --logs --log-lines 20    # Show status with 20 lines of logs
    $0 --live --refresh 3       # Live monitoring with 3s refresh
    $0 --status --resources     # Show only status and resources

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Live monitoring mode
    if [[ "$live_mode" == "true" ]]; then
        live_monitor "$refresh_interval"
        exit 0
    fi
    
    # Static monitoring
    echo -e "${BOLD}${BLUE}VaultWarden-OCI Monitor${NC}"
    echo "Generated at: $(date)"
    echo "=============================================="
    echo ""
    
    # Run selected modules or all
    if [[ "$run_all" == "true" ]]; then
        selected_modules=("system" "status" "resources" "disk" "network")
        if [[ "$show_logs" == "true" ]]; then
            selected_modules+=("logs")
        fi
    else
        if [[ "$show_logs" == "true" ]]; then
            selected_modules+=("logs")
        fi
    fi
    
    for module in "${selected_modules[@]}"; do
        case "$module" in
            "system") show_system_info ;;
            "status") show_service_status ;;
            "resources") show_resource_usage ;;
            "disk") show_disk_usage ;;
            "network") show_network_status ;;
            "logs") show_recent_logs "$log_lines" ;;
            *) log_warning "Unknown monitoring module: $module" ;;
        esac
    done
    
    echo "=============================================="
    log_info "Monitor complete!"
    log_info "Run '$0 --live' for continuous monitoring"
    log_info "Run './diagnose.sh' for troubleshooting"
}

# Execute main function
main "$@"
