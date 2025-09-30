#!/usr/bin/env bash
# dashboard.sh -- Unified monitoring dashboard for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_dashboard_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/performance.sh"

# Dashboard configuration
REFRESH_INTERVAL="${DASHBOARD_REFRESH:-10}"
HISTORY_FILE="/tmp/vaultwarden_metrics_history.json"
MAX_HISTORY_ENTRIES=100

# ================================
# DASHBOARD COMPONENTS
# ================================

# Dashboard header
show_dashboard_header() {
    local current_time load_avg uptime_info
    current_time=$(date '+%Y-%m-%d %H:%M:%S %Z')
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    uptime_info=$(uptime -p 2>/dev/null || uptime | cut -d',' -f1)
    
    cat <<EOF
${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗
║                          VaultWarden-OCI Dashboard                          ║
╠══════════════════════════════════════════════════════════════════════════════╣${NC}
${BOLD}║${NC} ${YELLOW}Time:${NC} $current_time ${BOLD}║${NC}
${BOLD}║${NC} ${YELLOW}Host:${NC} $(hostname -f 2>/dev/null || hostname) ${BOLD}║${NC}
${BOLD}║${NC} ${YELLOW}Load:${NC} $load_avg ${BOLD}║${NC}
${BOLD}║${NC} ${YELLOW}Uptime:${NC} $uptime_info ${BOLD}║${NC}
${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}

EOF
}

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

# System information
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

# Interactive dashboard mode
interactive_dashboard() {
    # Set up terminal for non-blocking input
    if command -v stty >/dev/null 2>&1; then
        stty -echo -icanon time 0 min 0
        
        # Cleanup function
        cleanup_terminal() {
            stty echo icanon
            clear
            exit 0
        }
        trap cleanup_terminal EXIT INT TERM
    fi
    
    local last_refresh=0
    
    while true; do
        local current_time
        current_time=$(date +%s)
        
        # Refresh dashboard at intervals
        if (( current_time - last_refresh >= REFRESH_INTERVAL )); then
            clear
            show_dashboard_header
            show_service_status
            show_resource_usage
            show_disk_usage
            
            # Control panel
            echo -e "${BOLD}${CYAN}┌─ QUICK ACTIONS ───────────────────────────────────────────────────────────┐${NC}"
            printf "│ ${BOLD}[r]${NC} Refresh   ${BOLD}[p]${NC} Perf Monitor   ${BOLD}[d]${NC} Diagnose   ${BOLD}[l]${NC} Logs   ${BOLD}[q]${NC} Quit %*s │\n" $((18)) ""
            echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
            
            last_refresh=$current_time
        fi
        
        # Check for user input
        if command -v stty >/dev/null 2>&1; then
            local key
            IFS= read -r -n1 key 2>/dev/null
            if [[ -n "$key" ]]; then
                handle_input "$key"
            fi
        fi
        
        sleep 1
    done
}

# Handle user input
handle_input() {
    local key="$1"
    
    case "$key" in
        "r"|"R")
            # Refresh - just return to main loop
            return 0
            ;;
        "p"|"P")
            clear
            echo "Launching Performance Monitor..."
            ./perf-monitor.sh status
            echo ""
            read -p "Press Enter to return to dashboard..."
            ;;
        "d"|"D")
            clear
            echo "Running Diagnostics..."
            ./diagnose.sh --system --docker --performance
            echo ""
            read -p "Press Enter to return to dashboard..."
            ;;
        "l"|"L")
            clear
            echo "Recent Logs:"
            echo "============"
            show_recent_logs 20
            echo ""
            read -p "Press Enter to return to dashboard..."
            ;;
        "q"|"Q")
            clear
            echo "Goodbye!"
            exit 0
            ;;
        *)
            # Unknown key - ignore
            return 0
            ;;
    esac
}

# Static dashboard (single refresh)
static_dashboard() {
    show_dashboard_header
    show_system_info
    show_service_status
    show_resource_usage
    show_disk_usage
    
    echo -e "${BOLD}${BLUE}Dashboard snapshot complete.${NC}"
    echo ""
    echo "For interactive mode: $0 --interactive"
    echo "For continuous monitoring: $0 live"
    echo "For performance analysis: ./perf-monitor.sh monitor"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local mode="${1:-dashboard}"
    
    case "$mode" in
        "dashboard"|"interactive")
            # Full interactive dashboard
            interactive_dashboard
            ;;
        "status"|"simple")
            # Simple monitoring (old monitor.sh functionality)
            echo -e "${BOLD}${BLUE}VaultWarden-OCI Status${NC}"
            echo "Generated at: $(date)"
            echo "=========================="
            echo ""
            
            show_service_status
            show_resource_usage
            show_disk_usage
            
            if [[ "${2:-}" == "--logs" ]]; then
                show_recent_logs "${3:-10}"
            fi
            ;;
        "live")
            # Live monitoring mode
            live_monitor "${2:-5}"
            ;;
        "export")
            # Export dashboard
            local export_file="${2:-dashboard_export_$(date +%Y%m%d_%H%M%S).txt}"
            {
                static_dashboard
            } > "$export_file"
            log_success "Dashboard exported to: $export_file"
            ;;
        "help"|"-h"|"--help")
            cat <<EOF
VaultWarden-OCI Unified Dashboard

Usage: $0 [mode] [options]

Modes:
    dashboard, interactive  Full interactive dashboard (default)
    status, simple         Simple status view (equivalent to old monitor.sh)
    live [interval]        Live monitoring mode
    export [file]          Export dashboard to file
    help                   Show this help message

Options for 'status' mode:
    --logs [lines]         Include recent logs (default: 10 lines)

Examples:
    $0                          # Interactive dashboard
    $0 status                   # Simple status view
    $0 status --logs 20         # Status with 20 lines of logs
    $0 live 3                   # Live mode with 3s refresh
    $0 export report.txt        # Export to file

Interactive Controls:
    [r] - Refresh display
    [p] - Launch performance monitor
    [d] - Run diagnostics
    [l] - Show recent logs
    [q] - Quit

Related Tools:
    Performance monitoring:     ./perf-monitor.sh
    System diagnostics:         ./diagnose.sh
    Alert management:           ./alerts.sh

EOF
            exit 0
            ;;
        *)
            log_error "Unknown mode: $mode"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
