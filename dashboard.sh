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

For performance analysis: ./perf-monitor.sh
For diagnostics: ./diagnose.sh
For alerts: ./alerts.sh

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
