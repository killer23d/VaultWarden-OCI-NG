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

    echo -e "\n${BLUE}Network Connectivity:${NC}"
    test_internal_connectivity

    # Port status
    echo -e "\n${BLUE}Port Status:${NC}"
    if command -v ss >/dev/null 2>&1; then
        echo "Listening ports (80, 443, 3306, 6379):"
        ss -tulpn | grep -E ":80\s|:443\s|:3306\s|:6379\s" | head -10 2>/dev/null || echo "No relevant ports found"
    elif command -v netstat >/dev/null 2>&1; then
        echo "Listening ports (80, 443, 3306, 6379):"
        netstat -tulpn | grep -E ":80\s|:443\s|:3306\s|:6379\s" | head -10 2>/dev/null || echo "No relevant ports found"
    else
        echo "Port checking tools not available (install ss or netstat)"
    fi

    echo ""
}

# Performance monitoring
show_performance() {
    echo -e "${BOLD}=== PERFORMANCE METRICS ===${NC}"

    # System load
    echo -e "${BLUE}System Load:${NC}"
    uptime

    # Memory usage
    echo -e "\n${BLUE}Memory Usage:${NC}"
    free -h

    # CPU info
    echo -e "\n${BLUE}CPU Usage:${NC}"
    if command -v top >/dev/null 2>&1; then
        top -bn1 | grep "Cpu(s)" | head -1
    else
        echo "CPU usage info not available"
    fi

    # Docker system usage
    echo -e "\n${BLUE}Docker System Usage:${NC}"
    docker system df 2>/dev/null || echo "Docker system info not available"

    echo ""
}

# Security monitoring
show_security_status() {
    echo -e "${BOLD}=== SECURITY STATUS ===${NC}"

    # Fail2ban status
    if is_service_running "bw_fail2ban"; then
        echo -e "${BLUE}Fail2ban Status:${NC}"
        local f2b_id
        f2b_id=$(get_container_id "bw_fail2ban")

        if [[ -n "$f2b_id" ]]; then
            echo "Active jails:"
            docker exec "$f2b_id" fail2ban-client status 2>/dev/null || echo "Unable to get fail2ban status"

            echo -e "\nBanned IPs:"
            docker exec "$f2b_id" fail2ban-client status vaultwarden 2>/dev/null | grep "Banned IP list" || echo "No banned IPs"
        fi
    else
        echo -e "${YELLOW}Fail2ban not running${NC}"
    fi

    # SSL certificate status
    echo -e "\n${BLUE}SSL Certificate:${NC}"
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        source "$SETTINGS_FILE" 2>/dev/null || true
        set +a

        if [[ -n "${APP_DOMAIN:-}" ]] && command -v openssl >/dev/null 2>&1; then
            local cert_info
            cert_info=$(echo | openssl s_client -servername "${APP_DOMAIN}" -connect "${APP_DOMAIN}":443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)

            if [[ -n "$cert_info" ]]; then
                echo "Certificate found:"
                echo "$cert_info"
            else
                echo "No SSL certificate found or unable to retrieve"
            fi
        else
            echo "Domain not configured or openssl not available"
        fi
    else
        echo "Settings file not found"
    fi

    echo ""
}

# Backup monitoring
show_backup_status() {
    echo -e "${BOLD}=== BACKUP STATUS ===${NC}"

    if is_service_running "bw_backup"; then
        echo -e "${GREEN}Backup service is running${NC}"

        # Check recent backups
        if [[ -d "./data/backups" ]]; then
            local backup_count recent_backup
            backup_count=$(find ./data/backups -name "db_backup_*.sql*" 2>/dev/null | wc -l)
            recent_backup=$(find ./data/backups -name "db_backup_*.sql*" -mtime -1 2>/dev/null | head -1)

            echo "Total backups: $backup_count"

            if [[ -n "$recent_backup" ]]; then
                local backup_size backup_age
                backup_size=$(du -h "$recent_backup" 2>/dev/null | cut -f1)
                backup_age=$(stat -c %Y "$recent_backup" 2>/dev/null)
                backup_age=$(( ($(date +%s) - backup_age) / 3600 ))

                echo -e "${GREEN}Recent backup: $(basename "$recent_backup") (${backup_size}, ${backup_age}h ago)${NC}"
            else
                echo -e "${YELLOW}No recent backup found (last 24 hours)${NC}"
            fi
        else
            echo -e "${YELLOW}Backup directory not found${NC}"
        fi
    else
        echo -e "${YELLOW}Backup service not running${NC}"
    fi

    echo ""
}

# Combined dashboard view
show_dashboard() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                     VaultWarden-OCI Monitoring Dashboard                    ║"
    echo "║                          $(date '+%Y-%m-%d %H:%M:%S %Z')                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    show_service_status
    show_resource_usage
    show_security_status
    show_backup_status

    echo -e "${BOLD}${BLUE}Press Ctrl+C to exit, or wait 30 seconds for refresh...${NC}"
}

# ================================
# INTERACTIVE FUNCTIONS
# ================================

# Watch mode - refresh dashboard every 30 seconds
watch_dashboard() {
    while true; do
        show_dashboard
        sleep 30
    done
}

# Interactive menu
show_interactive_menu() {
    while true; do
        clear
        echo -e "${BOLD}${BLUE}VaultWarden-OCI Monitor - Interactive Menu${NC}"
        echo ""
        echo "1) Full Dashboard"
        echo "2) Service Status"
        echo "3) Resource Usage"
        echo "4) Recent Logs"
        echo "5) Disk Usage"
        echo "6) Network Status"
        echo "7) Performance Metrics"
        echo "8) Security Status"
        echo "9) Backup Status"
        echo "w) Watch Mode (auto-refresh)"
        echo "q) Quit"
        echo ""
        read -p "Select option: " choice

        case $choice in
            1) show_dashboard; read -p "Press Enter to continue..." ;;
            2) show_service_status; read -p "Press Enter to continue..." ;;
            3) show_resource_usage; read -p "Press Enter to continue..." ;;
            4) 
                echo "Enter number of log lines (default 20):"
                read -p "Lines: " lines
                show_recent_logs "${lines:-20}"
                read -p "Press Enter to continue..."
                ;;
            5) show_disk_usage; read -p "Press Enter to continue..." ;;
            6) show_network_status; read -p "Press Enter to continue..." ;;
            7) show_performance; read -p "Press Enter to continue..." ;;
            8) show_security_status; read -p "Press Enter to continue..." ;;
            9) show_backup_status; read -p "Press Enter to continue..." ;;
            w|W) watch_dashboard ;;
            q|Q) exit 0 ;;
            *) echo "Invalid option. Press Enter to continue..."; read ;;
        esac
    done
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local command="${1:-dashboard}"

    case "$command" in
        dashboard|status)
            show_dashboard
            ;;
        watch)
            watch_dashboard
            ;;
        interactive|menu)
            show_interactive_menu
            ;;
        services)
            show_service_status
            ;;
        resources)
            show_resource_usage
            ;;
        logs)
            local lines="${2:-20}"
            show_recent_logs "$lines"
            ;;
        disk)
            show_disk_usage
            ;;
        network)
            show_network_status
            ;;
        performance|perf)
            show_performance
            ;;
        security)
            show_security_status
            ;;
        backup)
            show_backup_status
            ;;
        --help|-h)
            cat <<EOF
VaultWarden-OCI Monitoring Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    dashboard          Show full dashboard (default)
    watch              Watch mode - auto-refresh every 30s
    interactive        Interactive menu mode
    services           Show service status only
    resources          Show resource usage only
    logs [lines]       Show recent logs (default: 20 lines)
    disk               Show disk usage only
    network            Show network status only
    performance        Show performance metrics only
    security           Show security status only
    backup             Show backup status only

Examples:
    $0                 # Show dashboard once
    $0 watch           # Auto-refresh dashboard
    $0 interactive     # Interactive menu
    $0 logs 50         # Show last 50 log lines
    $0 services        # Quick service check

EOF
            exit 0
            ;;
        *)
            log_error "Unknown command: $command. Use --help for usage information."
            ;;
    esac
}

# Handle interrupts gracefully
trap 'echo -e "\n${YELLOW}Monitoring stopped${NC}"; exit 0' INT TERM

# Execute main function
main "$@"
