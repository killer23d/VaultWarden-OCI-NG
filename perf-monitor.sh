#!/usr/bin/env bash
# perf-monitor.sh -- Performance monitoring and optimization for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_performance_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/performance.sh"

# ================================
# PERFORMANCE COMMANDS
# ================================

# Show current performance status
cmd_status() {
    echo -e "${BOLD}${BLUE}VaultWarden-OCI Performance Status${NC}"
    echo "Generated at: $(date)"
    echo "==============================================="
    echo ""
    
    get_system_metrics
    echo ""
    
    echo -e "${BOLD}Container Performance:${NC}"
    get_container_metrics
    echo ""
    
    echo -e "${BOLD}Service Health:${NC}"
    perform_health_check
}

# Monitor performance in real-time
cmd_monitor() {
    local interval="${1:-5}"
    
    log_info "Starting performance monitor (refresh every ${interval}s, press Ctrl+C to exit)"
    
    while true; do
        clear
        echo -e "${BOLD}${BLUE}VaultWarden-OCI Performance Monitor${NC} - $(date)"
        echo "Refresh interval: ${interval}s | Press Ctrl+C to exit"
        echo "=================================================================="
        
        get_system_metrics
        echo ""
        
        echo -e "${BOLD}Container Stats:${NC}"
        get_container_metrics
        
        sleep "$interval"
    done
}

# Check performance thresholds
cmd_check() {
    echo -e "${BOLD}${BLUE}Performance Threshold Check${NC}"
    echo "==========================================="
    
    if check_performance_thresholds; then
        log_success "All performance metrics are within acceptable ranges"
        exit 0
    else
        log_warning "Some performance metrics exceed thresholds"
        exit 1
    fi
}

# Optimize system and Docker performance
cmd_optimize() {
    echo -e "${BOLD}${BLUE}Performance Optimization${NC}"
    echo "=================================="
    
    optimize_system_performance
    optimize_docker_performance
    
    log_success "Performance optimization completed"
}

# Show detailed database performance
cmd_database() {
    echo -e "${BOLD}${BLUE}Database Performance Details${NC}"
    echo "===================================="
    
    monitor_database_performance
    
    # Additional database checks
    if is_service_running "bw_mariadb"; then
        echo ""
        echo -e "${BOLD}Database Configuration:${NC}"
        local db_id
        db_id=$(get_container_id "bw_mariadb")
        
        echo "Max Connections: $(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW VARIABLES LIKE 'max_connections';" -s -N 2>/dev/null | cut -f2)"
        echo "InnoDB Buffer Pool Size: $(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW VARIABLES LIKE 'innodb_buffer_pool_size';" -s -N 2>/dev/null | cut -f2)"
        echo "Query Cache Type: $(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW VARIABLES LIKE 'query_cache_type';" -s -N 2>/dev/null | cut -f2)"
    fi
}

# Show detailed Redis performance
cmd_redis() {
    echo -e "${BOLD}${BLUE}Redis Performance Details${NC}"
    echo "=============================="
    
    monitor_redis_performance
    
    # Additional Redis info
    if is_service_running "bw_redis"; then
        echo ""
        echo -e "${BOLD}Redis Configuration:${NC}"
        local redis_id
        redis_id=$(get_container_id "bw_redis")
        
        local maxmemory maxclients
        maxmemory=$(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" CONFIG GET maxmemory 2>/dev/null | tail -1)
        maxclients=$(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" CONFIG GET maxclients 2>/dev/null | tail -1)
        
        echo "Max Memory: ${maxmemory:-unlimited}"
        echo "Max Clients: ${maxclients:-N/A}"
    fi
}

# Manage log rotation
cmd_logs() {
    local action="${1:-status}"
    
    case "$action" in
        "status"|"size")
            echo -e "${BOLD}${BLUE}Log Status${NC}"
            echo "=============="
            get_log_sizes
            ;;
        "rotate")
            echo -e "${BOLD}${BLUE}Log Rotation${NC}"
            echo "=============="
            rotate_application_logs
            ;;
        "clean")
            echo -e "${BOLD}${BLUE}Log Cleanup${NC}"
            echo "============="
            
            # Clean old logs
            local cleaned=0
            
            # Clean backup logs older than 30 days
            if [[ -d "./data/backup_logs" ]]; then
                local count
                count=$(find ./data/backup_logs -name "*.log" -mtime +30 2>/dev/null | wc -l)
                if [[ "$count" -gt 0 ]]; then
                    find ./data/backup_logs -name "*.log" -mtime +30 -delete 2>/dev/null
                    log_success "Cleaned $count old backup logs"
                    cleaned=$((cleaned + count))
                fi
            fi
            
            # Clean large Docker logs
            local container_logs_dir="/var/lib/docker/containers"
            if [[ -d "$container_logs_dir" && -w "$container_logs_dir" ]]; then
                local large_logs
                large_logs=$(find "$container_logs_dir" -name "*.log" -size +100M 2>/dev/null | wc -l)
                if [[ "$large_logs" -gt 0 ]]; then
                    find "$container_logs_dir" -name "*.log" -size +100M -exec truncate -s 50M {} \; 2>/dev/null
                    log_success "Truncated $large_logs large Docker logs"
                    cleaned=$((cleaned + large_logs))
                fi
            fi
            
            if [[ "$cleaned" -eq 0 ]]; then
                log_info "No logs needed cleaning"
            fi
            ;;
        *)
            log_error "Unknown log action: $action. Use: status, rotate, clean"
            ;;
    esac
}

# Generate comprehensive performance report
cmd_report() {
    local output_file="${1:-}"
    local report_file
    
    if [[ -n "$output_file" ]]; then
        report_file="$output_file"
    else
        report_file="performance_report_$(date +%Y%m%d_%H%M%S).txt"
    fi
    
    report_file=$(generate_performance_report "$report_file")
    
    echo -e "${BOLD}${BLUE}Performance Report Generated${NC}"
    echo "============================="
    echo "Report saved to: $report_file"
    echo ""
    echo "Report contents:"
    echo "---------------"
    head -20 "$report_file"
    echo "..."
    echo ""
    log_info "Full report available at: $report_file"
}

# ================================
# MAIN EXECUTION
# ================================

show_help() {
    cat <<EOF
VaultWarden-OCI Performance Management

Usage: $0 <command> [options]

Commands:
    status              Show current performance status
    monitor [interval]  Real-time performance monitoring (default: 5s)
    check              Check performance against thresholds
    optimize           Optimize system and Docker performance
    database           Show detailed database performance
    redis              Show detailed Redis performance
    logs <action>      Manage logs (status|rotate|clean)
    report [file]      Generate performance report
    help               Show this help message

Examples:
    $0 status                    # Show current status
    $0 monitor 3                 # Monitor with 3s refresh
    $0 check                     # Check thresholds
    $0 optimize                  # Apply optimizations
    $0 logs rotate               # Rotate application logs
    $0 report my_report.txt      # Generate custom report

Environment Variables:
    CPU_ALERT_THRESHOLD         CPU usage alert threshold (default: 80%)
    MEMORY_ALERT_THRESHOLD      Memory usage alert threshold (default: 85%)
    DISK_ALERT_THRESHOLD        Disk usage alert threshold (default: 85%)
    LOAD_ALERT_THRESHOLD        Load average alert threshold (default: 2.0)
    DEBUG                       Enable debug logging

EOF
}

main() {
    local command="${1:-status}"
    
    case "$command" in
        "status")
            cmd_status
            ;;
        "monitor")
            cmd_monitor "${2:-5}"
            ;;
        "check")
            cmd_check
            ;;
        "optimize")
            cmd_optimize
            ;;
        "database")
            cmd_database
            ;;
        "redis")
            cmd_redis
            ;;
        "logs")
            cmd_logs "${2:-status}"
            ;;
        "report")
            cmd_report "${2:-}"
            ;;
        "help"|"-h"|"--help")
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
