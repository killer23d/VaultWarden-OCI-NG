#!/usr/bin/env bash
# dashboard.sh -- Comprehensive monitoring dashboard for VaultWarden-OCI

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

# System overview panel
show_system_overview() {
    echo -e "${BOLD}${CYAN}┌─ SYSTEM OVERVIEW ─────────────────────────────────────────────────────────┐${NC}"
    
    # Get system metrics
    local cpu_usage memory_usage disk_usage swap_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
    memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1 2>/dev/null || echo "0")
    swap_usage=$(free | grep Swap | awk '{if($2>0) printf("%.1f", $3/$2 * 100.0); else print "0"}' 2>/dev/null || echo "0")
    
    # Color code based on thresholds
    local cpu_color memory_color disk_color swap_color
    cpu_color=$(get_metric_color "$cpu_usage" "${CPU_ALERT_THRESHOLD:-80}")
    memory_color=$(get_metric_color "$memory_usage" "${MEMORY_ALERT_THRESHOLD:-85}")
    disk_color=$(get_metric_color "$disk_usage" "${DISK_ALERT_THRESHOLD:-85}")
    swap_color=$(get_metric_color "$swap_usage" "50")
    
    # Progress bars
    local cpu_bar memory_bar disk_bar swap_bar
    cpu_bar=$(create_progress_bar "$cpu_usage" 100 20)
    memory_bar=$(create_progress_bar "$memory_usage" 100 20)
    disk_bar=$(create_progress_bar "$disk_usage" 100 20)
    swap_bar=$(create_progress_bar "$swap_usage" 100 20)
    
    printf "│ %-15s ${cpu_color}%6.1f%%${NC} %s │\n" "CPU Usage:" "$cpu_usage" "$cpu_bar"
    printf "│ %-15s ${memory_color}%6.1f%%${NC} %s │\n" "Memory Usage:" "$memory_usage" "$memory_bar"
    printf "│ %-15s ${disk_color}%6.0f%%${NC} %s │\n" "Disk Usage:" "$disk_usage" "$disk_bar"
    printf "│ %-15s ${swap_color}%6.1f%%${NC} %s │\n" "Swap Usage:" "$swap_usage" "$swap_bar"
    
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Service status panel
show_services_panel() {
    echo -e "${BOLD}${CYAN}┌─ SERVICE STATUS ──────────────────────────────────────────────────────────┐${NC}"
    
    local service_count=0
    local healthy_count=0
    
    for service in "${SERVICES[@]}"; do
        local container_id status health display_name
        container_id=$(get_container_id "$service")
        
        # Format service name for display
        display_name=$(echo "$service" | sed 's/^bw_//' | tr '[:lower:]' '[:upper:]')
        display_name=$(printf "%-12s" "$display_name")
        
        if [[ -z "$container_id" ]]; then
            printf "│ %s ${RED}●${NC} %-10s ${YELLOW}NOT RUNNING${NC} %*s │\n" "$display_name" "" $((35)) ""
        else
            status=$(get_container_status "$container_id")
            health=$(get_container_health "$container_id")
            service_count=$((service_count + 1))
            
            case "$status" in
                "running")
                    case "$health" in
                        "healthy")
                            printf "│ %s ${GREEN}●${NC} %-10s ${GREEN}HEALTHY${NC} %*s │\n" "$display_name" "RUNNING" $((37)) ""
                            healthy_count=$((healthy_count + 1))
                            ;;
                        "unhealthy")
                            printf "│ %s ${RED}●${NC} %-10s ${RED}UNHEALTHY${NC} %*s │\n" "$display_name" "RUNNING" $((35)) ""
                            ;;
                        "starting")
                            printf "│ %s ${YELLOW}●${NC} %-10s ${YELLOW}STARTING${NC} %*s │\n" "$display_name" "RUNNING" $((36)) ""
                            ;;
                        *)
                            printf "│ %s ${BLUE}●${NC} %-10s ${BLUE}RUNNING${NC} %*s │\n" "$display_name" "RUNNING" $((37)) ""
                            healthy_count=$((healthy_count + 1))
                            ;;
                    esac
                    ;;
                "restarting")
                    printf "│ %s ${YELLOW}●${NC} %-10s ${YELLOW}RESTARTING${NC} %*s │\n" "$display_name" "" $((34)) ""
                    ;;
                *)
                    printf "│ %s ${RED}●${NC} %-10s ${RED}%s${NC} %*s │\n" "$display_name" "" "${status^^}" $((40 - ${#status})) ""
                    ;;
            esac
        fi
    done
    
    # Summary line
    local summary_color
    if [[ $healthy_count -eq $service_count ]] && [[ $service_count -gt 0 ]]; then
        summary_color="${GREEN}"
    elif [[ $healthy_count -gt 0 ]]; then
        summary_color="${YELLOW}"
    else
        summary_color="${RED}"
    fi
    
    echo -e "${BOLD}${CYAN}├───────────────────────────────────────────────────────────────────────────┤${NC}"
    printf "│ ${BOLD}Summary:${NC} ${summary_color}%d/%d services healthy${NC} %*s │\n" "$healthy_count" "$service_count" $((47 - ${#healthy_count} - ${#service_count})) ""
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Performance metrics panel
show_performance_panel() {
    echo -e "${BOLD}${CYAN}┌─ PERFORMANCE METRICS ─────────────────────────────────────────────────────┐${NC}"
    
    # Container resource usage
    if is_stack_running; then
        local stats_output
        stats_output=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" 2>/dev/null)
        
        if [[ -n "$stats_output" ]]; then
            # Parse and display container stats
            echo "$stats_output" | tail -n +2 | while IFS=$'\t' read -r name cpu mem_usage mem_perc; do
                local display_name cpu_num mem_perc_num
                display_name=$(echo "$name" | sed 's/^bw_//' | tr '[:lower:]' '[:upper:]')
                display_name=$(printf "%-12s" "$display_name")
                
                # Extract numeric values
                cpu_num=$(echo "$cpu" | sed 's/%//' | cut -d'.' -f1)
                mem_perc_num=$(echo "$mem_perc" | sed 's/%//' | cut -d'.' -f1)
                
                # Color code based on usage
                local cpu_color mem_color
                cpu_color=$(get_metric_color "$cpu_num" "50")
                mem_color=$(get_metric_color "$mem_perc_num" "80")
                
                printf "│ %s CPU: ${cpu_color}%8s${NC} RAM: ${mem_color}%8s (%s)${NC} │\n" \
                    "$display_name" "$cpu" "$mem_usage" "$mem_perc"
            done
        fi
    else
        printf "│ %-73s │\n" "No containers running - performance data unavailable"
    fi
    
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Database metrics panel
show_database_panel() {
    echo -e "${BOLD}${CYAN}┌─ DATABASE METRICS ────────────────────────────────────────────────────────┐${NC}"
    
    if is_service_running "bw_mariadb"; then
        local db_metrics
        db_metrics=$(monitor_database_performance "json" 2>/dev/null)
        
        if [[ -n "$db_metrics" ]]; then
            local connections threads_running slow_queries uptime
            connections=$(echo "$db_metrics" | jq -r '.connections // 0')
            threads_running=$(echo "$db_metrics" | jq -r '.threads_running // 0')
            slow_queries=$(echo "$db_metrics" | jq -r '.slow_queries // 0')
            uptime=$(echo "$db_metrics" | jq -r '.uptime_seconds // 0')
            
            # Format uptime
            local uptime_formatted
            uptime_formatted=$(format_duration "$uptime")
            
            # Color code connections based on max connections
            local conn_color
            local max_conn="${DATABASE_MAX_CONNECTIONS:-15}"
            local conn_percent=$((connections * 100 / max_conn))
            conn_color=$(get_metric_color "$conn_percent" "80")
            
            printf "│ %-20s ${conn_color}%6s${NC} / %-6s (${conn_color}%3d%%${NC}) %*s │\n" \
                "Active Connections:" "$connections" "$max_conn" "$conn_percent" $((26)) ""
            printf "│ %-20s %6s %*s │\n" "Running Threads:" "$threads_running" $((47)) ""
            printf "│ %-20s %6s %*s │\n" "Slow Queries:" "$slow_queries" $((47)) ""
            printf "│ %-20s %s %*s │\n" "Uptime:" "$uptime_formatted" $((55 - ${#uptime_formatted})) ""
        else
            printf "│ %-73s │\n" "Unable to retrieve database metrics"
        fi
    else
        printf "│ %-73s │\n" "MariaDB service is not running"
    fi
    
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Redis metrics panel
show_redis_panel() {
    echo -e "${BOLD}${CYAN}┌─ REDIS METRICS ───────────────────────────────────────────────────────────┐${NC}"
    
    if is_service_running "bw_redis"; then
        local redis_metrics
        redis_metrics=$(monitor_redis_performance "json" 2>/dev/null)
        
        if [[ -n "$redis_metrics" ]]; then
            local clients used_memory hits misses uptime
            clients=$(echo "$redis_metrics" | jq -r '.connected_clients // 0')
            used_memory=$(echo "$redis_metrics" | jq -r '.used_memory // "N/A"')
            hits=$(echo "$redis_metrics" | jq -r '.keyspace_hits // 0')
            misses=$(echo "$redis_metrics" | jq -r '.keyspace_misses // 0')
            uptime=$(echo "$redis_metrics" | jq -r '.uptime_seconds // 0')
            
            # Calculate hit ratio
            local hit_ratio="N/A"
            if [[ "$hits" != "0" || "$misses" != "0" ]]; then
                local total=$((hits + misses))
                if [[ $total -gt 0 ]]; then
                    hit_ratio=$(echo "scale=1; $hits * 100 / $total" | bc -l 2>/dev/null || echo "N/A")
                    hit_ratio="${hit_ratio}%"
                fi
            fi
            
            # Format uptime
            local uptime_formatted
            uptime_formatted=$(format_duration "$uptime")
            
            # Color code hit ratio
            local hit_ratio_color
            if [[ "$hit_ratio" != "N/A" ]]; then
                local hit_ratio_num
                hit_ratio_num=$(echo "$hit_ratio" | sed 's/%//')
                hit_ratio_color=$(get_metric_color "$hit_ratio_num" "70" "reverse")
            else
                hit_ratio_color="${NC}"
            fi
            
            printf "│ %-20s %6s %*s │\n" "Connected Clients:" "$clients" $((47)) ""
            printf "│ %-20s %10s %*s │\n" "Memory Used:" "$used_memory" $((43)) ""
            printf "│ %-20s ${hit_ratio_color}%10s${NC} %*s │\n" "Cache Hit Ratio:" "$hit_ratio" $((43)) ""
            printf "│ %-20s %s %*s │\n" "Uptime:" "$uptime_formatted" $((55 - ${#uptime_formatted})) ""
        else
            printf "│ %-73s │\n" "Unable to retrieve Redis metrics"
        fi
    else
        printf "│ %-73s │\n" "Redis service is not running"
    fi
    
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Alerts panel
show_alerts_panel() {
    echo -e "${BOLD}${CYAN}┌─ ALERTS & NOTIFICATIONS ──────────────────────────────────────────────────┐${NC}"
    
    local alerts=()
    local alert_count=0
    
    # Check performance thresholds
    local cpu_usage memory_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
    memory_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1 2>/dev/null || echo "0")
    
    # CPU alert
    if [[ -n "$cpu_usage" ]] && (( $(echo "$cpu_usage > ${CPU_ALERT_THRESHOLD:-80}" | bc -l 2>/dev/null || echo "0") )); then
        alerts+=("${RED}HIGH CPU${NC}: ${cpu_usage}% (threshold: ${CPU_ALERT_THRESHOLD:-80}%)")
        alert_count=$((alert_count + 1))
    fi
    
    # Memory alert
    if [[ -n "$memory_usage" ]] && (( memory_usage > ${MEMORY_ALERT_THRESHOLD:-85} )); then
        alerts+=("${RED}HIGH MEMORY${NC}: ${memory_usage}% (threshold: ${MEMORY_ALERT_THRESHOLD:-85}%)")
        alert_count=$((alert_count + 1))
    fi
    
    # Disk alert
    if [[ -n "$disk_usage" ]] && (( disk_usage > ${DISK_ALERT_THRESHOLD:-85} )); then
        alerts+=("${RED}HIGH DISK${NC}: ${disk_usage}% (threshold: ${DISK_ALERT_THRESHOLD:-85}%)")
        alert_count=$((alert_count + 1))
    fi
    
    # Service health alerts
    for service in "${SERVICES[@]}"; do
        local container_id health
        container_id=$(get_container_id "$service")
        
        if [[ -n "$container_id" ]]; then
            health=$(get_container_health "$container_id")
            if [[ "$health" == "unhealthy" ]]; then
                alerts+=("${YELLOW}UNHEALTHY SERVICE${NC}: $service")
                alert_count=$((alert_count + 1))
            fi
        fi
    done
    
    # Display alerts or all clear message
    if [[ ${#alerts[@]} -eq 0 ]]; then
        printf "│ ${GREEN}●${NC} %-69s │\n" "All systems operating normally"
    else
        for alert in "${alerts[@]}"; do
            printf "│ ${YELLOW}⚠${NC}  %-65s │\n" "$alert"
        done
    fi
    
    # Alert summary
    echo -e "${BOLD}${CYAN}├───────────────────────────────────────────────────────────────────────────┤${NC}"
    if [[ $alert_count -eq 0 ]]; then
        printf "│ ${BOLD}Status:${NC} ${GREEN}No active alerts${NC} %*s │\n" $((55)) ""
    else
        printf "│ ${BOLD}Status:${NC} ${RED}%d active alert(s)${NC} %*s │\n" "$alert_count" $((55 - ${#alert_count})) ""
    fi
    
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# Control panel
show_control_panel() {
    echo -e "${BOLD}${CYAN}┌─ QUICK ACTIONS ───────────────────────────────────────────────────────────┐${NC}"
    printf "│ ${BOLD}[r]${NC} Refresh   ${BOLD}[p]${NC} Perf Monitor   ${BOLD}[d]${NC} Diagnose   ${BOLD}[l]${NC} Logs   ${BOLD}[q]${NC} Quit %*s │\n" $((18)) ""
    echo -e "${BOLD}${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
}

# ================================
# UTILITY FUNCTIONS
# ================================

# Get color based on metric value and threshold
get_metric_color() {
    local value="$1"
    local threshold="$2"
    local reverse="${3:-false}"
    
    if [[ "$value" == "N/A" ]] || [[ "$value" == "0" ]]; then
        echo "${NC}"
        return
    fi
    
    local num_value
    num_value=$(echo "$value" | sed 's/[^0-9.]//g')
    
    if [[ -z "$num_value" ]]; then
        echo "${NC}"
        return
    fi
    
    if [[ "$reverse" == "true" ]]; then
        # For metrics where higher is better (like cache hit ratio)
        if (( $(echo "$num_value >= $threshold" | bc -l 2>/dev/null || echo "0") )); then
            echo "${GREEN}"
        elif (( $(echo "$num_value >= $threshold * 0.7" | bc -l 2>/dev/null || echo "0") )); then
            echo "${YELLOW}"
        else
            echo "${RED}"
        fi
    else
        # For metrics where lower is better (like CPU usage)
        if (( $(echo "$num_value >= $threshold" | bc -l 2>/dev/null || echo "0") )); then
            echo "${RED}"
        elif (( $(echo "$num_value >= $threshold * 0.8" | bc -l 2>/dev/null || echo "0") )); then
            echo "${YELLOW}"
        else
            echo "${GREEN}"
        fi
    fi
}

# Create progress bar
create_progress_bar() {
    local current="$1"
    local max="$2"
    local width="$3"
    
    local percentage
    percentage=$(echo "scale=0; $current * 100 / $max" | bc -l 2>/dev/null || echo "0")
    
    local filled
    filled=$(echo "scale=0; $percentage * $width / 100" | bc -l 2>/dev/null || echo "0")
    
    local bar=""
    for ((i=0; i<width; i++)); do
        if (( i < filled )); then
            bar+="█"
        else
            bar+="░"
        fi
    done
    
    echo "$bar"
}

# Format duration in seconds to human readable
format_duration() {
    local seconds="$1"
    
    if [[ "$seconds" -lt 60 ]]; then
        echo "${seconds}s"
    elif [[ "$seconds" -lt 3600 ]]; then
        echo "$((seconds / 60))m $((seconds % 60))s"
    elif [[ "$seconds" -lt 86400 ]]; then
        echo "$((seconds / 3600))h $((seconds % 3600 / 60))m"
    else
        echo "$((seconds / 86400))d $((seconds % 86400 / 3600))h"
    fi
}

# Store metrics history
store_metrics_history() {
    local timestamp metrics_json
    timestamp=$(date -Iseconds)
    
    # Get current metrics
    local cpu_usage memory_usage disk_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
    memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1 2>/dev/null || echo "0")
    
    metrics_json=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "cpu_usage": $cpu_usage,
    "memory_usage": $memory_usage,
    "disk_usage": $disk_usage,
    "services_running": $(docker compose ps --services --filter status=running | wc -l)
}
EOF
)
    
    # Initialize history file if it doesn't exist
    if [[ ! -f "$HISTORY_FILE" ]]; then
        echo "[]" > "$HISTORY_FILE"
    fi
    
    # Add new entry and keep only last MAX_HISTORY_ENTRIES
    jq --argjson entry "$metrics_json" '. += [$entry] | if length > '$MAX_HISTORY_ENTRIES' then .[-'$MAX_HISTORY_ENTRIES':] else . end' "$HISTORY_FILE" > "${HISTORY_FILE}.tmp" && mv "${HISTORY_FILE}.tmp" "$HISTORY_FILE"
}

# ================================
# INTERACTIVE FUNCTIONS
# ================================

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
            ./monitor.sh --logs --log-lines 20
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
            show_system_overview
            show_services_panel
            show_performance_panel
            show_database_panel
            show_redis_panel
            show_alerts_panel
            show_control_panel
            
            # Store metrics for history
            store_metrics_history
            
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

# Static dashboard (single refresh)
static_dashboard() {
    show_dashboard_header
    show_system_overview
    show_services_panel
    show_performance_panel
    show_database_panel
    show_redis_panel
    show_alerts_panel
    
    echo -e "${BOLD}${BLUE}Dashboard snapshot complete.${NC}"
    echo ""
    echo "For interactive mode: $0 --interactive"
    echo "For continuous monitoring: ./monitor.sh --live"
    echo "For performance analysis: ./perf-monitor.sh monitor"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local interactive_mode=false
    local export_mode=false
    local export_file=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interactive|-i)
                interactive_mode=true
                shift
                ;;
            --refresh)
                REFRESH_INTERVAL="$2"
                shift 2
                ;;
            --export)
                export_mode=true
                export_file="${2:-dashboard_export_$(date +%Y%m%d_%H%M%S).txt}"
                shift 2
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Dashboard

Usage: $0 [OPTIONS]

Options:
    --interactive, -i   Interactive dashboard mode
    --refresh N         Refresh interval in seconds (default: $REFRESH_INTERVAL)
    --export [file]     Export dashboard to file
    --help, -h          Show this help message

Interactive Mode Controls:
    [r] Refresh dashboard
    [p] Launch performance monitor
    [d] Run diagnostics
    [l] Show recent logs
    [q] Quit

Examples:
    $0                          # Static dashboard snapshot
    $0 --interactive            # Interactive dashboard
    $0 --interactive --refresh 5 # Interactive with 5s refresh
    $0 --export dashboard.txt   # Export to file

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Export mode
    if [[ "$export_mode" == "true" ]]; then
        {
            static_dashboard
        } > "$export_file"
        log_success "Dashboard exported to: $export_file"
        exit 0
    fi
    
    # Interactive or static mode
    if [[ "$interactive_mode" == "true" ]]; then
        log_info "Starting interactive dashboard (refresh every ${REFRESH_INTERVAL}s)"
        interactive_dashboard
    else
        static_dashboard
    fi
}

# Execute main function
main "$@"
