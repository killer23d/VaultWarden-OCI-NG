#!/usr/bin/env bash
# lib/performance.sh - Performance monitoring and optimization functions

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/common.sh"

# ================================
# PERFORMANCE MONITORING
# ================================

# Get system performance metrics
get_system_metrics() {
    local output_format="${1:-human}" # human, json, csv
    
    local cpu_usage memory_usage disk_usage load_avg
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    memory_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
    
    case "$output_format" in
        "json")
            cat <<EOF
{
    "cpu_usage_percent": ${cpu_usage:-0},
    "memory_usage_percent": ${memory_usage:-0},
    "disk_usage_percent": ${disk_usage:-0},
    "load_average_1min": ${load_avg:-0},
    "timestamp": "$(date -Iseconds)"
}
EOF
            ;;
        "csv")
            echo "timestamp,cpu_percent,memory_percent,disk_percent,load_1min"
            echo "$(date -Iseconds),${cpu_usage:-0},${memory_usage:-0},${disk_usage:-0},${load_avg:-0}"
            ;;
        *)
            cat <<EOF
System Performance Metrics ($(date))
=====================================
CPU Usage:     ${cpu_usage:-N/A}%
Memory Usage:  ${memory_usage:-N/A}%
Disk Usage:    ${disk_usage:-N/A}%
Load Average:  ${load_avg:-N/A}
EOF
            ;;
    esac
}

# Get container performance metrics
get_container_metrics() {
    local service="${1:-}"
    local output_format="${2:-human}"
    
    if [[ -z "$service" ]]; then
        # Get all containers
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
        return 0
    fi
    
    local container_id
    container_id=$(get_container_id "$service")
    
    if [[ -z "$container_id" ]]; then
        log_error "Service $service not found or not running"
        return 1
    fi
    
    local stats_json
    stats_json=$(docker stats --no-stream --format "{{json .}}" "$container_id")
    
    case "$output_format" in
        "json")
            echo "$stats_json"
            ;;
        "csv")
            echo "service,cpu_percent,memory_usage,memory_percent,network_io,block_io"
            echo "$stats_json" | jq -r '[.Name, .CPUPerc, .MemUsage, .MemPerc, .NetIO, .BlockIO] | @csv'
            ;;
        *)
            echo "$stats_json" | jq -r '"Service: " + .Name + "\nCPU: " + .CPUPerc + "\nMemory: " + .MemUsage + " (" + .MemPerc + ")\nNetwork I/O: " + .NetIO + "\nBlock I/O: " + .BlockIO'
            ;;
    esac
}

# Monitor database performance
monitor_database_performance() {
    local output_format="${1:-human}"
    
    if ! is_service_running "bw_mariadb"; then
        log_warning "MariaDB service is not running"
        return 1
    fi
    
    local db_id
    db_id=$(get_container_id "bw_mariadb")
    
    # Get database metrics
    local connections threads_running slow_queries uptime
    connections=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';" -s -N 2>/dev/null | cut -f2)
    threads_running=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Threads_running';" -s -N 2>/dev/null | cut -f2)
    slow_queries=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';" -s -N 2>/dev/null | cut -f2)
    uptime=$(docker exec "$db_id" mysql -uroot -p"${MARIADB_ROOT_PASSWORD}" -e "SHOW GLOBAL STATUS LIKE 'Uptime';" -s -N 2>/dev/null | cut -f2)
    
    case "$output_format" in
        "json")
            cat <<EOF
{
    "connections": ${connections:-0},
    "threads_running": ${threads_running:-0},
    "slow_queries": ${slow_queries:-0},
    "uptime_seconds": ${uptime:-0},
    "timestamp": "$(date -Iseconds)"
}
EOF
            ;;
        *)
            cat <<EOF
Database Performance Metrics
============================
Active Connections: ${connections:-N/A}
Running Threads:    ${threads_running:-N/A}
Slow Queries:       ${slow_queries:-N/A}
Uptime:             ${uptime:-N/A} seconds
EOF
            ;;
    esac
}

# Monitor Redis performance
monitor_redis_performance() {
    local output_format="${1:-human}"
    
    if ! is_service_running "bw_redis"; then
        log_warning "Redis service is not running"
        return 1
    fi
    
    local redis_id
    redis_id=$(get_container_id "bw_redis")
    
    # Get Redis info
    local info_output
    info_output=$(docker exec "$redis_id" redis-cli -a "${REDIS_PASSWORD}" INFO 2>/dev/null)
    
    local connected_clients used_memory keyspace_hits keyspace_misses uptime
    connected_clients=$(echo "$info_output" | grep "^connected_clients:" | cut -d: -f2 | tr -d '\r')
    used_memory=$(echo "$info_output" | grep "^used_memory_human:" | cut -d: -f2 | tr -d '\r')
    keyspace_hits=$(echo "$info_output" | grep "^keyspace_hits:" | cut -d: -f2 | tr -d '\r')
    keyspace_misses=$(echo "$info_output" | grep "^keyspace_misses:" | cut -d: -f2 | tr -d '\r')
    uptime=$(echo "$info_output" | grep "^uptime_in_seconds:" | cut -d: -f2 | tr -d '\r')
    
    case "$output_format" in
        "json")
            cat <<EOF
{
    "connected_clients": ${connected_clients:-0},
    "used_memory": "${used_memory:-N/A}",
    "keyspace_hits": ${keyspace_hits:-0},
    "keyspace_misses": ${keyspace_misses:-0},
    "uptime_seconds": ${uptime:-0},
    "timestamp": "$(date -Iseconds)"
}
EOF
            ;;
        *)
            local hit_ratio="N/A"
            if [[ -n "$keyspace_hits" && -n "$keyspace_misses" && "$keyspace_hits" != "0" ]]; then
                hit_ratio=$(echo "scale=2; $keyspace_hits / ($keyspace_hits + $keyspace_misses) * 100" | bc -l 2>/dev/null || echo "N/A")
                hit_ratio="${hit_ratio}%"
            fi
            
            cat <<EOF
Redis Performance Metrics
=========================
Connected Clients: ${connected_clients:-N/A}
Memory Used:       ${used_memory:-N/A}
Keyspace Hits:     ${keyspace_hits:-N/A}
Keyspace Misses:   ${keyspace_misses:-N/A}
Hit Ratio:         ${hit_ratio}
Uptime:            ${uptime:-N/A} seconds
EOF
            ;;
    esac
}

# ================================
# PERFORMANCE OPTIMIZATION
# ================================

# Optimize system performance
optimize_system_performance() {
    log_info "Applying system performance optimizations..."
    
    # Check if running as root or with sudo
    if ! is_root && ! sudo -n true 2>/dev/null; then
        log_warning "Root privileges required for system optimizations"
        return 1
    fi
    
    local prefix=""
    if ! is_root; then
        prefix="sudo"
    fi
    
    # Optimize swappiness for database workloads
    local current_swappiness
    current_swappiness=$(cat /proc/sys/vm/swappiness)
    
    if [[ "$current_swappiness" -gt 10 ]]; then
        log_info "Setting swappiness to 10 (current: $current_swappiness)"
        $prefix sysctl vm.swappiness=10
        echo "vm.swappiness=10" | $prefix tee -a /etc/sysctl.conf >/dev/null
    fi
    
    # Optimize dirty ratio for better I/O performance
    $prefix sysctl vm.dirty_ratio=15
    $prefix sysctl vm.dirty_background_ratio=5
    
    # Network optimizations
    $prefix sysctl net.core.somaxconn=1024
    $prefix sysctl net.ipv4.tcp_max_syn_backlog=1024
    
    log_success "System optimizations applied"
}

# Optimize Docker performance
optimize_docker_performance() {
    log_info "Checking Docker performance settings..."
    
    # Check Docker daemon configuration
    local docker_info
    docker_info=$(docker info --format "{{json .}}" 2>/dev/null)
    
    local storage_driver logging_driver
    storage_driver=$(echo "$docker_info" | jq -r '.Driver // "unknown"')
    logging_driver=$(echo "$docker_info" | jq -r '.LoggingDriver // "unknown"')
    
    log_info "Docker storage driver: $storage_driver"
    log_info "Docker logging driver: $logging_driver"
    
    # Recommendations
    if [[ "$storage_driver" != "overlay2" ]]; then
        log_warning "Consider using overlay2 storage driver for better performance"
    fi
    
    if [[ "$logging_driver" == "json-file" ]]; then
        log_info "JSON file logging is configured - ensure log rotation is enabled"
    fi
    
    # Check for resource constraints
    local total_memory
    total_memory=$(free -m | awk '/^Mem:/{print $2}')
    
    if [[ "$total_memory" -lt 6144 ]]; then
        log_warning "System has less than 6GB RAM - performance may be constrained"
    fi
}

# ================================
# PERFORMANCE ALERTS
# ================================

# Check performance thresholds and alert if exceeded
check_performance_thresholds() {
    local cpu_threshold="${CPU_ALERT_THRESHOLD:-80}"
    local memory_threshold="${MEMORY_ALERT_THRESHOLD:-85}"
    local disk_threshold="${DISK_ALERT_THRESHOLD:-85}"
    local load_threshold="${LOAD_ALERT_THRESHOLD:-2.0}"
    
    local alerts=()
    
    # Get current metrics
    local cpu_usage memory_usage disk_usage load_avg
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    memory_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1)
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
    
    # Check thresholds
    if [[ -n "$cpu_usage" ]] && (( $(echo "$cpu_usage > $cpu_threshold" | bc -l) )); then
        alerts+=("CPU usage ${cpu_usage}% exceeds threshold ${cpu_threshold}%")
    fi
    
    if [[ -n "$memory_usage" ]] && (( memory_usage > memory_threshold )); then
        alerts+=("Memory usage ${memory_usage}% exceeds threshold ${memory_threshold}%")
    fi
    
    if [[ -n "$disk_usage" ]] && (( disk_usage > disk_threshold )); then
        alerts+=("Disk usage ${disk_usage}% exceeds threshold ${disk_threshold}%")
    fi
    
    if [[ -n "$load_avg" ]] && (( $(echo "$load_avg > $load_threshold" | bc -l) )); then
        alerts+=("Load average $load_avg exceeds threshold $load_threshold")
    fi
    
    # Return alerts
    if [[ ${#alerts[@]} -gt 0 ]]; then
        for alert in "${alerts[@]}"; do
            log_warning "PERFORMANCE ALERT: $alert"
        done
        return 1
    else
        log_success "All performance metrics within thresholds"
        return 0
    fi
}

# ================================
# LOG MANAGEMENT
# ================================

# Rotate application logs
rotate_application_logs() {
    log_info "Rotating application logs..."
    
    # Rotate Caddy logs
    if is_service_running "bw_caddy"; then
        docker kill --signal=USR1 bw_caddy 2>/dev/null && log_success "Caddy logs rotated"
    fi
    
    # Clean old backup logs (older than 30 days)
    if [[ -d "./data/backup_logs" ]]; then
        find ./data/backup_logs -name "*.log" -mtime +30 -delete 2>/dev/null
        log_success "Old backup logs cleaned"
    fi
    
    # Clean Docker logs if they exceed size limits
    local container_logs_dir="/var/lib/docker/containers"
    if [[ -d "$container_logs_dir" ]]; then
        find "$container_logs_dir" -name "*.log" -size +100M -exec truncate -s 50M {} \; 2>/dev/null
        log_success "Large Docker logs truncated"
    fi
}

# Get log sizes
get_log_sizes() {
    echo "Application Log Sizes:"
    echo "====================="
    
    [[ -d "./data/caddy_logs" ]] && echo "Caddy logs: $(du -sh ./data/caddy_logs 2>/dev/null | cut -f1)"
    [[ -d "./data/backup_logs" ]] && echo "Backup logs: $(du -sh ./data/backup_logs 2>/dev/null | cut -f1)"
    [[ -d "./data/fail2ban" ]] && echo "Fail2ban logs: $(du -sh ./data/fail2ban 2>/dev/null | cut -f1)"
    
    # Docker container logs
    local total_docker_logs=0
    for service in "${SERVICES[@]}"; do
        local container_id
        container_id=$(get_container_id "$service")
        if [[ -n "$container_id" ]]; then
            local log_file="/var/lib/docker/containers/$container_id/$container_id-json.log"
            if [[ -f "$log_file" ]]; then
                local size
                size=$(du -m "$log_file" 2>/dev/null | cut -f1)
                echo "Docker logs ($service): ${size}MB"
                total_docker_logs=$((total_docker_logs + size))
            fi
        fi
    done
    
    echo "Total Docker logs: ${total_docker_logs}MB"
}

# ================================
# PERFORMANCE REPORTS
# ================================

# Generate performance report
generate_performance_report() {
    local output_file="${1:-performance_report_$(date +%Y%m%d_%H%M%S).txt}"
    
    log_info "Generating performance report: $output_file"
    
    {
        echo "VaultWarden-OCI Performance Report"
        echo "Generated: $(date)"
        echo "======================================="
        echo ""
        
        get_system_metrics
        echo ""
        
        echo "Container Performance:"
        echo "====================="
        get_container_metrics
        echo ""
        
        echo "Database Performance:"
        echo "===================="
        monitor_database_performance
        echo ""
        
        echo "Redis Performance:"
        echo "=================="
        monitor_redis_performance
        echo ""
        
        echo "Log Sizes:"
        echo "=========="
        get_log_sizes
        echo ""
        
        echo "Service Health:"
        echo "==============="
        perform_health_check
        
    } > "$output_file"
    
    log_success "Performance report saved to: $output_file"
    echo "$output_file"
}
