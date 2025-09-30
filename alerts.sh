#!/usr/bin/env bash
# alerts.sh -- Alert management and notification system for VaultWarden-OCI

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_alerts_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/performance.sh"

# Alert configuration
ALERT_STATE_FILE="/tmp/vaultwarden_alert_state.json"
ALERT_HISTORY_FILE="/tmp/vaultwarden_alert_history.json"
ALERT_COOLDOWN_MINUTES="${ALERT_COOLDOWN_MINUTES:-30}"
MAX_ALERT_HISTORY=1000

# Alert levels
readonly ALERT_CRITICAL="CRITICAL"
readonly ALERT_WARNING="WARNING"
readonly ALERT_INFO="INFO"

# ================================
# ALERT DEFINITIONS
# ================================

# Define alert rules
declare -A ALERT_RULES=(
    ["cpu_high"]="CPU usage > ${CPU_ALERT_THRESHOLD:-80}%"
    ["memory_high"]="Memory usage > ${MEMORY_ALERT_THRESHOLD:-85}%"
    ["disk_high"]="Disk usage > ${DISK_ALERT_THRESHOLD:-85}%"
    ["load_high"]="Load average > ${LOAD_ALERT_THRESHOLD:-2.0}"
    ["service_unhealthy"]="Service health check failed"
    ["service_down"]="Service is not running"
    ["database_connections_high"]="Database connections > 80% of max"
    ["redis_memory_high"]="Redis memory usage > 80% of limit"
    ["backup_failed"]="Backup process failed"
    ["cert_expiry"]="SSL certificate expires within 30 days"
)

# ================================
# ALERT FUNCTIONS
# ================================

# Initialize alert system
init_alert_system() {
    log_debug "Initializing alert system..."
    
    # Create alert state file if it doesn't exist
    if [[ ! -f "$ALERT_STATE_FILE" ]]; then
        echo "{}" > "$ALERT_STATE_FILE"
    fi
    
    # Create alert history file if it doesn't exist
    if [[ ! -f "$ALERT_HISTORY_FILE" ]]; then
        echo "[]" > "$ALERT_HISTORY_FILE"
    fi
    
    log_debug "Alert system initialized"
}

# Check if alert is in cooldown period
is_alert_in_cooldown() {
    local alert_id="$1"
    local current_time
    current_time=$(date +%s)
    
    if [[ ! -f "$ALERT_STATE_FILE" ]]; then
        return 1  # Not in cooldown
    fi
    
    local last_sent
    last_sent=$(jq -r --arg id "$alert_id" '.[$id].last_sent // 0' "$ALERT_STATE_FILE" 2>/dev/null || echo "0")
    
    if [[ "$last_sent" == "null" ]] || [[ "$last_sent" == "0" ]]; then
        return 1  # Not in cooldown
    fi
    
    local cooldown_seconds=$((ALERT_COOLDOWN_MINUTES * 60))
    local time_since_last=$((current_time - last_sent))
    
    if [[ $time_since_last -lt $cooldown_seconds ]]; then
        return 0  # In cooldown
    else
        return 1  # Not in cooldown
    fi
}

# Update alert state
update_alert_state() {
    local alert_id="$1"
    local level="$2"
    local message="$3"
    local current_time
    current_time=$(date +%s)
    
    local new_state
    new_state=$(jq --arg id "$alert_id" \
                   --arg level "$level" \
                   --arg message "$message" \
                   --argjson time "$current_time" \
                   '.[$id] = {
                       "level": $level,
                       "message": $message,
                       "last_sent": $time,
                       "count": ((.[$id].count // 0) + 1)
                   }' "$ALERT_STATE_FILE")
    
    echo "$new_state" > "$ALERT_STATE_FILE"
}

# Add alert to history
add_alert_to_history() {
    local alert_id="$1"
    local level="$2"
    local message="$3"
    local timestamp
    timestamp=$(date -Iseconds)
    
    local alert_entry
    alert_entry=$(jq -n --arg id "$alert_id" \
                       --arg level "$level" \
                       --arg message "$message" \
                       --arg timestamp "$timestamp" \
                       '{
                           id: $id,
                           level: $level,
                           message: $message,
                           timestamp: $timestamp
                       }')
    
    local updated_history
    updated_history=$(jq --argjson entry "$alert_entry" \
                        '. += [$entry] | if length > '$MAX_ALERT_HISTORY' then .[-'$MAX_ALERT_HISTORY':] else . end' \
                        "$ALERT_HISTORY_FILE")
    
    echo "$updated_history" > "$ALERT_HISTORY_FILE"
}

# Send alert notification
send_alert_notification() {
    local alert_id="$1"
    local level="$2"
    local message="$3"
    local details="${4:-}"
    
    log_info "Sending $level alert: $alert_id - $message"
    
    # Prepare notification content
    local subject="[$level] VaultWarden-OCI Alert: $message"
    local body="VaultWarden-OCI Alert Notification

Alert ID: $alert_id
Level: $level
Message: $message
Server: $(hostname)
Timestamp: $(date)

$details

---
Alert Rules:
$(printf '%s\n' "${ALERT_RULES[@]}" | sed 's/^/  /')

To manage alerts: ./alerts.sh
To check system status: ./dashboard.sh
To run diagnostics: ./diagnose.sh"

    # Send notification via different channels
    send_email_notification "$subject" "$body"
    send_webhook_notification "$alert_id" "$level" "$message" "$details"
    send_syslog_notification "$alert_id" "$level" "$message"
    
    # Update alert state and history
    update_alert_state "$alert_id" "$level" "$message"
    add_alert_to_history "$alert_id" "$level" "$message"
}

# Send email notification
send_email_notification() {
    local subject="$1"
    local body="$2"
    local recipient="${ALERT_EMAIL:-${ADMIN_EMAIL:-admin@example.com}}"
    
    # Try different email methods
    if command -v msmtp >/dev/null 2>&1; then
        {
            echo "From: VaultWarden-OCI <system@$(hostname)>"
            echo "To: $recipient"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo "$body"
        } | msmtp -t 2>/dev/null && log_debug "Alert email sent via msmtp"
    elif command -v sendmail >/dev/null 2>&1; then
        {
            echo "From: VaultWarden-OCI <system@$(hostname)>"
            echo "To: $recipient"
            echo "Subject: $subject"
            echo ""
            echo "$body"
        } | sendmail "$recipient" 2>/dev/null && log_debug "Alert email sent via sendmail"
    elif command -v mail >/dev/null 2>&1; then
        echo "$body" | mail -s "$subject" "$recipient" 2>/dev/null && log_debug "Alert email sent via mail"
    else
        log_debug "No email client available for notifications"
    fi
}

# Send webhook notification
send_webhook_notification() {
    local alert_id="$1"
    local level="$2"
    local message="$3"
    local details="$4"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local payload
        payload=$(jq -n --arg id "$alert_id" \
                       --arg level "$level" \
                       --arg message "$message" \
                       --arg details "$details" \
                       --arg hostname "$(hostname)" \
                       --arg timestamp "$(date -Iseconds)" \
                       '{
                           alert_id: $id,
                           level: $level,
                           message: $message,
                           details: $details,
                           hostname: $hostname,
                           timestamp: $timestamp,
                           source: "VaultWarden-OCI"
                       }')
        
        curl -X POST \
             -H "Content-Type: application/json" \
             -d "$payload" \
             "${WEBHOOK_URL}" \
             --max-time 10 \
             --silent \
             >/dev/null 2>&1 && log_debug "Alert webhook sent"
    fi
}

# Send syslog notification
send_syslog_notification() {
    local alert_id="$1"
    local level="$2"
    local message="$3"
    
    local syslog_priority
    case "$level" in
        "$ALERT_CRITICAL") syslog_priority="crit" ;;
        "$ALERT_WARNING") syslog_priority="warning" ;;
        *) syslog_priority="info" ;;
    esac
    
    logger -t vaultwarden-alert -p "user.$syslog_priority" "[$level] $alert_id: $message"
    log_debug "Alert logged to syslog"
}

# ================================
# CHECK FUNCTIONS
# ================================

# Check system metrics
check_system_metrics() {
    local alerts_triggered=()
    
    # CPU usage check
    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")
    
    if [[ -n "$cpu_usage" ]] && (( $(echo "$cpu_usage > ${CPU_ALERT_THRESHOLD:-80}" | bc -l 2>/dev/null || echo "0") )); then
        if ! is_alert_in_cooldown "cpu_high"; then
            send_alert_notification "cpu_high" "$ALERT_WARNING" "High CPU usage: ${cpu_usage}%" \
                "Current CPU usage is ${cpu_usage}%, which exceeds the threshold of ${CPU_ALERT_THRESHOLD:-80}%."
            alerts_triggered+=("cpu_high")
        fi
    fi
    
    # Memory usage check
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}' 2>/dev/null || echo "0")
    
    if [[ -n "$memory_usage" ]] && (( memory_usage > ${MEMORY_ALERT_THRESHOLD:-85} )); then
        if ! is_alert_in_cooldown "memory_high"; then
            send_alert_notification "memory_high" "$ALERT_WARNING" "High memory usage: ${memory_usage}%" \
                "Current memory usage is ${memory_usage}%, which exceeds the threshold of ${MEMORY_ALERT_THRESHOLD:-85}%."
            alerts_triggered+=("memory_high")
        fi
    fi
    
    # Disk usage check
    local disk_usage
    disk_usage=$(df . | tail -1 | awk '{print $5}' | cut -d'%' -f1 2>/dev/null || echo "0")
    
    if [[ -n "$disk_usage" ]] && (( disk_usage > ${DISK_ALERT_THRESHOLD:-85} )); then
        if ! is_alert_in_cooldown "disk_high"; then
            send_alert_notification "disk_high" "$ALERT_CRITICAL" "High disk usage: ${disk_usage}%" \
                "Current disk usage is ${disk_usage}%, which exceeds the threshold of ${DISK_ALERT_THRESHOLD:-85}%.
                
$(df -h . | tail -1)

Largest directories:
$(du -h ./data/* 2>/dev/null | sort -hr | head -5)"
            alerts_triggered+=("disk_high")
        fi
    fi
    
    # Load average check
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | xargs)
    
    if [[ -n "$load_avg" ]] && (( $(echo "$load_avg > ${LOAD_ALERT_THRESHOLD:-2.0}" | bc -l 2>/dev/null || echo "0") )); then
        if ! is_alert_in_cooldown "load_high"; then
            send_alert_notification "load_high" "$ALERT_WARNING" "High load average: $load_avg" \
                "Current load average is $load_avg, which exceeds the threshold of ${LOAD_ALERT_THRESHOLD:-2.0}."
            alerts_triggered+=("load_high")
        fi
    fi
    
    echo "${alerts_triggered[@]}"
}

# Check service health
check_service_health() {
    local alerts_triggered=()
    
    for service in "${SERVICES[@]}"; do
        local container_id status health
        container_id=$(get_container_id "$service")
        
        if [[ -z "$container_id" ]]; then
            # Service is not running
            if ! is_alert_in_cooldown "service_down_$service"; then
                send_alert_notification "service_down_$service" "$ALERT_CRITICAL" "Service $service is not running" \
                    "The $service container is not running. This may indicate a startup failure or manual shutdown."
                alerts_triggered+=("service_down_$service")
            fi
        else
            status=$(get_container_status "$container_id")
            health=$(get_container_health "$container_id")
            
            if [[ "$health" == "unhealthy" ]]; then
                if ! is_alert_in_cooldown "service_unhealthy_$service"; then
                    local health_log
                    health_log=$(docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' "$container_id" 2>/dev/null | tail -3)
                    
                    send_alert_notification "service_unhealthy_$service" "$ALERT_WARNING" "Service $service is unhealthy" \
                        "The $service container is running but failing health checks.

Recent health check output:
$health_log"
                    alerts_triggered+=("service_unhealthy_$service")
                fi
            fi
        fi
    done
    
    echo "${alerts_triggered[@]}"
}

# Check database metrics
check_database_metrics() {
    local alerts_triggered=()
    
    if is_service_running "bw_mariadb"; then
        local db_metrics
        db_metrics=$(monitor_database_performance "json" 2>/dev/null)
        
        if [[ -n "$db_metrics" ]]; then
            local connections max_connections
            connections=$(echo "$db_metrics" | jq -r '.connections // 0')
            max_connections="${DATABASE_MAX_CONNECTIONS:-15}"
            
            # Check connection usage
            local conn_percentage
            conn_percentage=$(echo "scale=0; $connections * 100 / $max_connections" | bc -l 2>/dev/null || echo "0")
            
            if (( conn_percentage > 80 )); then
                if ! is_alert_in_cooldown "database_connections_high"; then
                    send_alert_notification "database_connections_high" "$ALERT_WARNING" \
                        "High database connection usage: $connections/$max_connections (${conn_percentage}%)" \
                        "Database connection usage is at ${conn_percentage}%, which may indicate connection leaks or high load."
                    alerts_triggered+=("database_connections_high")
                fi
            fi
        fi
    fi
    
    echo "${alerts_triggered[@]}"
}

# Check backup status
check_backup_status() {
    local alerts_triggered=()
    
    # Check for recent backup failures
    if [[ -d "./data/backup_logs" ]]; then
        local recent_failures
        recent_failures=$(find ./data/backup_logs -name "*.log" -mtime -1 -exec grep -l "ERROR\|FAILED" {} \; 2>/dev/null)
        
        if [[ -n "$recent_failures" ]]; then
            if ! is_alert_in_cooldown "backup_failed"; then
                local failure_details
                failure_details=$(echo "$recent_failures" | head -3 | xargs tail -10 2>/dev/null)
                
                send_alert_notification "backup_failed" "$ALERT_CRITICAL" "Recent backup failures detected" \
                    "Backup failures have been detected in the last 24 hours.

Failed backup logs:
$recent_failures

Recent error details:
$failure_details"
                alerts_triggered+=("backup_failed")
            fi
        fi
    fi
    
    echo "${alerts_triggered[@]}"
}

# ================================
# MANAGEMENT FUNCTIONS
# ================================

# Run all alert checks
run_alert_checks() {
    log_info "Running alert checks..."
    
    local all_alerts=()
    local system_alerts service_alerts db_alerts backup_alerts
    
    # Run all checks
    system_alerts=($(check_system_metrics))
    service_alerts=($(check_service_health))
    db_alerts=($(check_database_metrics))
    backup_alerts=($(check_backup_status))
    
    # Combine all alerts
    all_alerts=("${system_alerts[@]}" "${service_alerts[@]}" "${db_alerts[@]}" "${backup_alerts[@]}")
    
    if [[ ${#all_alerts[@]} -eq 0 ]]; then
        log_success "No alerts triggered"
    else
        log_warning "${#all_alerts[@]} alert(s) triggered: ${all_alerts[*]}"
    fi
    
    return ${#all_alerts[@]}
}

# Show alert status
show_alert_status() {
    echo -e "${BOLD}${BLUE}Alert System Status${NC}"
    echo "===================="
    
    # Show current alert state
    if [[ -f "$ALERT_STATE_FILE" ]]; then
        local active_alerts
        active_alerts=$(jq 'length' "$ALERT_STATE_FILE" 2>/dev/null || echo "0")
        
        echo "Active alert states: $active_alerts"
        echo ""
        
        if [[ "$active_alerts" != "0" ]]; then
            echo -e "${BOLD}Current Alert States:${NC}"
            jq -r 'to_entries[] | "  \(.key): \(.value.level) - \(.value.message) (count: \(.value.count))"' "$ALERT_STATE_FILE" 2>/dev/null
            echo ""
        fi
    fi
    
    # Show recent alert history
    if [[ -f "$ALERT_HISTORY_FILE" ]]; then
        local history_count
        history_count=$(jq 'length' "$ALERT_HISTORY_FILE" 2>/dev/null || echo "0")
        
        echo "Alert history entries: $history_count"
        echo ""
        
        if [[ "$history_count" != "0" ]]; then
            echo -e "${BOLD}Recent Alerts (last 10):${NC}"
            jq -r '.[-10:] | reverse[] | "\(.timestamp) [\(.level)] \(.id): \(.message)"' "$ALERT_HISTORY_FILE" 2>/dev/null
        fi
    fi
}

# Clear alert states
clear_alert_states() {
    log_info "Clearing alert states..."
    echo "{}" > "$ALERT_STATE_FILE"
    log_success "Alert states cleared"
}

# Test alert system
test_alert_system() {
    log_info "Testing alert system..."
    
    send_alert_notification "test_alert" "$ALERT_INFO" "Alert system test" \
        "This is a test notification to verify the alert system is working correctly."
    
    log_success "Test alert sent"
}

# ================================
# MAIN EXECUTION
# ================================

main() {
    local command="${1:-check}"
    
    # Initialize alert system
    init_alert_system
    
    case "$command" in
        "check")
            run_alert_checks
            exit $?
            ;;
        "status")
            show_alert_status
            ;;
        "clear")
            clear_alert_states
            ;;
        "test")
            test_alert_system
            ;;
        "daemon")
            local interval="${2:-300}"  # 5 minutes default
            log_info "Starting alert daemon (check every ${interval}s)"
            
            while true; do
                run_alert_checks >/dev/null 2>&1
                sleep "$interval"
            done
            ;;
        "help"|"-h"|"--help")
            cat <<EOF
VaultWarden-OCI Alert Management

Usage: $0 <command> [options]

Commands:
    check               Run alert checks once
    status              Show alert system status
    clear               Clear all alert states
    test                Send test alert
    daemon [interval]   Run as daemon (default: 300s)
    help                Show this help message

Configuration:
    ALERT_EMAIL                 Email for alert notifications
    WEBHOOK_URL                 Webhook URL for notifications
    CPU_ALERT_THRESHOLD         CPU usage threshold (default: 80%)
    MEMORY_ALERT_THRESHOLD      Memory usage threshold (default: 85%)
    DISK_ALERT_THRESHOLD        Disk usage threshold (default: 85%)
    LOAD_ALERT_THRESHOLD        Load average threshold (default: 2.0)
    ALERT_COOLDOWN_MINUTES      Minutes between duplicate alerts (default: 30)

Examples:
    $0 check                    # Run alert checks
    $0 status                   # Show current status
    $0 daemon 600               # Run as daemon, check every 10 minutes
    $0 test                     # Send test notification

EOF
            exit 0
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
