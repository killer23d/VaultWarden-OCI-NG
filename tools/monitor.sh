#!/usr/bin/env bash
# tools/monitor.sh — Automated system monitor with self-healing capabilities.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source the consolidated monitoring library
source "$ROOT_DIR/lib/monitoring.sh"

_set_log_prefix "monitor"

# Configuration
MONITOR_STATE_DIR="$PROJECT_STATE_DIR/monitoring"
MONITOR_LOCK_FILE="$MONITOR_STATE_DIR/monitor.lock"
MONITOR_LOG_FILE="$PROJECT_STATE_DIR/logs/monitoring.log"

# Initialize monitoring system
init_monitoring() {
    # Create monitoring directories
    mkdir -p "$MONITOR_STATE_DIR"
    
    _log_debug "Monitoring initialized"
}

# Check if another monitor instance is running
check_monitor_lock() {
    if [[ -f "$MONITOR_LOCK_FILE" ]]; then
        local lock_pid
        lock_pid=$(cat "$MONITOR_LOCK_FILE" 2>/dev/null || echo "")
        
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            _log_debug "Another monitor instance is running (PID: $lock_pid)"
            return 1
        else
            _log_debug "Stale lock file detected, removing"
            rm -f "$MONITOR_LOCK_FILE"
        fi
    fi
    
    echo $$ > "$MONITOR_LOCK_FILE"
    return 0
}

# Clean up lock file on exit
cleanup_monitor_lock() {
    rm -f "$MONITOR_LOCK_FILE"
}
trap cleanup_monitor_lock EXIT

# Log monitoring results
log_monitoring_results() {
    local total_warnings="$1"
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    # Create log entry
    local log_entry
    log_entry=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "monitoring_run": true,
  "total_warnings": $total_warnings,
  "sops_integration": $([[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]] && echo "true" || echo "false"),
  "secrets_loaded": $([[ "$SECRETS_LOADED" == "true" ]] && echo "true" || echo "false"),
  "configuration_source": "${CONFIG_SOURCE:-unknown}",
  "project_name": "${PROJECT_NAME:-unknown}"
}
EOF
)
    
    # Append to monitoring log
    echo "$log_entry" >> "$MONITOR_LOG_FILE"
    
    # Rotate log if it gets too large (keep last 1000 lines)
    if [[ $(wc -l < "$MONITOR_LOG_FILE" 2>/dev/null) -gt 1000 ]]; then
        tail -1000 "$MONITOR_LOG_FILE" > "$MONITOR_LOG_FILE.tmp" && mv "$MONITOR_LOG_FILE.tmp" "$MONITOR_LOG_FILE"
    fi
}

# Main monitoring function
run_monitoring() {
    local start_time end_time duration
    start_time=$(date +%s)
    
    _log_header "VaultWarden Automated System Monitor"
    
    # Run all health checks from the library
    check_sops_system_health
    check_container_health  
    check_system_health
    check_network_health
    check_backup_health
    check_service_integration

    local health_result=$?
    
    # Self-heal if needed and enabled
    if [[ $CRITICAL_COUNT -gt 0 ]] && [[ "${AUTO_HEAL:-true}" == "true" ]]; then
        _log_warning "Health check failed - attempting self-heal..."
        if self_heal_once; then
            _log_success "Self-heal completed successfully"

            # Re-run health checks after healing
            WARNINGS_COUNT=0
            CRITICAL_COUNT=0
            check_sops_system_health
            check_container_health
            health_result=$?
        else
            _log_error "Self-heal failed - manual intervention required"
            alert_on_sops_failures "Self-Heal Failed" "Automated healing could not restore system health"
        fi
    fi

    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    _log_header "Monitoring Summary"
    if [[ $CRITICAL_COUNT -eq 0 ]] && [[ $WARNINGS_COUNT -eq 0 ]]; then
        _log_success "🎉 All monitoring checks passed! System is healthy."
    else
        _log_warning "⚠️  Monitoring completed with $WARNINGS_COUNT warning(s) and $CRITICAL_COUNT failure(s)."
    fi

    _log_info "Monitoring duration: ${duration}s"
    
    # Log results
    log_monitoring_results "$WARNINGS_COUNT"
    
    return $(( CRITICAL_COUNT > 0 ? 2 : (WARNINGS_COUNT > 0 ? 1 : 0) ))
}

# Argument handling
main() {
    if ! check_monitor_lock; then
        exit 0  # Another instance is running
    fi
            
    init_monitoring
    run_monitoring
}

main "$@"