#!/usr/bin/env bash
# check-disk-space.sh -- Disk space monitoring with email alerts

# Source library modules if available, otherwise use basic functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
    source "$SCRIPT_DIR/lib/common.sh"
else
    # Basic fallback functions if lib is not available
    log_info() { echo "[INFO] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_error() { echo "[ERROR] $1" >&2; exit 1; }
    log_success() { echo "[SUCCESS] $1"; }
fi

# Configuration
THRESHOLD="${DISK_ALERT_THRESHOLD:-85}"  # Percentage threshold
ALERT_EMAIL="${ALERT_EMAIL:-admin@example.com}"
DATA_DIR="${DATA_DIR:-./data}"

# Check if data directory exists
if [[ ! -d "$DATA_DIR" ]]; then
    log_error "Data directory not found: $DATA_DIR"
fi

# Get current disk usage
get_disk_usage() {
    local usage_line
    usage_line=$(df "$DATA_DIR" | tail -1)
    
    # Extract usage percentage (remove % sign)
    echo "$usage_line" | awk '{print $5}' | sed 's/%//'
}

# Get disk usage details
get_disk_details() {
    local usage_line
    usage_line=$(df -h "$DATA_DIR" | tail -1)
    
    echo "Disk Usage Details:"
    echo "==================="
    echo "Filesystem: $(echo "$usage_line" | awk '{print $1}')"
    echo "Size:       $(echo "$usage_line" | awk '{print $2}')"
    echo "Used:       $(echo "$usage_line" | awk '{print $3}')"
    echo "Available:  $(echo "$usage_line" | awk '{print $4}')"
    echo "Usage:      $(echo "$usage_line" | awk '{print $5}')"
    echo "Mount:      $(echo "$usage_line" | awk '{print $6}')"
    echo ""
}

# Get largest directories in data
get_largest_directories() {
    echo "Largest directories in $DATA_DIR:"
    echo "=================================="
    
    if [[ -d "$DATA_DIR" ]]; then
        # Use du to find largest subdirectories, sort by size
        du -h "$DATA_DIR"/* 2>/dev/null | sort -hr | head -10
    else
        echo "Data directory not accessible"
    fi
    echo ""
}

# Send email alert
send_alert_email() {
    local usage="$1"
    local subject="⚠️ VaultWarden-OCI Disk Space Alert - ${usage}% Used"
    
    local body="VaultWarden-OCI disk space usage has exceeded the threshold.

Current Usage: ${usage}%
Threshold: ${THRESHOLD}%
Server: $(hostname)
Timestamp: $(date)

$(get_disk_details)

$(get_largest_directories)

Recommended Actions:
- Check backup logs and clean old backups
- Review application logs and rotate if needed
- Consider increasing disk space or adjusting retention policies
- Run './perf-monitor.sh logs clean' to cleanup old logs

For detailed analysis, run: ./perf-monitor.sh logs status"

    # Try to send email using different methods
    if command -v msmtp >/dev/null 2>&1; then
        {
            echo "From: VaultWarden-OCI <system@$(hostname)>"
            echo "To: $ALERT_EMAIL"
            echo "Subject: $subject"
            echo "Content-Type: text/plain; charset=UTF-8"
            echo ""
            echo "$body"
        } | msmtp -t 2>/dev/null && log_success "Alert email sent via msmtp"
    elif command -v sendmail >/dev/null 2>&1; then
        {
            echo "From: VaultWarden-OCI <system@$(hostname)>"
            echo "To: $ALERT_EMAIL"
            echo "Subject: $subject"
            echo ""
            echo "$body"
        } | sendmail "$ALERT_EMAIL" 2>/dev/null && log_success "Alert email sent via sendmail"
    elif command -v mail >/dev/null 2>&1; then
        echo "$body" | mail -s "$subject" "$ALERT_EMAIL" 2>/dev/null && log_success "Alert email sent via mail"
    else
        log_warning "No email client found - alert not sent"
        log_warning "Install msmtp, sendmail, or mailutils to enable email alerts"
        
        # Log the alert to syslog as fallback
        logger -t vaultwarden-disk-alert "Disk usage ${usage}% exceeds threshold ${THRESHOLD}%"
        log_info "Alert logged to syslog"
    fi
}

# Main execution
main() {
    local usage
    usage=$(get_disk_usage)
    
    if [[ -z "$usage" ]] || ! [[ "$usage" =~ ^[0-9]+$ ]]; then
        log_error "Unable to determine disk usage"
    fi
    
    log_info "Current disk usage: ${usage}%"
    log_info "Alert threshold: ${THRESHOLD}%"
    
    if [[ "$usage" -ge "$THRESHOLD" ]]; then
        log_warning "Disk usage ${usage}% exceeds threshold ${THRESHOLD}%"
        
        get_disk_details
        get_largest_directories
        
        # Send alert email
        send_alert_email "$usage"
        
        # Suggest cleanup actions
        echo "Cleanup suggestions:"
        echo "==================="
        echo "1. Run log cleanup:     ./perf-monitor.sh logs clean"
        echo "2. Check backup retention: review BACKUP_RETENTION_DAYS setting"
        echo "3. Clean old Docker images: docker image prune -a"
        echo "4. Check for core dumps: find /tmp -name 'core.*' -mtime +7 -delete"
        
        exit 1
    else
        log_success "Disk usage ${usage}% is within acceptable limits"
        exit 0
    fi
}

# Execute main function
main "$@"
