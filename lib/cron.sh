#!/usr/bin/env bash
# lib/cron.sh - Cron job management library with enhanced automation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/system.sh"

_set_log_prefix "cron"

# Add a cron job for a specific user (idempotent)
add_cron_job() {
    local user="$1"
    local schedule="$2"
    local command="$3"
    local description="${4:-$command}"
    
    # Create a unique identifier for this job
    local job_id="# VaultWarden: $description"
    
    # Check if job already exists
    if crontab -u "$user" -l 2>/dev/null | grep -Fq "$job_id"; then
        _log_info "Cron job already exists for user $user: $description"
        return 0
    fi
    
    # Add the job
    (
        crontab -u "$user" -l 2>/dev/null || true
        echo "$job_id"
        echo "$schedule $command"
        echo ""
    ) | crontab -u "$user" -
    
    _log_success "Added cron job for $user: $description"
}

# Setup all VaultWarden maintenance cron jobs
setup_cron_jobs() {
    local auto_mode="${1:-false}"
    local cron_user="root"
    
    _log_section "Setting Up Automated Maintenance Jobs"
    
    if [[ "$auto_mode" != "true" ]]; then
        _log_info "The following automated maintenance jobs will be scheduled:"
        _log_info "  • Daily database backups (1 AM)"
        _log_info "  • Weekly full system backups (Sunday midnight)"  
        _log_info "  • Daily Cloudflare IP updates (3 AM)"
        _log_confirm "Enable automated maintenance jobs?" "Y"
        read -r response
        response=${response:-Y}
        
        if [[ ! "$response" =~ ^[yY][eE][sS]?$ ]]; then
            _log_info "Skipping cron job setup. You can run this later with setup_cron_jobs."
            return 0
        fi
    fi
    
    # Daily database backup at 1 AM
    add_cron_job "$cron_user" \
        "0 1 * * *" \
        "cd $ROOT_DIR && ./tools/backup-monitor.sh db 2>&1 | logger -t backup-monitor" \
        "Daily database backup"
    
    # Weekly full backup on Sundays at midnight
    add_cron_job "$cron_user" \
        "0 0 * * 0" \
        "cd $ROOT_DIR && ./tools/backup-monitor.sh full 2>&1 | logger -t backup-monitor" \
        "Weekly full system backup"
    
    # Daily Cloudflare IP updates at 3 AM
    add_cron_job "$cron_user" \
        "0 3 * * *" \
        "cd $ROOT_DIR && ./tools/update-firewall-rules.sh --quiet 2>&1 | logger -t firewall-rules" \
        "Daily Cloudflare IP update"
    
    # Ensure cron service is running
    if ! _get_service_status cron | grep -q "active"; then
        _log_info "Starting cron service..."
        _start_service cron
        _enable_service cron
    fi
    
    _log_success "All automated maintenance jobs have been scheduled"
    _log_info "View current cron jobs with: crontab -l"
}

# Remove all VaultWarden cron jobs
remove_cron_jobs() {
    local user="${1:-root}"
    
    _log_section "Removing VaultWarden Cron Jobs"
    
    # Get current crontab without VaultWarden jobs
    local temp_cron
    temp_cron="$(mktemp)"
    
    crontab -u "$user" -l 2>/dev/null | grep -v "# VaultWarden:" | grep -v "backup-monitor.sh" | grep -v "update-firewall-rules.sh" > "$temp_cron" || true
    
    # Apply cleaned crontab
    crontab -u "$user" "$temp_cron"
    rm -f "$temp_cron"
    
    _log_success "VaultWarden cron jobs removed for user: $user"
}

# List current VaultWarden cron jobs
list_cron_jobs() {
    local user="${1:-root}"
    
    _log_section "Current VaultWarden Cron Jobs"
    
    if crontab -u "$user" -l 2>/dev/null | grep -A1 "# VaultWarden:" | grep -v "^--$"; then
        return 0
    else
        _log_info "No VaultWarden cron jobs found for user: $user"
        return 1
    fi
}
