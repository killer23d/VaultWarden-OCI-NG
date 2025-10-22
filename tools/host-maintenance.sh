#!/usr/bin/env bash
# tools/host-maintenance.sh - System maintenance script for VaultWarden-OCI-NG host

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
# Source system library for service/package management (optional but helpful)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "lib/system.sh" ]]; then
    source "lib/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
    log_warn "lib/system.sh not found. Some checks/operations might be limited."
fi
# Source config library (needed for PROJECT_STATE_DIR)
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh."
        # Use default state dir if config fails
        PROJECT_STATE_DIR="/var/lib/vaultwarden"
    fi
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    # Use default state dir if config lib missing
    PROJECT_STATE_DIR="/var/lib/vaultwarden"
fi
# Source constants if available (for log cleanup days etc.)
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi
# Source notifications library (optional)
NOTIFICATIONS_AVAILABLE=false
if [[ -f "lib/notifications.sh" ]]; then
    source "lib/notifications.sh"
    NOTIFICATIONS_AVAILABLE=true
else
    log_warn "Optional library not found: lib/notifications.sh. Notifications disabled."
fi

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---


# --- Configuration ---
# LOG_FILE="/var/log/vaultwarden/maintenance.log" # Handled by lib/logging.sh redirection
COMPOSE_FILE="docker-compose.yml" # Assumes running from project root
# Use constants or provide defaults
LOG_CLEANUP_DAYS=${LOG_CLEANUP_DAYS:-${DEFAULT_LOG_CLEANUP_DAYS:-30}} # Default 30 days
JOURNAL_VACUUM_TIME=${JOURNAL_VACUUM_TIME:-"30d"} # Systemd journal retention time
JOURNAL_VACUUM_SIZE=${JOURNAL_VACUUM_SIZE:-"100M"} # Systemd journal retention size limit

# --- Help text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Host System Maintenance

USAGE:
    sudo $0 [OPTIONS]

DESCRIPTION:
    Performs essential host system maintenance tasks including package updates,
    Docker system cleanup, and log rotation relevant to the VaultWarden stack.
    Designed for automated execution via cron. Requires sudo privileges.

OPTIONS:
    --help              Show this help message
    --auto              Run all standard maintenance tasks non-interactively (Default if no tasks specified)
    --update-packages   Only update system packages (apt update && apt upgrade)
    --cleanup-docker    Only clean up Docker system (prune images, volumes, networks)
    --cleanup-logs      Only clean up VaultWarden logs and system journal
    --check-reboot      Only check if a system reboot is recommended/required
    --emergency-kit     Generate and email a new emergency access kit after maintenance
    --dry-run           Preview actions without making changes
    --debug             Enable debug logging (set DEBUG=true)

EXAMPLES:
    sudo $0 --auto                       # Run all tasks automatically (recommended for cron)
    sudo $0 --update-packages            # Only update OS packages
    sudo $0 --cleanup-docker --dry-run   # Preview Docker cleanup actions
    sudo $0 --auto --emergency-kit       # Run all tasks and generate a kit

SCHEDULING (root crontab):
    # Weekly full maintenance on Sunday at 3 AM, logging to dedicated file
    0 3 * * 0 cd $PROJECT_ROOT && ./tools/host-maintenance.sh --auto >> ${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/maintenance-cron.log 2>&1
EOF
}

# --- Argument Parsing ---
# Determine which tasks to run
RUN_UPDATE_PACKAGES=false
RUN_CLEANUP_DOCKER=false
RUN_CLEANUP_LOGS=false
RUN_CHECK_REBOOT=false
RUN_EMERGENCY_KIT=false
DRY_RUN=false
# If no specific task flags are given, assume --auto
AUTO_MODE=false
# Check if any task-specific flags were passed
task_flag_passed=false
for arg in "$@"; do
    case "$arg" in
        --update-packages|--cleanup-docker|--cleanup-logs|--check-reboot|--emergency-kit)
            task_flag_passed=true
            break
            ;;
    esac
done
# If no args were passed OR only --auto was passed, OR no task flags were passed
if [[ $# -eq 0 || ($# -eq 1 && "$1" == "--auto") || "$task_flag_passed" == false ]]; then
    AUTO_MODE=true
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --auto) AUTO_MODE=true; shift ;; # Set flag but don't exit loop yet
        --update-packages) RUN_UPDATE_PACKAGES=true; shift ;;
        --cleanup-docker) RUN_CLEANUP_DOCKER=true; shift ;;
        --cleanup-logs) RUN_CLEANUP_LOGS=true; shift ;;
        --check-reboot) RUN_CHECK_REBOOT=true; shift ;;
        --emergency-kit) RUN_EMERGENCY_KIT=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --debug) export DEBUG=true; shift ;; # Enable debug logging
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done


# If --auto or no specific tasks, enable all standard tasks (not kit unless specified)
if [[ "$AUTO_MODE" == true ]]; then
    log_info "Auto mode enabled: running standard maintenance tasks."
    RUN_UPDATE_PACKAGES=true
    RUN_CLEANUP_DOCKER=true
    RUN_CLEANUP_LOGS=true
    RUN_CHECK_REBOOT=true # Include reboot check in auto mode
fi

# --- Functions ---

# Check if running as root
check_privileges() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        log_error "This script requires root privileges (sudo) to manage packages, services, and logs."
        exit 1
    fi
    _log_debug "Root privileges confirmed."
}

# Update system packages (Debian/Ubuntu specific)
update_system_packages() {
    if [[ "$RUN_UPDATE_PACKAGES" == "false" ]]; then _log_debug "Skipping package update."; return 0; fi
    _log_section "System Package Update"

    # Check for apt-get command
    if ! command -v apt-get >/dev/null; then
         log_error "apt-get command not found. Cannot update packages."
         return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run: apt-get update"
        log_info "[DRY RUN] Would run: apt-get upgrade -y"
        log_info "[DRY RUN] Would run: apt-get autoremove -y"
        log_info "[DRY RUN] Would run: apt-get autoclean"
        return 0
    fi

    log_info "Updating package lists (apt-get update)..."
    # Use non-interactive flags, capture output on error
    local output rc
    # Run with timeout? No, update can take time.
    output=$(DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        log_error "Failed to update package lists (Exit Code: $rc)."
        log_error "Output:\n$output"
        return 1
    fi
    log_success "Package lists updated successfully."

    log_info "Upgrading installed packages (apt-get upgrade)..."
    # Use -o options to handle config file prompts non-interactively
    # --force-confdef: Keep current config if new default available
    # --force-confold: Keep current config if maintainer script changed it
    # Add --allow-releaseinfo-change based on potential apt errors
    output=$(DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        --allow-releaseinfo-change 2>&1)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        log_error "Package upgrade failed (Exit Code: $rc)."
        log_error "Output:\n$output"
        # Don't fail hard, some packages might fail transiently, report and continue
        # return 1
    else
        log_success "System packages upgraded successfully."
    fi


    log_info "Removing unused packages (apt-get autoremove)..."
    output=$(DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq 2>&1)
    rc=$?
     if [[ $rc -ne 0 ]]; then
         log_warn "Autoremove command failed (Exit Code: $rc). Output:\n$output"
     else
          log_success "Unused packages removed."
     fi

     log_info "Cleaning up package cache (apt-get autoclean)..."
     if ! apt-get autoclean -qq; then
          log_warn "Autoclean command failed."
     fi

    log_success "System package update process finished."
    return 0
}


# Clean up Docker system resources
cleanup_docker_system() {
    if [[ "$RUN_CLEANUP_DOCKER" == "false" ]]; then _log_debug "Skipping Docker cleanup."; return 0; fi
    _log_section "Docker System Cleanup"

    if ! command -v docker >/dev/null 2>&1; then
        log_warn "Docker command not found. Skipping Docker cleanup."
        return 0
    fi
    # Use timeout for docker info in case daemon is hung
    if ! timeout 10 docker info >/dev/null 2>&1; then
         log_warn "Docker daemon not accessible. Skipping Docker cleanup."
         return 0
    fi


    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run 'docker system prune -af --volumes'."
        # Also simulate image pull? Maybe too complex for dry run.
        return 0
    fi

    # Optional: Pull latest images for running services first?
    # This overlaps with Watchtower's check. Skip pull here if Watchtower is used.
    # log_info "Pulling latest images for Vaultwarden stack (if defined)..."
    # if [[ -f "$COMPOSE_FILE" ]]; then
    #    (cd "$PROJECT_ROOT" && docker compose -f "$COMPOSE_FILE" pull) || log_warn "Failed to pull some Docker images."
    # fi


    log_info "Running Docker system prune (removes stopped containers, unused networks, dangling images, build cache)..."
    # Use -a to remove ALL unused images (not just dangling)
    # Use --volumes to remove unused volumes (CAUTION: ensure no important data in unnamed volumes managed outside compose)
    # Add timeout? Prune can take time.
    if docker system prune -af --volumes; then
        log_success "Docker system cleanup completed successfully."
    else
        log_error "Docker system prune command failed. Check Docker logs."
        return 1 # Indicate failure
    fi

    return 0
}


# Clean up Vaultwarden logs and system journal
cleanup_system_logs() {
     if [[ "$RUN_CLEANUP_LOGS" == "false" ]]; then _log_debug "Skipping log cleanup."; return 0; fi
     _log_section "System Log Cleanup"

     # Use PROJECT_STATE_DIR loaded from config
     local log_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs"
     local log_cleanup_days_num=${LOG_CLEANUP_DAYS:-30} # Ensure it's a number

     if [[ "$DRY_RUN" == "true" ]]; then
         log_info "[DRY RUN] Would clean up logs in '$log_dir/*' older than $log_cleanup_days_num days."
         log_info "[DRY RUN] Would clean up Vaultwarden internal log if present."
         log_info "[DRY RUN] Would vacuum systemd journal (time <= ${JOURNAL_VACUUM_TIME}, size <= ${JOURNAL_VACUUM_SIZE})."
         return 0
     fi

     # Clean VaultWarden-specific logs in state/logs directory
     if [[ -d "$log_dir" ]]; then
         log_info "Cleaning up VaultWarden container logs in '$log_dir' older than $log_cleanup_days_num days..."
         local deleted_count=0 error_occurred=false
         # Find and delete log files (e.g., *.log, *.log.N, *.gz), count successes
         # Use -print0 and xargs -0 for safety with filenames
         # Capture output of find directly to count files found for deletion
         mapfile -t files_to_delete < <(find "$log_dir" -type f \( -name "*.log" -o -name "*.log.*" -o -name "*.gz" \) -mtime "+$log_cleanup_days_num" -print 2>/dev/null)
         deleted_count=${#files_to_delete[@]}

         if [[ $deleted_count -gt 0 ]]; then
             log_info "Found $deleted_count old log files for deletion..."
             # Use printf '%s\0' with xargs -0 rm -f
             if printf '%s\0' "${files_to_delete[@]}" | xargs -0 -r rm -f; then
                 log_success "Removed $deleted_count old VaultWarden log files from '$log_dir'."
             else
                 log_warn "Failed to remove some old VaultWarden log files."
             fi
         else
              log_info "No old VaultWarden container log files found for deletion in '$log_dir'."
         fi
     else
          log_warn "VaultWarden log directory '$log_dir' not found. Skipping cleanup."
     fi

     # Clean internal Vaultwarden log file (vaultwarden.log inside data volume) if it exists
     local internal_log_path="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/vaultwarden.log"
     if [[ -f "$internal_log_path" ]]; then
          log_info "Checking internal Vaultwarden log file '$internal_log_path'..."
          local internal_log_size_kb
          internal_log_size_kb=$(du -k "$internal_log_path" | cut -f1)
          local max_size_kb=102400 # Max size 100MB
          if [[ $internal_log_size_kb -gt $max_size_kb ]]; then
               log_warn "Internal log file '$internal_log_path' is large (${internal_log_size_kb}KB). Truncating..."
               # Truncate file instead of deleting (safer for running process)
               if truncate -s 0 "$internal_log_path"; then
                    log_success "Internal log file truncated."
               else
                    log_error "Failed to truncate internal log file."
               fi
          else
               _log_debug "Internal log file size (${internal_log_size_kb}KB) is within limits."
          fi
     fi


     # Clean systemd journal (if available)
     if command -v journalctl >/dev/null 2>&1; then
         log_info "Vacuuming systemd journal (Time <= $JOURNAL_VACUUM_TIME, Size <= $JOURNAL_VACUUM_SIZE)..."
         local journal_output journal_rc
         # Run vacuum by time first, then size
         journal_output=$(journalctl --vacuum-time="$JOURNAL_VACUUM_TIME" 2>&1)
         journal_rc=$?
         if [[ $journal_rc -eq 0 ]]; then
             log_success "Systemd journal vacuumed by time ($JOURNAL_VACUUM_TIME)."
             _log_debug "Vacuum time output: $journal_output"
         else
             log_warn "Failed to vacuum systemd journal by time (rc=$journal_rc). Output: $journal_output"
         fi

         # Vacuum by size
         journal_output=$(journalctl --vacuum-size="$JOURNAL_VACUUM_SIZE" 2>&1)
         journal_rc=$?
          if [[ $journal_rc -eq 0 ]]; then
               log_success "Systemd journal vacuumed by size ($JOURNAL_VACUUM_SIZE)."
                _log_debug "Vacuum size output: $journal_output"
          else
                log_warn "Failed to vacuum systemd journal by size (rc=$journal_rc). Output: $journal_output"
          fi
     else
          log_info "journalctl command not found. Skipping systemd journal cleanup."
     fi

     log_success "System log cleanup process finished."
     return 0
}


# Check if system reboot is needed
check_reboot_needed() {
    if [[ "$RUN_CHECK_REBOOT" == "false" ]]; then _log_debug "Skipping reboot check."; return 0; fi
     _log_section "Checking if Reboot Recommended"

    local reboot_required=false
    local reboot_reason=""

    # Standard check file for Debian/Ubuntu
    if [[ -f "/var/run/reboot-required" ]]; then
        reboot_required=true
        reboot_reason="System updates require reboot (found /var/run/reboot-required)."
         # Append package names if available and file readable
         if [[ -r "/var/run/reboot-required.pkgs" ]]; then
             reboot_reason+=" Packages: $(head -n 5 /var/run/reboot-required.pkgs | tr '\n' ' ')$( [[ $(wc -l < /var/run/reboot-required.pkgs) -gt 5 ]] && echo '...' )"
         fi
         _log_debug "Reboot required flag file found."
    fi

    # Check if running kernel differs from latest installed kernel (optional, more advanced)
     # Check if /boot exists and we can list modules
     if [[ -d "/boot" && -d "/lib/modules" ]]; then
         local running_kernel installed_kernel
         running_kernel=$(uname -r)
         # Find latest installed kernel based on directory modification time in /lib/modules
         # This assumes kernel versions are simple enough for ls -t to work reliably
         installed_kernel=$(ls -t /lib/modules/ | head -n 1 2>/dev/null)

         if [[ -n "$installed_kernel" && "$running_kernel" != "$installed_kernel" ]]; then
              # Verify the installed kernel has a corresponding image in /boot
              if find "/boot/" -maxdepth 1 -name "vmlinuz-${installed_kernel}*" | grep -q .; then
                   _log_debug("Running kernel ($running_kernel) differs from latest installed ($installed_kernel).")
                   if [[ "$reboot_required" == "false" ]]; then # Only add reason if not already set
                        reboot_required=true
                        reboot_reason="New kernel ($installed_kernel) installed but not running (current: $running_kernel)."
                   fi
              else
                   _log_debug("Latest module directory ($installed_kernel) found, but no matching kernel image in /boot. Ignoring.")
              fi
         fi
     else
         _log_debug "Cannot check running vs installed kernel (/boot or /lib/modules missing/inaccessible)."
     fi


    if [[ "$reboot_required" == "true" ]]; then
        log_warn "Reboot Recommended: ${reboot_reason}"

        # Send notification if notifications library is available
        if [[ "$NOTIFICATIONS_AVAILABLE" == "true" ]]; then
             if declare -f send_notification >/dev/null; then
                 local subject="⚠️ Reboot Recommended on $(hostname -f 2>/dev/null || hostname)"
                 local body="VaultWarden server maintenance check has detected that a system reboot is recommended.

Reason: ${reboot_reason}
Server: $(hostname -f 2>/dev/null || hostname)
Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

Please schedule a reboot when convenient to apply kernel/system updates:
'sudo reboot'

VaultWarden services should restart automatically after reboot if Docker service is enabled."
                 send_notification "maintenance" "$subject" "$body" || log_warn "Failed to send reboot notification email."
             else
                  log_warn "send_notification function not found. Cannot send reboot email."
             fi
        fi
    else
        log_success "No system reboot required or recommended at this time."
    fi

    return 0
}


# Generate emergency access kit (calls the dedicated script)
generate_emergency_kit() {
    if [[ "$RUN_EMERGENCY_KIT" == "false" ]]; then _log_debug "Skipping emergency kit generation."; return 0; fi
     _log_section "Emergency Access Kit Generation"

    local kit_script="$PROJECT_ROOT/tools/create-emergency-kit.sh"
    if [[ ! -x "$kit_script" ]]; then
        log_error "Emergency kit script '$kit_script' not found or not executable. Skipping."
        return 1
    fi

    log_info "Triggering emergency access kit generation (using auto-password)..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run '$kit_script --auto-password'."
        return 0
    fi

    # Run non-interactively, capture output/status
    local kit_output kit_rc=0
    # Run with sudo if needed (kit script checks itself, but let's be explicit)
    kit_output=$(sudo "$kit_script" --auto-password 2>&1) || kit_rc=$?

    if [[ $kit_rc -eq 0 ]]; then
        log_success "Emergency access kit generated and should be sent via email."
        _log_debug "Kit generation output:\n$kit_output"
        return 0
    else
        log_error "Emergency kit generation script failed (rc=$kit_rc)."
        log_error "Output:\n$kit_output"
        return 1
    fi
}


# Send maintenance completion notification
send_completion_notification() {
    # Only send if running in auto mode OR if specific tasks were run (implies scheduled/intentional execution)
    if [[ "$AUTO_MODE" != "true" && "$RUN_UPDATE_PACKAGES" == false && "$RUN_CLEANUP_DOCKER" == false && "$RUN_CLEANUP_LOGS" == false && "$RUN_CHECK_REBOOT" == false && "$RUN_EMERGENCY_KIT" == false ]]; then
        _log_debug "Not sending completion notification (not auto mode and no tasks run)."
        return 0
    fi
    # Also skip if running manually and no tasks were performed (e.g., just --help)
    if [[ "$AUTO_MODE" != "true" && "$RUN_UPDATE_PACKAGES" == false && "$RUN_CLEANUP_DOCKER" == false && "$RUN_CLEANUP_LOGS" == false && "$RUN_CHECK_REBOOT" == false && "$RUN_EMERGENCY_KIT" == false ]]; then
        _log_debug "Skipping completion notification (manual run with no tasks performed)."
        return 0
    fi


    if [[ "$NOTIFICATIONS_AVAILABLE" == "true" ]]; then
         if ! declare -f send_notification >/dev/null; then
             log_warn "send_notification function not found. Skipping completion email."
             return
         fi

        log_info "Sending maintenance completion notification..."
        local subject="✅ VaultWarden Host Maintenance Completed on $(hostname -f 2>/dev/null || hostname)"
        local reboot_status="System status normal. No reboot required."
        # Check reboot flag file again for final status
        [[ -f "/var/run/reboot-required" ]] && reboot_status="WARNING: A system reboot is recommended."

        local body="Scheduled host system maintenance for VaultWarden has completed.

Tasks Performed:
- Package Updates:   $( [[ "$RUN_UPDATE_PACKAGES" == "true" ]] && echo "Yes" || echo "No" )
- Docker Cleanup:    $( [[ "$RUN_CLEANUP_DOCKER" == "true" ]] && echo "Yes" || echo "No" )
- Log Cleanup:       $( [[ "$RUN_CLEANUP_LOGS" == "true" ]] && echo "Yes" || echo "No" )
- Reboot Check:      $( [[ "$RUN_CHECK_REBOOT" == "true" ]] && echo "Yes" || echo "No" )
- Emergency Kit:     $( [[ "$RUN_EMERGENCY_KIT" == "true" ]] && echo "Attempted" || echo "Skipped" )

Server: $(hostname -f 2>/dev/null || hostname)
Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

${reboot_status}
"
        # Send notification
        send_notification "maintenance" "$subject" "$body" || log_warn "Failed to send completion notification email. Check notification logs."
    else
         _log_debug "Notifications disabled. Skipping completion email."
    fi
}


# --- Main Execution ---
main() {
    log_header "VaultWarden Host Maintenance Started"
    check_privileges # Ensure script runs as root

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "*** DRY RUN MODE ENABLED - NO CHANGES WILL BE MADE ***"
    fi

    local overall_status=0 # 0 = success, 1 = failure in at least one step

    # Perform selected maintenance tasks sequentially
    # Use || overall_status=1 to track if any step fails
    update_system_packages || overall_status=1
    cleanup_docker_system || overall_status=1
    cleanup_system_logs || overall_status=1
    check_reboot_needed # Doesn't return failure status, just logs/notifies
    generate_emergency_kit || overall_status=1 # Run this after other cleanups

    # Send completion notification (only if not in dry run)
    if [[ "$DRY_RUN" == "false" ]]; then
        send_completion_notification
    fi

    log_header "Host Maintenance Finished"
    if [[ $overall_status -eq 0 ]]; then
         log_success "All selected maintenance tasks completed successfully."
    else
         # Use log_warn because script might finish, but with errors
         log_warn "One or more maintenance tasks encountered errors. Please review logs."
    fi

    exit $overall_status
}

# --- Script Entry Point ---
# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Optional: Add ERR trap for better debugging
    # trap 'log_error "Unhandled error occurred at line $LINENO in $(basename ${BASH_SOURCE[0]})"; exit 1' ERR
    main
fi
