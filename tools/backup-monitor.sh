#!/usr/bin/env bash
# tools/backup-monitor.sh - Orchestrates backups, manages retention, and sends notifications

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
# Source required libraries with error checking
CONFIG_LOADED_SUCCESS=false
for lib in config notifications; do # Added notifications
    lib_file="lib/${lib}.sh"
    if [[ -f "$lib_file" ]]; then
        # shellcheck source=/dev/null
        source "$lib_file"
        # Mark config as loaded successfully if it was config.sh
        [[ "$lib" == "config" ]] && CONFIG_LOADED_SUCCESS=true
    else
        # Allow missing notifications (logs warning), but config is critical
        if [[ "$lib" == "config" ]]; then
            log_error "CRITICAL: Required library not found: $lib_file"
            exit 1
        else
            log_warn "Optional library not found: $lib_file. Notifications disabled."
        fi
    fi
done

# Ensure config was loaded successfully before proceeding
if [[ "$CONFIG_LOADED_SUCCESS" != "true" ]]; then
     log_error "Configuration library (lib/config.sh) failed to load. Aborting."
     exit 1
fi
# Explicitly load config data into environment/map if needed immediately
load_config || { log_error "Failed to execute load_config function. Aborting."; exit 1; }


# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Configuration ---
# Use get_config_value for defaults, source constants library for fallback defaults
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi
readonly MAX_BACKUP_DISK_PERCENTAGE=${MAX_BACKUP_DISK_PERCENTAGE:-$(get_config_value "MAX_BACKUP_DISK_PERCENTAGE" "40")} # Default 40%
# Use a persistent lock file location within the state directory
# Ensure PROJECT_STATE_DIR is loaded via config.sh before using this
PERSISTENT_LOCK_FILE_PATH="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/.backup_cleanup.lock"

# --- Help text ---
show_help() {
    cat << EOF
VaultWarden Backup Monitor
USAGE:
    $0 [OPTIONS]
DESCRIPTION:
    Creates backups (DB or Full), manages retention (date and size based),
    and sends status notifications via email. Designed for cron execution.
    Uses a persistent lock file (${PERSISTENT_LOCK_FILE_PATH}) to prevent concurrent cleanup runs.
OPTIONS:
    --help           Show this help message
    --db-only        Create a database-only backup.
    --full           Create a full system backup (data + config).
    --cleanup        Run retention policy only to clean up old backups.
    --test-email     Send a test notification email using settings from secrets.
EOF
}

# --- Argument Parsing ---
DB_ONLY=false
FULL_BACKUP=false
CLEANUP_ONLY=false
TEST_EMAIL=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --db-only) DB_ONLY=true; shift ;;
        --full) FULL_BACKUP=true; shift ;;
        --cleanup) CLEANUP_ONLY=true; shift ;;
        --test-email) TEST_EMAIL=true; shift ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- Functions ---

perform_db_backup() {
    log_info "Starting database backup..."
    local script_path="tools/db-backup.sh"
    if [[ ! -x "$script_path" ]]; then
        log_error "'$script_path' script not found or not executable."
        return 1
    fi
    # Execute script, inherit errexit behavior
    # Run in subshell to isolate environment? Not necessary if scripts are well-behaved.
    if "$script_path"; then
        log_success "Database backup completed successfully."
        return 0
    else
        log_error "Database backup script failed (exit code $?). Check logs."
        return 1
    fi
}

perform_full_backup() {
    log_info "Starting full system backup..."
    local script_path="tools/create-full-backup.sh"
    if [[ ! -x "$script_path" ]]; then
        log_error "'$script_path' script not found or not executable."
        return 1
    fi
    if "$script_path"; then
        log_success "Full system backup completed successfully."
        return 0
    else
        log_error "Full backup script failed (exit code $?). Check logs."
        return 1
    fi
}

# Cleans old backups based on date and size, using flock for safety.
cleanup_old_backups_safe() {
    log_info "Running backup cleanup and retention policy..."
    # Ensure the directory for the lock file exists
    mkdir -p "$(dirname "$PERSISTENT_LOCK_FILE_PATH")" || { log_error "Cannot create directory for lock file. Skipping cleanup."; return 1; }

    # Use flock with a persistent lock file (FD 9)
    (
        # Attempt to acquire exclusive, non-blocking lock on FD 9
        flock -n 9 || { log_warn "Cleanup already in progress (lock held on $PERSISTENT_LOCK_FILE_PATH). Skipping this run."; exit 0; } # Exit subshell gracefully if lock held

        log_info "Acquired cleanup lock ($PERSISTENT_LOCK_FILE_PATH)."
        local db_dir="backups/db"
        local full_dir="backups/full"
        local backup_root_dir="backups" # Directory containing db/ and full/

        # --- Date-based cleanup ---
        log_info "Performing date-based cleanup..."
        local db_deleted=0 full_deleted=0 files_to_delete=() db_to_keep full_to_keep

        # Safely get retention counts from config or use defaults from constants.sh
        db_to_keep=$(get_config_value "BACKUP_KEEP_DB" "${DEFAULT_BACKUP_KEEP_DB:-14}")
        full_to_keep=$(get_config_value "BACKUP_KEEP_FULL" "${DEFAULT_BACKUP_KEEP_FULL:-4}")
         # Validate they are numbers > 0
         [[ "$db_to_keep" =~ ^[1-9][0-9]*$ ]] || db_to_keep=14
         [[ "$full_to_keep" =~ ^[1-9][0-9]*$ ]] || full_to_keep=4


        if [[ -d "$db_dir" ]]; then
             log_info "Keeping the latest $db_to_keep database backups based on modification date."
             # Find files, sort reverse by modification time, skip the ones to keep, collect the rest
             mapfile -t files_to_delete < <(find "$db_dir" -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' | sort -nr | tail -n +$((db_to_keep + 1)) | cut -d' ' -f2-)
             if [[ ${#files_to_delete[@]} -gt 0 ]]; then
                 log_info "Deleting ${#files_to_delete[@]} old DB backups (date-based)..."
                 # Use xargs with null delimiter for safety with filenames
                 printf '%s\0' "${files_to_delete[@]}" | xargs -0 -r rm -f || log_warn "Failed to delete some old DB backups."
                 db_deleted=${#files_to_delete[@]}
                 files_to_delete=() # Reset array
             else
                 _log_debug "No old DB backups found for date-based deletion."
             fi
        else
             _log_debug "DB backup directory '$db_dir' not found. Skipping date cleanup for DB."
        fi


        if [[ -d "$full_dir" ]]; then
             log_info "Keeping the latest $full_to_keep full backups based on modification date."
             mapfile -t files_to_delete < <(find "$full_dir" -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' | sort -nr | tail -n +$((full_to_keep + 1)) | cut -d' ' -f2-)
              if [[ ${#files_to_delete[@]} -gt 0 ]]; then
                 log_info "Deleting ${#files_to_delete[@]} old full backups (date-based)..."
                 printf '%s\0' "${files_to_delete[@]}" | xargs -0 -r rm -f || log_warn "Failed to delete some old full backups."
                 full_deleted=${#files_to_delete[@]}
                 files_to_delete=() # Reset array
             else
                 _log_debug "No old Full backups found for date-based deletion."
             fi
        else
             _log_debug "Full backup directory '$full_dir' not found. Skipping date cleanup for Full."
        fi
         log_info "Date-based cleanup removed $db_deleted DB and $full_deleted full backups."

        # --- Size-based cleanup ---
        log_info "Performing size-based cleanup (if necessary)..."
        local disk_usage_percent disk_info available_human available_kb oldest_backup size_deleted_count=0

        # Get usage percentage of the filesystem containing the backup root dir
         if ! disk_info=$(df -P "$backup_root_dir" 2>/dev/null | awk 'NR==2'); then
             log_error "Cannot determine disk usage for backup directory '$backup_root_dir'. Skipping size-based cleanup."
             # Continue to release lock in subshell
             return # Exit subshell function
         fi
         disk_usage_percent=$(echo "$disk_info" | awk '{ print $5 }' | sed 's/%//')
         available_kb=$(echo "$disk_info" | awk '{ print $4 }')
         # Use numfmt if available for human-readable size
         if command -v numfmt >/dev/null; then
             available_human=$(numfmt --to=iec --suffix=B $((available_kb * 1024)) 2>/dev/null || echo "${available_kb}K")
         else
             available_human="${available_kb}K"
         fi

        # Check against threshold (e.g., MAX_BACKUP_DISK_PERCENTAGE constant)
        if [[ "$disk_usage_percent" -gt "$MAX_BACKUP_DISK_PERCENTAGE" ]]; then
            log_warn "Filesystem usage ($disk_usage_percent%) for '$backup_root_dir' exceeds threshold ($MAX_BACKUP_DISK_PERCENTAGE%, ${available_human} free). Cleaning oldest backups by modification time..."

            # Loop while usage is high and backups exist
            local current_usage_percent="$disk_usage_percent"
            while [[ "$current_usage_percent" -gt "$MAX_BACKUP_DISK_PERCENTAGE" ]]; do
                # Find the single oldest backup file across both db and full directories based on modification time
                oldest_backup=$(find "$backup_root_dir/db" "$backup_root_dir/full" -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' 2>/dev/null | sort -n | head -n 1 | cut -d' ' -f2-)

                if [[ -n "$oldest_backup" && -f "$oldest_backup" ]]; then
                    local oldest_size
                    oldest_size=$(du -h "$oldest_backup" | cut -f1)
                    log_info "Deleting oldest backup ($oldest_size) to free space: $(basename "$oldest_backup")"
                    if rm -f "$oldest_backup"; then
                        ((size_deleted_count++))
                        sleep 0.1 # Small pause to allow FS update
                        # Re-check disk usage
                        if ! disk_info=$(df -P "$backup_root_dir" 2>/dev/null | awk 'NR==2'); then
                             log_error "Cannot re-check disk usage. Stopping size cleanup."
                             break
                        fi
                        current_usage_percent=$(echo "$disk_info" | awk '{ print $5 }' | sed 's/%//')
                        _log_debug "New usage: $current_usage_percent%"
                    else
                         log_error "Failed to delete '$oldest_backup'. Stopping size-based cleanup."
                         break # Exit loop if deletion fails
                    fi
                else
                    log_error "No more backup files found to delete in '$backup_root_dir', but disk usage ($current_usage_percent%) is still high ($MAX_BACKUP_DISK_PERCENTAGE% limit)."
                    break # Exit the while loop
                fi
            done
            log_info "Size-based cleanup removed $size_deleted_count oldest backups."
        else
             log_info "Filesystem usage ($disk_usage_percent%) for '$backup_root_dir' is within threshold ($MAX_BACKUP_DISK_PERCENTAGE%). No size-based cleanup needed."
        fi

        log_success "Backup cleanup process complete."
        # Lock released automatically when subshell exits

    ) 9>"$PERSISTENT_LOCK_FILE_PATH" # Associate FD 9 with the persistent lock file for the subshell
    local cleanup_rc=$? # Capture exit code of the subshell (flock process)
    if [[ $cleanup_rc -ne 0 ]]; then
         log_error "Backup cleanup sub-process failed with exit code $cleanup_rc."
         return 1
    fi
    return 0
}


send_test_email() {
    log_info "Sending test notification email..."
    # Check if notification function exists (sourced earlier)
    if ! declare -f test_smtp_connection > /dev/null; then
        log_error "Notification library not sourced or 'test_smtp_connection' function missing. Cannot send test email."
        return 1
    fi

    # Call the function from the sourced library
    if test_smtp_connection; then
        # Success message logged by test_smtp_connection itself
        return 0
    else
        # Error logged by test_smtp_connection itself
        return 1
    fi
}

send_backup_notification() {
    local backup_type="$1" # "Database" or "Full System"
    local success="$2" # true or false
    local details="$3" # Optional details like filename or error message

    # Check if notification function exists
     if ! declare -f send_notification > /dev/null; then
         log_warn "Notification library not sourced or 'send_notification' function missing. Skipping email notification."
         return
     fi

     local subject status_msg body category host
     # Get hostname safely
     host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "UnknownHost")
     if [[ "$success" == "true" ]]; then
        status_msg="SUCCESS"
        subject="✅ VaultWarden Backup Successful: $backup_type on $host"
        category="backup-success"
        body="The $backup_type backup for VaultWarden completed successfully.

Server: $host
Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Details: ${details:-No additional details}

No action required."
     else
        status_msg="FAILURE"
        subject="❌ VaultWarden Backup FAILED: $backup_type on $host"
        category="backup-failure"
        body="CRITICAL ALERT: The $backup_type backup for VaultWarden FAILED.

Server: $host
Time: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Error Details: ${details:-Check backup logs for more information}

ACTION REQUIRED: Please investigate the backup logs immediately on server '$host'.
Relevant log file: ${LOG_FILE:-/var/log/vaultwarden/system.log}" # Use logging lib variable
    fi

    log_info "Sending $status_msg notification for $backup_type backup..."
    # Call notification function
    send_notification "$category" "$subject" "$body" || log_warn "Attempt to send backup status notification email failed. Check notification logs."

}


# --- Main Execution ---
main() {
    log_header "Backup Monitor Started"
    local exit_code=0 # Track overall success/failure

    # Configuration loaded at the top of the script

    # Update lock file path now that PROJECT_STATE_DIR is loaded (redundant but safe)
     PERSISTENT_LOCK_FILE_PATH="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/.backup_cleanup.lock"
     _log_debug "Using lock file: $PERSISTENT_LOCK_FILE_PATH"


    if [[ "$TEST_EMAIL" == "true" ]]; then
        send_test_email || exit_code=1
        log_header "Backup Monitor Finished (Test Email Mode)"
        exit $exit_code
    fi

    if [[ "$CLEANUP_ONLY" == "true" ]]; then
        cleanup_old_backups_safe || exit_code=1 # Use the safe version with locking
        log_header "Backup Monitor Finished (Cleanup Only Mode)"
        exit $exit_code # Exit with status from cleanup
    fi

    # Default action if no flags: run cleanup only
    if [[ "$DB_ONLY" == false && "$FULL_BACKUP" == false ]]; then
        log_warn "No backup type specified (--db-only or --full). Running cleanup only."
        cleanup_old_backups_safe || exit_code=1
        log_header "Backup Monitor Finished (Implicit Cleanup)"
        exit $exit_code
    fi

    local backup_failed_type="" backup_error_details="" backup_filename=""

    # --- Perform Backups ---
    if [[ "$DB_ONLY" == "true" ]]; then
        local db_backup_success=true
        if ! perform_db_backup; then
             db_backup_success=false
             backup_failed_type="Database"
             backup_error_details="Database backup script failed. Check logs."
             exit_code=1 # Mark failure
        else
             # Get latest db backup filename for notification details
             backup_filename=$(find backups/db -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-)
             [[ -n "$backup_filename" ]] && backup_filename=$(basename "$backup_filename")
        fi
        # Send notification immediately after DB backup attempt
         send_backup_notification "Database" "$db_backup_success" "${backup_filename:-$backup_error_details}"
    fi


    if [[ "$FULL_BACKUP" == "true" ]]; then
         local full_backup_success=true full_backup_filename=""
         # Capture specific error message if possible
         local full_backup_output="" full_backup_rc=0
         # Execute and capture output/rc
         full_backup_output=$(perform_full_backup 2>&1) || full_backup_rc=$?

        if [[ $full_backup_rc -ne 0 ]]; then
            full_backup_success=false
            # Update failure type only if no previous failure recorded
            [[ -z "$backup_failed_type" ]] && backup_failed_type="Full System"
            backup_error_details="Full backup script failed (rc=$full_backup_rc). Check logs. Last lines: $(echo "$full_backup_output" | tail -n 3)"
            exit_code=1 # Ensure overall exit code reflects failure
        else
             # Get latest full backup filename
             full_backup_filename=$(find backups/full -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-)
              [[ -n "$full_backup_filename" ]] && full_backup_filename=$(basename "$full_backup_filename")
        fi
        # Send notification after attempting Full backup
         send_backup_notification "Full System" "$full_backup_success" "${full_backup_filename:-$backup_error_details}"

         # Optionally trigger Emergency Kit after successful full backup if requested by flag
         # Example: if [[ "$full_backup_success" == "true" && "$CREATE_KIT_AFTER_FULL" == "true" ]]; then ./tools/create-emergency-kit.sh --auto-password; fi
    fi

    # --- Perform Cleanup ---
    # Always run cleanup after backup attempts, regardless of success
    cleanup_old_backups_safe || { log_warn "Backup cleanup task reported errors."; exit_code=1; } # Update exit code if cleanup failed

    log_header "Backup Monitor Finished"
    exit $exit_code
}

# --- Script Entry Point ---
# Wrap main execution in error trapping for better diagnostics
# trap 'log_error "Unhandled error occurred at line $LINENO"; exit 1' ERR # Optional: Trap ERR signals
main "$@"
