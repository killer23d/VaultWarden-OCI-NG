#!/usr/bin/env bash
# tools/backup-monitor.sh - Comprehensive backup monitoring and execution

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

# Additional required libraries
for lib in config backup-core notifications system; do
    lib_file="lib/${lib}.sh"
    if [[ -f "$lib_file" ]]; then
        # shellcheck source=/dev/null
        source "$lib_file"
    else
        log_error "CRITICAL: Required library not found: $lib_file"
        exit 1
    fi
done

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# P1 FIX: Add standardized error handling
trap 'log_error "Script failed at line $LINENO in $(basename "${BASH_SOURCE[0]}")"; exit 1' ERR

# --- Configuration ---
DB_ONLY=false
FULL_BACKUP=false
VERIFY_ONLY=false
EMERGENCY_KIT=false
FORCE_MODE=false
NOTIFICATION_TYPE="backup"

# --- Help Text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Backup Monitor and Execution Script

USAGE:
    $0 [OPTIONS]

DESCRIPTION:
    Manages and monitors VaultWarden backups with comprehensive options for
    database-only backups, full system backups, verification, and emergency
    kit generation. Includes automatic notification and cleanup.

OPTIONS:
    --help              Show this help message
    --db-only           Perform database backup only (SQLite)
    --full-backup       Perform complete system backup (database + configs)
    --verify            Verify existing backups without creating new ones
    --emergency-kit     Generate emergency access kit after backup
    --force             Force backup even if recent backup exists
    --silent            Suppress notifications (emergency use only)

BACKUP TYPES:
    Database Only:      SQLite database with integrity checks
    Full Backup:        Database + configuration + secrets (encrypted)
    Emergency Kit:      Complete system recovery package (encrypted)

EXAMPLES:
    # Daily database backup (typical cron usage)
    $0 --db-only

    # Weekly full system backup
    $0 --full-backup

    # Verify all existing backups
    $0 --verify

    # Emergency complete backup with kit
    $0 --full-backup --emergency-kit --force

NOTES:
    - Backups are encrypted using Age encryption
    - Notifications sent via configured SMTP (if available)
    - Failed backups trigger alert notifications
    - Retention policies automatically enforced
EOF
}

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --db-only) DB_ONLY=true; shift ;;
            --full-backup) FULL_BACKUP=true; shift ;;
            --verify) VERIFY_ONLY=true; shift ;;
            --emergency-kit) EMERGENCY_KIT=true; shift ;;
            --force) FORCE_MODE=true; shift ;;
            --silent) NOTIFICATION_TYPE="silent"; shift ;;
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done

    # Validate argument combinations
    local selected_modes=0
    [[ "$DB_ONLY" == "true" ]] && ((selected_modes++))
    [[ "$FULL_BACKUP" == "true" ]] && ((selected_modes++))
    [[ "$VERIFY_ONLY" == "true" ]] && ((selected_modes++))

    if [[ $selected_modes -eq 0 ]]; then
        log_info "No backup mode specified, defaulting to --db-only"
        DB_ONLY=true
    elif [[ $selected_modes -gt 1 ]]; then
        log_error "Multiple backup modes specified. Choose only one."
        exit 1
    fi

    # Emergency kit only makes sense with actual backups
    if [[ "$EMERGENCY_KIT" == "true" && "$VERIFY_ONLY" == "true" ]]; then
        log_error "Emergency kit cannot be generated in verify-only mode."
        exit 1
    fi
}

# --- Backup Functions ---

check_backup_prerequisites() {
    _log_section "Checking Backup Prerequisites"
    local errors=0

    # Check if config is loaded
    if ! load_config >/dev/null 2>&1; then
        log_error "Failed to load project configuration."
        ((errors++))
    fi

    # Check backup directory
    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    if [[ ! -d "$backup_dir" ]]; then
        log_info "Creating backup directory: $backup_dir"
        mkdir -p "$backup_dir" || {
            log_error "Failed to create backup directory."
            ((errors++))
        }
    fi

    # Check Age key availability
    if [[ ! -f "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" ]]; then
        log_error "Age encryption key not found. Cannot perform encrypted backups."
        ((errors++))
    fi

    # Check VaultWarden database
    local db_path="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/db.sqlite3"
    if [[ ! -f "$db_path" && "$VERIFY_ONLY" != "true" ]]; then
        log_warn "VaultWarden database not found at: $db_path"
        log_warn "This may be expected for new installations."
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Backup prerequisites check failed with $errors error(s)."
        return 1
    fi

    log_success "Backup prerequisites verified."
    return 0
}

perform_database_backup() {
    _log_section "Performing Database Backup"

    local db_path="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/db.sqlite3"
    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_file="$backup_dir/vaultwarden-db-backup-$timestamp.sqlite3.gz.age"

    if [[ ! -f "$db_path" ]]; then
        log_error "Database file not found: $db_path"
        return 1
    fi

    log_info "Creating database backup..."
    log_info "Source: $db_path"
    log_info "Target: $backup_file"

    # Check if recent backup exists and force mode is not enabled
    if [[ "$FORCE_MODE" != "true" ]]; then
        local recent_backup
        recent_backup=$(find "$backup_dir" -name "vaultwarden-db-backup-*.sqlite3.gz.age" -mtime -1 | head -n 1)
        if [[ -n "$recent_backup" ]]; then
            log_warn "Recent database backup found: $(basename "$recent_backup")"
            log_info "Use --force to override or run full backup instead."
            return 0
        fi
    fi

    # Create database backup with integrity check
    log_info "Verifying database integrity before backup..."
    if ! sqlite3 "$db_path" "PRAGMA integrity_check;" | grep -q "ok"; then
        log_error "Database integrity check failed. Aborting backup."
        return 1
    fi

    # Perform the backup with compression and encryption
    if sqlite3 "$db_path" ".backup /dev/stdout" | gzip | age -r "$(cat "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" | grep -o 'age[^[:space:]]*')" > "$backup_file"; then
        local backup_size
        backup_size=$(du -h "$backup_file" | cut -f1)
        log_success "Database backup created successfully."
        log_info "Backup file: $backup_file"
        log_info "Backup size: $backup_size"

        # Verify the backup can be decrypted
        if age -d -i "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" "$backup_file" | gzip -t >/dev/null 2>&1; then
            log_success "Backup verification passed (decryption + compression test)."
        else
            log_error "Backup verification failed. Backup may be corrupted."
            rm -f "$backup_file"
            return 1
        fi
    else
        log_error "Database backup failed."
        rm -f "$backup_file" # Clean up partial file
        return 1
    fi

    # Enforce retention policy (keep last 14 daily backups)
    log_info "Enforcing backup retention policy..."
    find "$backup_dir" -name "vaultwarden-db-backup-*.sqlite3.gz.age" -type f -mtime +14 -delete
    local kept_backups
    kept_backups=$(find "$backup_dir" -name "vaultwarden-db-backup-*.sqlite3.gz.age" | wc -l)
    log_info "Retention: $kept_backups database backup(s) kept."

    return 0
}

perform_full_backup() {
    _log_section "Performing Full System Backup"

    # Use the existing full backup tool
    local full_backup_script="tools/create-full-backup.sh"

    if [[ ! -x "$full_backup_script" ]]; then
        log_error "Full backup script not found or not executable: $full_backup_script"
        return 1
    fi

    log_info "Executing full system backup..."
    local backup_args=""
    [[ "$FORCE_MODE" == "true" ]] && backup_args="--force"

    if "$full_backup_script" $backup_args; then
        log_success "Full system backup completed successfully."
        return 0
    else
        log_error "Full system backup failed."
        return 1
    fi
}

verify_existing_backups() {
    _log_section "Verifying Existing Backups"

    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    local verified=0 failed=0

    if [[ ! -d "$backup_dir" ]]; then
        log_warn "Backup directory does not exist: $backup_dir"
        return 1
    fi

    log_info "Scanning for backup files in: $backup_dir"

    # Verify database backups
    while IFS= read -r -d '' backup_file; do
        log_info "Verifying: $(basename "$backup_file")"
        if age -d -i "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" "$backup_file" | gzip -t >/dev/null 2>&1; then
            log_success "✓ $(basename "$backup_file")"
            ((verified++))
        else
            log_error "✗ $(basename "$backup_file")"
            ((failed++))
        fi
    done < <(find "$backup_dir" -name "*.sqlite3.gz.age" -type f -print0)

    # Verify full system backups
    while IFS= read -r -d '' backup_file; do
        log_info "Verifying: $(basename "$backup_file")"
        if age -d -i "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" "$backup_file" | tar -tz >/dev/null 2>&1; then
            log_success "✓ $(basename "$backup_file")"
            ((verified++))
        else
            log_error "✗ $(basename "$backup_file")"
            ((failed++))
        fi
    done < <(find "$backup_dir" -name "*.tar.gz.age" -type f -print0)

    log_info "Verification Summary:"
    log_info "  Verified: $verified backup(s)"
    log_info "  Failed: $failed backup(s)"

    if [[ $failed -gt 0 ]]; then
        log_error "Some backups failed verification."
        return 1
    elif [[ $verified -eq 0 ]]; then
        log_warn "No backup files found to verify."
        return 1
    else
        log_success "All backups verified successfully."
        return 0
    fi
}

generate_emergency_kit() {
    _log_section "Generating Emergency Access Kit"

    local emergency_script="tools/create-emergency-kit.sh"

    if [[ ! -x "$emergency_script" ]]; then
        log_error "Emergency kit script not found or not executable: $emergency_script"
        return 1
    fi

    log_info "Creating emergency access kit..."

    if "$emergency_script" --auto-password; then
        log_success "Emergency access kit generated successfully."
        return 0
    else
        log_error "Emergency kit generation failed."
        return 1
    fi
}

send_backup_notification() {
    local status="$1"
    local details="$2"

    if [[ "$NOTIFICATION_TYPE" == "silent" ]]; then
        return 0
    fi

    # Check if notifications are available
    if ! declare -f send_notification >/dev/null; then
        _log_debug "Notification function not available, skipping email."
        return 0
    fi

    local subject emoji
    case "$status" in
        "success")
            subject="VaultWarden Backup Completed Successfully"
            emoji="✅"
            ;;
        "warning")
            subject="VaultWarden Backup Completed with Warnings"
            emoji="⚠️"
            ;;
        "error")
            subject="VaultWarden Backup Failed"
            emoji="❌"
            ;;
        *)
            subject="VaultWarden Backup Status Update"
            emoji="ℹ️"
            ;;
    esac

    local body
    body=$(cat << EOF
$emoji VaultWarden Backup Report

Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Server: $(hostname -f 2>/dev/null || hostname)
Status: $status

Details:
$details

This is an automated backup notification from VaultWarden-OCI-NG.
EOF
    )

    send_notification "$NOTIFICATION_TYPE" "$subject" "$body"
}

# --- Main Execution ---
main() {
    log_header "VaultWarden-OCI-NG Backup Monitor"

    parse_arguments "$@"

    # Check prerequisites
    check_backup_prerequisites || exit 1

    local overall_status="success"
    local details_log=""

    # Execute requested backup operation
    if [[ "$VERIFY_ONLY" == "true" ]]; then
        if verify_existing_backups; then
            details_log="All existing backups verified successfully."
        else
            overall_status="error"
            details_log="Backup verification failed."
        fi
    elif [[ "$DB_ONLY" == "true" ]]; then
        if perform_database_backup; then
            details_log="Database backup completed successfully."
        else
            overall_status="error"
            details_log="Database backup failed."
        fi
    elif [[ "$FULL_BACKUP" == "true" ]]; then
        if perform_full_backup; then
            details_log="Full system backup completed successfully."
        else
            overall_status="error"
            details_log="Full system backup failed."
        fi
    fi

    # Generate emergency kit if requested and backup was successful
    if [[ "$EMERGENCY_KIT" == "true" && "$overall_status" == "success" ]]; then
        if generate_emergency_kit; then
            details_log="$details_log\nEmergency access kit generated successfully."
        else
            overall_status="warning"
            details_log="$details_log\nEmergency kit generation failed."
        fi
    fi

    # Send notification
    send_backup_notification "$overall_status" "$details_log"

    # Final status
    case "$overall_status" in
        "success")
            log_success "Backup operation completed successfully."
            exit 0
            ;;
        "warning")
            log_warn "Backup operation completed with warnings."
            exit 0
            ;;
        "error")
            log_error "Backup operation failed."
            exit 1
            ;;
    esac
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
