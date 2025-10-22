#!/usr/bin/env bash
# tools/backup-recovery.sh - Backup validation and recovery for VaultWarden-OCI-NG

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
source "lib/config.sh" # Needed for PROJECT_STATE_DIR, AGE_KEY_FILE
# Explicitly load config data
load_config || { log_error "Failed to load configuration. Aborting."; exit 1; }

# Source sops library for AGE_KEY_FILE constant (if needed, though config.sh might handle it)
# source "lib/sops.sh" # Usually not needed directly if config.sh loads it

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Help Text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG Backup Recovery & Validation
USAGE:
    sudo $0 [OPTIONS] [BACKUP_FILE] # Sudo likely needed for restore
DESCRIPTION:
    Validates the integrity of encrypted backups or performs a system restore.
    Requires the Age private key and potentially sudo privileges for restore.
OPTIONS:
    --help           Show this help message
    --verify         (Default) Verify backup file integrity and contents.
                     Requires Age key access but not necessarily sudo.
    --restore        Restore from the specified backup file.
                     Requires confirmation, Age key access, and likely sudo.
    BACKUP_FILE      Path to the encrypted backup file (.age). If omitted,
                     verification defaults to the latest backup found.
EOF
}

# --- Argument Parsing ---
OPERATION="verify"
BACKUP_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --restore) OPERATION="restore"; shift ;;
        --verify) OPERATION="verify"; shift ;;
        -*) log_error "Unknown option: $1"; show_help; exit 1 ;;
        *)
            # Capture the first non-option argument as the backup file
            if [[ -z "$BACKUP_FILE" ]]; then
                BACKUP_FILE="$1"
            else
                log_error "Multiple backup files specified ('$BACKUP_FILE' and '$1'). Please provide only one."
                show_help
                exit 1
            fi
            shift
            ;;
    esac
done

# --- Functions ---

# Verifies the integrity of a backup file by decrypting and checking its contents
verify_backup() {
    log_info "Verifying backup file: $(basename "$BACKUP_FILE")"
    local errors=0
    # Use a secure temporary directory within the project or state dir if possible
    local temp_base="${PROJECT_STATE_DIR:-/tmp}"
    local temp_dir
    temp_dir=$(mktemp -d "${temp_base}/vw-verify-XXXXXX") || { log_error "Cannot create temporary directory in ${temp_base}"; return 1; }
    # Ensure temp dir is cleaned up securely
    trap 'log_info "Cleaning up temporary verification directory..."; shred -uzn 3 "$temp_dir"/* 2>/dev/null; rm -rf "$temp_dir"' EXIT INT TERM

    # Check dependencies needed for verification
    if ! command -v age >/dev/null || ! command -v gzip >/dev/null || ! command -v tar >/dev/null || ! command -v sqlite3 >/dev/null; then
         log_error "Missing required command (age, gzip, tar, or sqlite3). Cannot verify backup."
         return 1
    fi

    # Check Age key file existence and permissions (use constant from sops/config)
    local age_key="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
    if [[ ! -f "$age_key" ]]; then log_error "Age key file not found: $age_key"; return 1; fi
    if ! [[ "$(stat -c "%a" "$age_key" 2>/dev/null)" =~ ^[46]00$ ]]; then # Allow 400 or 600
         log_warn "Age key permissions are not 600 or 400. Decryption might fail."
         # Allow continuing, age might handle it depending on user context
    fi

    # 1. Test Decryption
    log_info "Attempting decryption..."
    if ! age -d -i "$age_key" "$BACKUP_FILE" > "$temp_dir/decrypted.gz" 2>/dev/null; then
        log_error "Decryption failed. Check your Age key ('$age_key') or backup file integrity."
        # Don't return yet, cleanup trap will run
        return 1
    fi
    log_success "Decryption successful."

    # 2. Test Decompression and Integrity based on file type
    if [[ "$BACKUP_FILE" =~ \.tar\.gz\.age$ ]]; then # Full Backup
        log_info "Backup type: Full System Archive"
        # Test gzip integrity
        if ! gzip -t "$temp_dir/decrypted.gz"; then
             log_error "Gzip integrity check failed. Compressed archive is corrupt."
             ((errors++))
        else
            log_success "Gzip integrity check passed."
            # Test tar listing
            log_info "Listing archive contents..."
            if ! tar -tvf <(gunzip -c "$temp_dir/decrypted.gz") > "$temp_dir/contents.list"; then
                log_error "Tar archive listing failed. Archive structure might be corrupt."
                ((errors++))
            else
                log_success "Tar archive listing successful."
                log_info "Contents:"
                # Indent contents list
                sed 's/^/  /' "$temp_dir/contents.list"
            fi
        fi
    elif [[ "$BACKUP_FILE" =~ \.sqlite3\.gz\.age$ ]]; then # DB Backup
        log_info "Backup type: Database (SQLite)"
        # Test gzip integrity
         if ! gzip -t "$temp_dir/decrypted.gz"; then
              log_error "Gzip integrity check failed. Compressed database is corrupt."
              ((errors++))
         else
             log_success "Gzip integrity check passed."
             # Decompress for SQLite check
             log_info "Decompressing database for integrity check..."
             if ! gunzip -c "$temp_dir/decrypted.gz" > "$temp_dir/db.sqlite3"; then
                  log_error "Failed to decompress database file."
                  ((errors++))
             else
                 # Check SQLite integrity
                 log_info "Running SQLite integrity check..."
                 local integrity_output
                 integrity_output=$(sqlite3 "$temp_dir/db.sqlite3" "PRAGMA integrity_check;" 2>&1)
                 if [[ "$integrity_output" == "ok" ]]; then
                     log_success "SQLite database integrity check passed."
                 else
                     log_error "SQLite database integrity check failed. Database file is corrupt."
                     log_error "Details: $integrity_output"
                     ((errors++))
                 fi
                 # Securely delete the decompressed DB after check (handled by trap)
             fi
         fi
    else
        log_warn "Unknown backup format based on filename: $(basename "$BACKUP_FILE"). Cannot perform detailed integrity check beyond decryption."
        # No error increment, just warning
    fi

    # Cleanup handled by trap

    if [[ $errors -eq 0 ]]; then
        log_success "Backup verification completed successfully."
        return 0
    else
        log_error "Backup verification failed with $errors error(s)."
        return 1
    fi
}

# Performs a full system restore from a backup file
perform_restore() {
    # Ensure sudo privileges for restore
    if [[ $EUID -ne 0 ]]; then
        log_error "Restore operation requires root privileges (sudo)."
        exit 1
    fi

    log_warn "You are about to perform a system restore from: $(basename "$BACKUP_FILE")"
    log_warn "This will STOP all Vaultwarden services and OVERWRITE current data and configuration."
    log_warn "Ensure you have backed up any recent changes not included in this backup file."
    # Use log_confirm if available, otherwise read
    local confirm_func="_log_confirm"
    if ! declare -f "$confirm_func" > /dev/null; then confirm_func="read -p"; fi
    "$confirm_func" "Type 'YES' to proceed with the restore: " "NO"
    if [[ "${REPLY:-NO}" != "YES" ]]; then
        log_info "Restore cancelled by user."
        exit 0
    fi

    # Verify backup integrity before attempting restore
    log_info "Verifying backup integrity before restore..."
    if ! verify_backup; then
        log_error "Backup verification failed. Restore aborted for safety."
        exit 1
    fi
    log_success "Backup verification passed. Proceeding with restore."

    log_info "Stopping Vaultwarden services..."
    # Use docker compose down from project root
    if ! (cd "$PROJECT_ROOT" && docker compose down --remove-orphans); then
         log_warn "Failed to stop services cleanly. Continuing restore attempt..."
         # Kill remaining containers? Risky. Proceed cautiously.
         # docker ps -q --filter "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME:-vaultwarden}" | xargs -r docker kill
    fi

    # Create an emergency backup of the current state directory
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    local emergency_backup_dir="$PROJECT_ROOT/backups/emergency-restore-backup-$(date +%Y%m%d_%H%M%S)"
    log_info "Backing up current state directory '$state_dir' to '$emergency_backup_dir'..."
    mkdir -p "$emergency_backup_dir" || { log_error "Cannot create emergency backup directory. Aborting."; exit 1; }
    # Use rsync for better handling of permissions and potential errors
    if rsync -a --info=progress2 "$state_dir/" "$emergency_backup_dir/state_backup/" && \
       rsync -a --info=progress2 "$PROJECT_ROOT/secrets/" "$emergency_backup_dir/secrets_backup/" && \
       rsync -a --info=progress2 "$PROJECT_ROOT/.env" "$emergency_backup_dir/" 2>/dev/null; then
        log_success "Current state backed up to '$emergency_backup_dir'."
    else
        log_warn "Failed to create complete emergency backup of current state. Some files might be missing in '$emergency_backup_dir'."
        # Ask user if they want to continue despite backup failure? Or abort? Abort safer.
         read -p "Emergency backup failed. Continue restore anyway? (y/N): " -r continue_restore
         if [[ ! "$continue_restore" =~ ^[Yy]$ ]]; then
             log_error "Restore aborted due to failed emergency backup."
             exit 1
         fi
         log_warn "Proceeding with restore despite failed emergency backup!"
    fi


    log_info "Restoring files from backup: $(basename "$BACKUP_FILE")"
    local age_key="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
    local restore_errors=0

    if [[ "$BACKUP_FILE" =~ \.tar\.gz\.age$ ]]; then # Full Backup
        log_info "Restoring Full System Backup..."
        # Restore directly into project root, overwriting existing config files
        # Extract requires appropriate permissions (running as root/sudo)
        # Use --numeric-owner to preserve numeric UIDs/GIDs from backup if possible
        if ! age -d -i "$age_key" "$BACKUP_FILE" | tar -xzvf - -C "$PROJECT_ROOT" --numeric-owner; then
            log_error "Failed to extract full backup archive. System may be in an inconsistent state."
            restore_errors=1
        else
            log_success "Files extracted successfully."
            # Verify extracted structure (basic check)
             if [[ ! -d "$PROJECT_ROOT/data/bwdata" || ! -f "$PROJECT_ROOT/config/Caddyfile" ]]; then # Check for expected paths post-extraction
                 log_warn "Extracted files might be incomplete or in unexpected locations."
                 # Maybe check tar listing again?
             fi
             # Fix permissions after extraction (ensure ownership is correct for running user if needed, scripts executable)
             log_info "Adjusting permissions after restore..."
             chown -R "${SUDO_USER:-root}:${SUDO_GROUP:-root}" "$PROJECT_ROOT" # Set ownership to user running sudo
             find "$PROJECT_ROOT/tools" "$PROJECT_ROOT/lib" -name "*.sh" -exec chmod 750 {} \;
             chmod 750 "$PROJECT_ROOT/startup.sh"
             chmod 600 "$PROJECT_ROOT/secrets/keys/age-key.txt" # Ensure key perm is correct
        fi
    elif [[ "$BACKUP_FILE" =~ \.sqlite3\.gz\.age$ ]]; then # DB Backup
        log_info "Restoring Database Only Backup..."
        local db_path="$state_dir/data/bwdata/db.sqlite3"
        log_info "Target database path: $db_path"
        # Ensure target directory exists
        mkdir -p "$(dirname "$db_path")" || { log_error "Cannot create database directory. Aborting."; exit 1; }
        # Decrypt and decompress directly to the target file
        if ! age -d -i "$age_key" "$BACKUP_FILE" | gunzip -c > "$db_path"; then
             log_error "Failed to decrypt or decompress database backup to '$db_path'."
             rm -f "$db_path" # Clean up potentially corrupt file
             restore_errors=1
        else
             log_success "Database file restored."
             # Verify integrity of restored DB
             log_info "Verifying restored database integrity..."
              local integrity_output
              integrity_output=$(sqlite3 "$db_path" "PRAGMA integrity_check;" 2>&1)
              if [[ "$integrity_output" == "ok" ]]; then
                  log_success "Restored database integrity check passed."
                  # Set correct ownership for container (e.g., 1000:1000)
                  log_info "Setting database file ownership..."
                  chown 1000:1000 "$db_path" || log_warn "Failed to set ownership on database file."
              else
                   log_error "Restored database integrity check FAILED: $integrity_output"
                   log_error "Database file might be corrupt. Restore aborted before service start."
                   restore_errors=1
              fi
        fi
    else
        log_error "Unsupported backup file type for restore: $(basename "$BACKUP_FILE")"
        restore_errors=1
    fi

    if [[ $restore_errors -ne 0 ]]; then
         log_error "Restore process failed. System may be inconsistent."
         log_info "Your previous state (before restore attempt) might be in '$emergency_backup_dir'."
         log_info "Manual recovery may be required."
         exit 1
    fi


    log_success "Restore process completed. Starting services..."
    # Start services using startup.sh from project root
    if ! (cd "$PROJECT_ROOT" && ./startup.sh); then
        log_error "Failed to start services after restore. Please check logs ('docker compose logs')."
        log_info "Your previous state (before restore attempt) might be in '$emergency_backup_dir'."
        exit 1
    fi

    # Post-start health check
    log_info "Waiting a moment before post-restore health check..."
    sleep 30
    log_info "Running post-restore health check..."
    if ! (cd "$PROJECT_ROOT" && ./tools/check-health.sh); then
        log_warn "Post-restore health check reported issues. Please review service logs ('docker compose logs')."
    else
        log_success "Post-restore health check passed."
    fi

    log_success "System restored and services are running."
    log_info "Consider generating a new Emergency Kit now."
}


# --- Main Execution ---
main() {
    # Find latest backup if file not specified and operation is verify
    if [[ -z "$BACKUP_FILE" && "$OPERATION" == "verify" ]]; then
         log_info "No backup file specified, attempting to verify the latest backup..."
         # Look in both db and full directories, find the newest .age file overall
         BACKUP_FILE=$(find "$PROJECT_ROOT/backups/db" "$PROJECT_ROOT/backups/full" -maxdepth 1 -type f -name "*.age" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-)
         if [[ -z "$BACKUP_FILE" ]]; then
             log_error "No backup files found in backups/db or backups/full directories."
             exit 1
         fi
         log_info "Found latest backup: $(basename "$BACKUP_FILE")"
    elif [[ -z "$BACKUP_FILE" ]]; then
        log_error "No backup file specified for the '$OPERATION' operation."
        show_help
        exit 1
    fi

    # Ensure absolute path or resolve relative path correctly
    if [[ ! "$BACKUP_FILE" == /* ]]; then
        BACKUP_FILE="$PROJECT_ROOT/$BACKUP_FILE"
    fi

    if [[ ! -f "$BACKUP_FILE" ]]; then
        log_error "Backup file not found at resolved path: $BACKUP_FILE"
        exit 1
    fi

    log_header "VaultWarden Backup Utility"
    # Configuration loaded at the top

    # Execute selected operation
    if [[ "$OPERATION" == "restore" ]]; then
        perform_restore
    else
        verify_backup
    fi

    # Exit with status code from operation
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_success "Operation '$OPERATION' completed successfully."
    else
        log_error "Operation '$OPERATION' failed."
    fi
    exit $exit_code
}

# Run main, handle potential errors during setup
main "$@"
