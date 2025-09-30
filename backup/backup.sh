#!/usr/bin/env bash
# backup.sh - Fully automated backup script for VaultWarden-OCI

set -euo pipefail

# Configuration from environment
BACKUP_DIR="${BACKUP_DIR:-/backups}"
LOG_DIR="${LOG_DIR:-/var/log/backup}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
BACKUP_PASSPHRASE="${BACKUP_PASSPHRASE:-}"
BACKUP_REMOTE="${BACKUP_REMOTE:-}"
BACKUP_PATH="${BACKUP_PATH:-vaultwarden-backups}"
NOTIFICATION_EMAIL="${BACKUP_EMAIL:-${ALERT_EMAIL:-}}"

# Logging setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/backup_$TIMESTAMP.log"
mkdir -p "$LOG_DIR"

# Redirect all output to log file and console
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# ================================
# LOGGING FUNCTIONS
# ================================

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
}

log_warning() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
}

# ================================
# NOTIFICATION FUNCTIONS
# ================================

send_backup_notification() {
    local status="$1"
    local details="$2"
    
    if [[ -n "$NOTIFICATION_EMAIL" ]]; then
        local subject="VaultWarden Backup $status - $(hostname)"
        local body="VaultWarden Backup Report

Status: $status
Timestamp: $(date)
Server: $(hostname)

Details:
$details

Log file: $LOG_FILE
"
        
        # Try different email methods
        if command -v msmtp >/dev/null 2>&1; then
            {
                echo "From: VaultWarden-Backup <backup@$(hostname)>"
                echo "To: $NOTIFICATION_EMAIL"
                echo "Subject: $subject"
                echo ""
                echo "$body"
            } | msmtp -t 2>/dev/null || log_warning "Failed to send email via msmtp"
        elif command -v mail >/dev/null 2>&1; then
            echo "$body" | mail -s "$subject" "$NOTIFICATION_EMAIL" 2>/dev/null || log_warning "Failed to send email via mail"
        fi
    fi
    
    # Always log to syslog for monitoring
    logger -t vaultwarden-backup "Backup $status: $details"
}

# ================================
# BACKUP FUNCTIONS
# ================================

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for database to be ready..."
    
    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if mysqladmin ping -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" --silent 2>/dev/null; then
            log_success "Database is ready"
            return 0
        fi
        
        attempt=$((attempt + 1))
        log_info "Waiting for database... (attempt $attempt/$max_attempts)"
        sleep 10
    done
    
    log_error "Database not ready after $max_attempts attempts"
    return 1
}

# Create database backup
backup_database() {
    local backup_file="$1"
    
    log_info "Creating database backup..."
    
    if mysqldump -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
        --single-transaction --routines --triggers --all-databases \
        --add-drop-table --add-locks --create-options \
        --disable-keys --extended-insert --quick \
        --set-charset > "$backup_file" 2>/dev/null; then
        
        log_success "Database backup created: $backup_file"
        return 0
    else
        log_error "Database backup failed"
        return 1
    fi
}

# Create file backup
backup_files() {
    local backup_file="$1"
    
    log_info "Creating file backup..."
    
    # Files to backup
    local backup_sources=(
        "/data"  # VaultWarden data
    )
    
    if tar -czf "$backup_file" "${backup_sources[@]}" 2>/dev/null; then
        log_success "File backup created: $backup_file"
        return 0
    else
        log_error "File backup failed"
        return 1
    fi
}

# Encrypt backup
encrypt_backup() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ -z "$BACKUP_PASSPHRASE" ]]; then
        log_warning "No encryption passphrase provided - backup will not be encrypted"
        mv "$input_file" "$output_file"
        return 0
    fi
    
    log_info "Encrypting backup..."
    
    if echo "$BACKUP_PASSPHRASE" | gpg --batch --yes --quiet --cipher-algo AES256 \
        --compress-algo 2 --compress-level 6 --symmetric --passphrase-fd 0 \
        --output "$output_file" "$input_file" 2>/dev/null; then
        
        rm -f "$input_file"  # Remove unencrypted version
        log_success "Backup encrypted: $output_file"
        return 0
    else
        log_error "Backup encryption failed"
        return 1
    fi
}

# Upload to remote storage
upload_backup() {
    local backup_file="$1"
    
    if [[ -z "$BACKUP_REMOTE" ]]; then
        log_info "No remote storage configured - keeping local backup only"
        return 0
    fi
    
    if ! command -v rclone >/dev/null 2>&1; then
        log_warning "rclone not available - skipping remote upload"
        return 1
    fi
    
    log_info "Uploading backup to remote storage..."
    
    local remote_path="$BACKUP_REMOTE:$BACKUP_PATH/$(basename "$backup_file")"
    
    if rclone copy "$backup_file" "$BACKUP_REMOTE:$BACKUP_PATH/" --progress 2>/dev/null; then
        log_success "Backup uploaded to: $remote_path"
        return 0
    else
        log_error "Remote upload failed"
        return 1
    fi
}

# Clean old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
    
    # Clean local backups
    local deleted_local=0
    if [[ -d "$BACKUP_DIR" ]]; then
        while IFS= read -r -d '' file; do
            rm -f "$file"
            deleted_local=$((deleted_local + 1))
        done < <(find "$BACKUP_DIR" -name "backup_*.tar.gz*" -mtime +$RETENTION_DAYS -print0 2>/dev/null)
    fi
    
    # Clean remote backups
    local deleted_remote=0
    if [[ -n "$BACKUP_REMOTE" ]] && command -v rclone >/dev/null 2>&1; then
        # List old files and delete them
        rclone delete "$BACKUP_REMOTE:$BACKUP_PATH/" --min-age "${RETENTION_DAYS}d" 2>/dev/null || log_warning "Failed to clean remote backups"
        deleted_remote="unknown"
    fi
    
    log_success "Cleanup completed: $deleted_local local files removed"
}

# ================================
# MAIN BACKUP PROCESS
# ================================

main() {
    local force_mode=false
    local skip_upload=false
    
    # Parse arguments (for manual runs)
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--force)
                force_mode=true
                shift
                ;;
            -n|--no-upload)
                skip_upload=true
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden Automated Backup Script

Usage: $0 [OPTIONS]

Options:
    -f, --force      Force backup even if recent backup exists
    -n, --no-upload  Skip remote upload (local backup only)
    -h, --help       Show this help message

Environment Variables:
    BACKUP_RETENTION_DAYS    Days to keep backups (default: 30)
    BACKUP_PASSPHRASE        Encryption passphrase (recommended)
    BACKUP_REMOTE            rclone remote name
    BACKUP_PATH              Remote path for backups
    BACKUP_EMAIL             Email for notifications

This script is designed to run automatically via cron.
No interactive prompts - fully automated operation.

EOF
                exit 0
                ;;
            *)
                log_warning "Unknown argument: $1"
                shift
                ;;
        esac
    done
    
    log_info "Starting automated backup process..."
    
    # Pre-flight checks
    if [[ ! -w "$BACKUP_DIR" ]]; then
        log_error "Backup directory is not writable: $BACKUP_DIR"
        exit 1
    fi
    
    # Check for recent backup (unless forced)
    if [[ "$force_mode" == "false" ]]; then
        local recent_backup
        recent_backup=$(find "$BACKUP_DIR" -name "backup_*.tar.gz*" -mtime -1 2>/dev/null | head -1)
        if [[ -n "$recent_backup" ]]; then
            log_info "Recent backup found: $(basename "$recent_backup")"
            log_info "Skipping backup (use --force to override)"
            exit 0
        fi
    fi
    
    # Wait for services
    wait_for_services || {
        send_backup_notification "FAILED" "Services not ready"
        exit 1
    }
    
    # Create backup files
    local db_backup_file="$BACKUP_DIR/database_$TIMESTAMP.sql"
    local files_backup_file="$BACKUP_DIR/files_$TIMESTAMP.tar.gz"
    local final_backup_file="$BACKUP_DIR/backup_$TIMESTAMP.tar.gz"
    
    local backup_success=true
    local backup_details=""
    
    # Database backup
    if backup_database "$db_backup_file"; then
        backup_details+="✓ Database backup: $(du -h "$db_backup_file" | cut -f1)\n"
    else
        backup_success=false
        backup_details+="✗ Database backup failed\n"
    fi
    
    # Files backup
    if backup_files "$files_backup_file"; then
        backup_details+="✓ Files backup: $(du -h "$files_backup_file" | cut -f1)\n"
    else
        backup_success=false
        backup_details+="✗ Files backup failed\n"
    fi
    
    # Combine backups
    if [[ "$backup_success" == "true" ]]; then
        log_info "Combining backups..."
        if tar -czf "$final_backup_file" -C "$BACKUP_DIR" \
            "$(basename "$db_backup_file")" "$(basename "$files_backup_file")" 2>/dev/null; then
            
            # Remove individual backup files
            rm -f "$db_backup_file" "$files_backup_file"
            
            # Encrypt if passphrase provided
            local encrypted_file="$final_backup_file.gpg"
            if [[ -n "$BACKUP_PASSPHRASE" ]]; then
                if encrypt_backup "$final_backup_file" "$encrypted_file"; then
                    final_backup_file="$encrypted_file"
                    backup_details+="✓ Backup encrypted\n"
                else
                    backup_details+="✗ Encryption failed\n"
                fi
            fi
            
            backup_details+="✓ Final backup: $(du -h "$final_backup_file" | cut -f1)\n"
            
            # Upload to remote storage
            if [[ "$skip_upload" == "false" ]]; then
                if upload_backup "$final_backup_file"; then
                    backup_details+="✓ Remote upload completed\n"
                else
                    backup_details+="✗ Remote upload failed\n"
                fi
            else
                backup_details+="- Remote upload skipped\n"
            fi
            
        else
            backup_success=false
            backup_details+="✗ Failed to combine backups\n"
        fi
    fi
    
    # Cleanup old backups
    cleanup_old_backups
    backup_details+="✓ Old backups cleaned up\n"
    
    # Send notification
    if [[ "$backup_success" == "true" ]]; then
        log_success "Backup process completed successfully"
        send_backup_notification "SUCCESS" "$backup_details"
        exit 0
    else
        log_error "Backup process failed"
        send_backup_notification "FAILED" "$backup_details"
        exit 1
    fi
}

# Execute main function
main "$@"
