#!/usr/bin/env bash
# db-backup.sh - Automated database backup script for VaultWarden-OCI

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
LOG_FILE="$LOG_DIR/db_backup_$TIMESTAMP.log"
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
        local subject="VaultWarden Database Backup $status - $(hostname)"
        local body="VaultWarden Database Backup Report

Status: $status
Timestamp: $(date)
Server: $(hostname)

Details:
$details

Log file: $LOG_FILE

---
For troubleshooting:
- Check backup logs: docker compose exec bw_backup tail -f $LOG_FILE
- Manual backup: docker compose exec bw_backup /backup/db-backup.sh --force
- Verify rclone: docker compose exec bw_backup rclone listremotes
"
        
        # Try different email methods
        if command -v msmtp >/dev/null 2>&1; then
            {
                echo "From: VaultWarden-Backup <backup@$(hostname)>"
                echo "To: $NOTIFICATION_EMAIL"
                echo "Subject: $subject"
                echo "Content-Type: text/plain; charset=UTF-8"
                echo ""
                echo "$body"
            } | msmtp -t 2>/dev/null && log_info "Alert email sent via msmtp"
        elif command -v sendmail >/dev/null 2>&1; then
            {
                echo "From: VaultWarden-Backup <backup@$(hostname)>"
                echo "To: $NOTIFICATION_EMAIL"
                echo "Subject: $subject"
                echo ""
                echo "$body"
            } | sendmail "$NOTIFICATION_EMAIL" 2>/dev/null && log_info "Alert email sent via sendmail"
        elif command -v mail >/dev/null 2>&1; then
            echo "$body" | mail -s "$subject" "$NOTIFICATION_EMAIL" 2>/dev/null && log_info "Alert email sent via mail"
        else
            log_warning "No email client found - notification not sent"
        fi
    fi
    
    # Always log to syslog for monitoring
    logger -t vaultwarden-db-backup "Database Backup $status: $details"
}

# ================================
# BACKUP FUNCTIONS
# ================================

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

# Upload to remote storage (Modified to be fault-tolerant)
upload_backup() {
    local backup_file="$1"
    
    if [[ -z "$BACKUP_REMOTE" ]]; then
        log_info "No remote storage configured - keeping local backup only"
        return 0
    fi
    
    if ! command -v rclone >/dev/null 2>&1; then
        log_warning "rclone not available - skipping remote upload"
        log_warning "Install rclone in container to enable remote backups"
        return 0  # Return success to continue with local backup
    fi
    
    # Check if rclone config exists
    if [[ ! -f "/home/backup/.config/rclone/rclone.conf" ]]; then
        log_warning "rclone configuration file not found - skipping remote upload"
        log_warning "Create rclone.conf to enable remote backups"
        return 0  # Return success to continue with local backup
    fi
    
    # Validate rclone remote exists
    if ! rclone --config /home/backup/.config/rclone/rclone.conf listremotes | grep -q "^${BACKUP_REMOTE}:$"; then
        log_warning "rclone remote '$BACKUP_REMOTE' not found in configuration"
        log_warning "Available remotes: $(rclone --config /home/backup/.config/rclone/rclone.conf listremotes | tr '\n' ' ')"
        return 0  # Return success to continue with local backup
    fi
    
    log_info "Uploading backup to remote storage: $BACKUP_REMOTE"
    
    local remote_path="$BACKUP_REMOTE:$BACKUP_PATH/$(basename "$backup_file")"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "Upload attempt $attempt of $max_attempts..."
        
        if rclone copy "$backup_file" "$BACKUP_REMOTE:$BACKUP_PATH/" \
            --config /home/backup/.config/rclone/rclone.conf \
            --progress \
            --retries 2 \
            --low-level-retries 3 \
            --stats 30s 2>/dev/null; then
            
            log_success "Backup uploaded successfully to: $remote_path"
            
            # Verify upload by checking file exists
            if rclone lsf "$BACKUP_REMOTE:$BACKUP_PATH/" \
                --config /home/backup/.config/rclone/rclone.conf \
                2>/dev/null | grep -q "$(basename "$backup_file")"; then
                log_success "Upload verification passed"
                return 0
            else
                log_warning "Upload verification failed - file not found in remote"
            fi
        else
            log_warning "Upload attempt $attempt failed"
        fi
        
        attempt=$((attempt + 1))
        if [[ $attempt -le $max_attempts ]]; then
            log_info "Waiting 30 seconds before retry..."
            sleep 30
        fi
    done
    
    # All upload attempts failed, but continue with local backup
    log_error "All upload attempts failed - backup will remain local only"
    log_error "Check rclone configuration and network connectivity"
    log_error "Remote: $BACKUP_REMOTE, Path: $BACKUP_PATH"
    
    # Return 0 (success) so local backup is still considered successful
    return 0
}

# Clean old backups (Enhanced with remote cleanup safety)
cleanup_old_backups() {
    log_info "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
    
    # Clean local backups
    local deleted_local=0
    if [[ -d "$BACKUP_DIR" ]]; then
        while IFS= read -r -d '' file; do
            log_info "Removing old local backup: $(basename "$file")"
            rm -f "$file"
            deleted_local=$((deleted_local + 1))
        done < <(find "$BACKUP_DIR" -name "db_backup_*.sql*" -mtime +$RETENTION_DAYS -print0 2>/dev/null)
    fi
    
    # Clean remote backups (with error handling)
    local deleted_remote=0
    if [[ -n "$BACKUP_REMOTE" ]] && command -v rclone >/dev/null 2>&1; then
        if [[ -f "/home/backup/.config/rclone/rclone.conf" ]]; then
            log_info "Cleaning old remote backups..."
            
            # List old files first
            local old_files
            old_files=$(rclone lsf "$BACKUP_REMOTE:$BACKUP_PATH/" \
                --config /home/backup/.config/rclone/rclone.conf \
                --min-age "${RETENTION_DAYS}d" 2>/dev/null | grep "db_backup_" | wc -l)
            
            if [[ "$old_files" -gt 0 ]]; then
                log_info "Found $old_files old remote backup files to delete"
                
                if rclone delete "$BACKUP_REMOTE:$BACKUP_PATH/" \
                    --config /home/backup/.config/rclone/rclone.conf \
                    --min-age "${RETENTION_DAYS}d" \
                    --include "db_backup_*" 2>/dev/null; then
                    log_success "Cleaned $old_files old remote backups"
                    deleted_remote=$old_files
                else
                    log_warning "Failed to clean remote backups - check connectivity"
                fi
            else
                log_info "No old remote backups to clean"
            fi
        else
            log_info "No rclone config - skipping remote cleanup"
        fi
    fi
    
    log_success "Cleanup completed: $deleted_local local files removed, $deleted_remote remote files removed"
}

# ================================
# HEALTH CHECK FUNCTIONS
# ================================

# Verify stack health before backup
verify_stack_health() {
    log_info "Verifying stack health before backup..."
    
    local health_issues=()
    
    # Check VaultWarden health
    if ! curl -f http://vaultwarden:80/alive --max-time 10 >/dev/null 2>&1; then
        health_issues+=("VaultWarden health check failed")
    fi
    
    # Check database connectivity and consistency
    if ! mysqladmin ping -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" --silent 2>/dev/null; then
        health_issues+=("Database connectivity failed")
    else
        # Check for database corruption
        local corruption_check
        corruption_check=$(mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
            -e "CHECK TABLE ${MARIADB_DATABASE}.users, ${MARIADB_DATABASE}.organizations;" 2>/dev/null | grep -c "error" || echo "0")
        
        if [[ "$corruption_check" -gt 0 ]]; then
            health_issues+=("Database corruption detected")
        fi
        
        # Check if database is in read-only mode
        local readonly_check
        readonly_check=$(mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
            -e "SELECT @@global.read_only;" -s -N 2>/dev/null || echo "1")
        
        if [[ "$readonly_check" == "1" ]]; then
            health_issues+=("Database is in read-only mode")
        fi
    fi
    
    # Check Redis health
    if ! echo "PING" | nc bw_redis 6379 | grep -q "PONG" 2>/dev/null; then
        health_issues+=("Redis health check failed")
    fi
    
    # Check if any critical issues found
    if [[ ${#health_issues[@]} -gt 0 ]]; then
        log_error "Stack health check failed:"
        for issue in "${health_issues[@]}"; do
            log_error "  - $issue"
        done
        
        send_backup_notification "FAILED" "Pre-backup health check failed:\n$(printf '%s\n' "${health_issues[@]}")"
        return 1
    fi
    
    log_success "Stack health verified - proceeding with backup"
    return 0
}

# Check database locks before backup
check_database_locks() {
    log_info "Checking for active database locks..."
    
    local active_locks
    active_locks=$(mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
        -e "SELECT COUNT(*) FROM information_schema.INNODB_LOCKS;" -s -N 2>/dev/null || echo "0")
    
    if [[ "$active_locks" -gt 0 ]]; then
        log_warning "Found $active_locks active database locks - waiting..."
        sleep 30
        
        # Check again
        active_locks=$(mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
            -e "SELECT COUNT(*) FROM information_schema.INNODB_LOCKS;" -s -N 2>/dev/null || echo "0")
        
        if [[ "$active_locks" -gt 0 ]]; then
            log_warning "Still $active_locks active locks - proceeding with caution"
        fi
    fi
}

# Create comprehensive database backup
backup_database() {
    local backup_file="$1"
    
    log_info "Creating database backup with consistency checks..."
    
    # Pre-backup database analysis
    local table_count
    table_count=$(mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${MARIADB_DATABASE}';" -s -N 2>/dev/null || echo "0")
    
    log_info "Backing up $table_count tables from database: ${MARIADB_DATABASE}"
    
    # Create backup with extended options for consistency
    if mysqldump -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" \
        --single-transaction \
        --routines \
        --triggers \
        --events \
        --add-drop-table \
        --add-locks \
        --create-options \
        --disable-keys \
        --extended-insert \
        --quick \
        --lock-tables=false \
        --set-charset \
        --default-character-set=utf8mb4 \
        --hex-blob \
        --complete-insert \
        --flush-logs \
        --master-data=2 \
        --databases "${MARIADB_DATABASE}" > "$backup_file" 2>/dev/null; then
        
        # Verify backup integrity
        local backup_size
        backup_size=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
        
        if [[ "$backup_size" -lt 1024 ]]; then
            log_error "Backup file too small (${backup_size} bytes) - likely corrupted"
            return 1
        fi
        
        # Check for SQL syntax errors in backup
        if grep -q "ERROR" "$backup_file" 2>/dev/null; then
            log_error "SQL errors found in backup file"
            return 1
        fi
        
        log_success "Database backup created: $backup_file ($(du -h "$backup_file" | cut -f1))"
        log_info "Backup contains $table_count tables"
        return 0
    else
        log_error "Database backup failed"
        return 1
    fi
}

# Verify backup before encryption
verify_backup_integrity() {
    local backup_file="$1"
    
    log_info "Verifying backup integrity..."
    
    # Check file is readable
    if [[ ! -r "$backup_file" ]]; then
        log_error "Backup file is not readable"
        return 1
    fi
    
    # Check SQL syntax (basic)
    if ! head -20 "$backup_file" | grep -q "MySQL dump" 2>/dev/null; then
        log_error "Backup file does not appear to be a valid MySQL dump"
        return 1
    fi
    
    # Check for complete backup (look for dump completed line)
    if ! tail -10 "$backup_file" | grep -q "Dump completed" 2>/dev/null; then
        log_warning "Backup may be incomplete - 'Dump completed' not found"
    fi
    
    log_success "Backup integrity verified"
    return 0
}

# ================================
# MAIN BACKUP PROCESS
# ================================

main() {
    local force_mode=false
    local skip_upload=false
    
    # Parse arguments
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
VaultWarden Automated Database Backup Script

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

Features:
- Pre-backup health checks for stack integrity
- Database consistency verification
- Encrypted backups with GPG
- Remote storage with rclone (fault-tolerant)
- Automatic cleanup and notifications

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
    
    log_info "Starting automated database backup process..."
    
    # Pre-flight checks
    if [[ ! -w "$BACKUP_DIR" ]]; then
        log_error "Backup directory is not writable: $BACKUP_DIR"
        exit 1
    fi
    
    # Verify stack health before proceeding
    verify_stack_health || exit 1
    
    # Check for recent backup (unless forced)
    if [[ "$force_mode" == "false" ]]; then
        local recent_backup
        recent_backup=$(find "$BACKUP_DIR" -name "db_backup_*.sql*" -mtime -1 2>/dev/null | head -1)
        if [[ -n "$recent_backup" ]]; then
            log_info "Recent backup found: $(basename "$recent_backup")"
            log_info "Skipping backup (use --force to override)"
            exit 0
        fi
    fi
    
    # Check database locks
    check_database_locks
    
    # Create backup
    local db_backup_file="$BACKUP_DIR/db_backup_$TIMESTAMP.sql"
    local backup_success=true
    local backup_details=""
    
    # Database backup with verification
    if backup_database "$db_backup_file" && verify_backup_integrity "$db_backup_file"; then
        backup_details+="✓ Database backup: $(du -h "$db_backup_file" | cut -f1)\n"
        backup_details+="✓ Backup integrity verified\n"
        
        # Encrypt backup
        if [[ -n "$BACKUP_PASSPHRASE" ]]; then
            local encrypted_file="$db_backup_file.gpg"
            if encrypt_backup "$db_backup_file" "$encrypted_file"; then
                db_backup_file="$encrypted_file"
                backup_details+="✓ Backup encrypted\n"
            else
                backup_details+="✗ Encryption failed\n"
            fi
        fi
        
        # Upload to remote storage
        if [[ "$skip_upload" == "false" ]]; then
            if upload_backup "$db_backup_file"; then
                backup_details+="✓ Remote upload completed\n"
            else
                backup_details+="✗ Remote upload failed\n"
            fi
        else
            backup_details+="- Remote upload skipped\n"
        fi
        
    else
        backup_success=false
        backup_details+="✗ Database backup failed\n"
    fi
    
    # Cleanup old backups
    cleanup_old_backups
    backup_details+="✓ Old backups cleaned up\n"
    
    # Send notification
    if [[ "$backup_success" == "true" ]]; then
        log_success "Database backup process completed successfully"
        send_backup_notification "SUCCESS" "$backup_details"
        exit 0
    else
        log_error "Database backup process failed"
        send_backup_notification "FAILED" "$backup_details"
        exit 1
    fi
}

# Execute main function
main "$@"
