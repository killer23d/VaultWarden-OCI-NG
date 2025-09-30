#!/usr/bin/env bash
# restore.sh - Database restore script for VaultWarden-OCI

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
LOG_DIR="${LOG_DIR:-/var/log/backup}"
RESTORE_LOG="$LOG_DIR/restore_$(date +%Y%m%d_%H%M%S).log"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" | tee -a "$RESTORE_LOG"
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" | tee -a "$RESTORE_LOG"
}

log_warning() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" | tee -a "$RESTORE_LOG"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" | tee -a "$RESTORE_LOG"
    exit 1
}

# List available backups
list_backups() {
    log_info "Available backups in $BACKUP_DIR:"
    
    if [[ -d "$BACKUP_DIR" ]]; then
        local backups
        backups=$(find "$BACKUP_DIR" -name "db_backup_*.sql*" -type f | sort -r)
        
        if [[ -n "$backups" ]]; then
            local count=0
            while IFS= read -r backup; do
                count=$((count + 1))
                local size age
                size=$(du -h "$backup" | cut -f1)
                age=$(stat -c %y "$backup" | cut -d' ' -f1)
                printf "%2d. %-50s %8s %s\n" "$count" "$(basename "$backup")" "$size" "$age"
            done <<< "$backups"
        else
            log_warning "No database backups found"
        fi
    else
        log_error "Backup directory not found: $BACKUP_DIR"
    fi
}

# Decrypt backup if encrypted
decrypt_backup() {
    local encrypted_file="$1"
    local output_file="$2"
    
    if [[ "$encrypted_file" == *.gpg ]]; then
        log_info "Decrypting backup file..."
        
        if [[ -z "${BACKUP_PASSPHRASE:-}" ]]; then
            read -s -p "Enter backup passphrase: " BACKUP_PASSPHRASE
            echo
        fi
        
        if echo "$BACKUP_PASSPHRASE" | gpg --batch --quiet --decrypt --passphrase-fd 0 "$encrypted_file" > "$output_file"; then
            log_success "Backup decrypted successfully"
            return 0
        else
            log_error "Failed to decrypt backup"
            return 1
        fi
    else
        # Not encrypted, just copy
        cp "$encrypted_file" "$output_file"
        return 0
    fi
}

# Restore database
restore_database() {
    local backup_file="$1"
    local confirm="${2:-true}"
    
    log_info "Preparing to restore database from: $(basename "$backup_file")"
    
    # Confirmation prompt
    if [[ "$confirm" == "true" ]]; then
        echo ""
        echo "⚠️  WARNING: This will COMPLETELY REPLACE your current database!"
        echo "   All existing data will be PERMANENTLY LOST!"
        echo ""
        echo "   Backup file: $(basename "$backup_file")"
        echo "   File size:   $(du -h "$backup_file" | cut -f1)"
        echo "   File date:   $(stat -c %y "$backup_file" | cut -d' ' -f1)"
        echo ""
        read -p "Are you absolutely sure you want to continue? (yes/NO): " confirm_restore
        
        if [[ "$confirm_restore" != "yes" ]]; then
            log_info "Restore cancelled by user"
            exit 0
        fi
    fi
    
    # Check if file needs decryption
    local temp_dir
    temp_dir=$(mktemp -d)
    local sql_file="$temp_dir/restore.sql"
    
    # Cleanup function
    cleanup() {
        rm -rf "$temp_dir"
    }
    trap cleanup EXIT
    
    # Decrypt if needed
    if ! decrypt_backup "$backup_file" "$sql_file"; then
        log_error "Failed to prepare backup file for restore"
    fi
    
    # Verify SQL file
    log_info "Verifying backup file integrity..."
    
    if ! head -20 "$sql_file" | grep -q "MySQL dump"; then
        log_error "Backup file does not appear to be a valid MySQL dump"
    fi
    
    local table_count
    table_count=$(grep -c "CREATE TABLE" "$sql_file" || echo "0")
    log_info "Backup contains $table_count tables"
    
    if [[ "$table_count" -eq 0 ]]; then
        log_error "Backup file contains no tables - may be corrupted"
    fi
    
    # Stop VaultWarden to prevent database access during restore
    log_info "Stopping VaultWarden service..."
    if docker stop vaultwarden 2>/dev/null; then
        log_success "VaultWarden stopped"
    else
        log_warning "Could not stop VaultWarden (may not be running)"
    fi
    
    # Wait for connections to close
    log_info "Waiting for database connections to close..."
    sleep 10
    
    # Perform restore
    log_info "Restoring database from backup..."
    
    if mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" < "$sql_file"; then
        log_success "Database restored successfully"
    else
        log_error "Database restore failed"
    fi
    
    # Restart VaultWarden
    log_info "Starting VaultWarden service..."
    if docker start vaultwarden 2>/dev/null; then
        log_success "VaultWarden started"
        
        # Wait for service to be ready
        log_info "Waiting for VaultWarden to be ready..."
        local attempts=0
        while [[ $attempts -lt 30 ]]; do
            if curl -f http://vaultwarden:80/alive --max-time 5 >/dev/null 2>&1; then
                log_success "VaultWarden is ready"
                break
            fi
            attempts=$((attempts + 1))
            sleep 5
        done
        
        if [[ $attempts -eq 30 ]]; then
            log_warning "VaultWarden may not be fully ready yet"
        fi
    else
        log_warning "Could not start VaultWarden - start manually"
    fi
    
    log_success "Database restore completed!"
    log_info "Restore log: $RESTORE_LOG"
}

# Main function
main() {
    mkdir -p "$LOG_DIR"
    
    local backup_file=""
    local list_only=false
    local no_confirm=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--list)
                list_only=true
                shift
                ;;
            -f|--file)
                backup_file="$2"
                shift 2
                ;;
            -y|--yes)
                no_confirm=true
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden Database Restore Script

Usage: $0 [OPTIONS]

Options:
    -l, --list          List available backups
    -f, --file FILE     Restore specific backup file
    -y, --yes           Skip confirmation prompt
    -h, --help          Show this help message

Examples:
    $0 --list                                    # List backups
    $0 --file db_backup_20250930_020015.sql.gpg # Restore specific backup
    $0                                           # Interactive restore

Environment Variables:
    BACKUP_PASSPHRASE   Passphrase for encrypted backups
    MARIADB_USER        Database username
    MARIADB_PASSWORD    Database password

⚠️  WARNING: This script will COMPLETELY REPLACE your database!
    Make sure you have a current backup before proceeding.

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    log_info "Starting database restore process..."
    
    # List backups if requested
    if [[ "$list_only" == "true" ]]; then
        list_backups
        exit 0
    fi
    
    # Interactive backup selection if no file specified
    if [[ -z "$backup_file" ]]; then
        echo "Available backups:"
        list_backups
        echo ""
        read -p "Enter backup number or full path: " backup_choice
        
        if [[ "$backup_choice" =~ ^[0-9]+$ ]]; then
            # User selected by number
            local backups_array
            readarray -t backups_array < <(find "$BACKUP_DIR" -name "db_backup_*.sql*" -type f | sort -r)
            
            if [[ "$backup_choice" -le "${#backups_array[@]}" ]] && [[ "$backup_choice" -gt 0 ]]; then
                backup_file="${backups_array[$((backup_choice - 1))]}"
            else
                log_error "Invalid backup number: $backup_choice"
            fi
        else
            # User provided full path
            backup_file="$backup_choice"
        fi
    fi
    
    # Validate backup file
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
    fi
    
    # Ensure we have database credentials
    if [[ -z "${MARIADB_USER:-}" ]] || [[ -z "${MARIADB_PASSWORD:-}" ]]; then
        log_error "Database credentials not set. Set MARIADB_USER and MARIADB_PASSWORD environment variables."
    fi
    
    # Perform restore
    local confirm="true"
    if [[ "$no_confirm" == "true" ]]; then
        confirm="false"
    fi
    
    restore_database "$backup_file" "$confirm"
}

# Execute main function
main "$@"
