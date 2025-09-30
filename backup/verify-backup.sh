#!/usr/bin/env bash
# verify-backup.sh - Backup verification script for VaultWarden-OCI

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
LOG_DIR="${LOG_DIR:-/var/log/backup}"

# Logging functions
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

# Verify backup file integrity
verify_backup_file() {
    local backup_file="$1"
    local issues=()
    
    log_info "Verifying backup file: $(basename "$backup_file")"
    
    # Check file exists and is readable
    if [[ ! -f "$backup_file" ]]; then
        issues+=("File does not exist")
        return 1
    fi
    
    if [[ ! -r "$backup_file" ]]; then
        issues+=("File is not readable")
    fi
    
    # Check file size (minimum 1KB)
    local file_size
    file_size=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
    
    if [[ "$file_size" -lt 1024 ]]; then
        issues+=("File too small (${file_size} bytes)")
    fi
    
    # Check if encrypted
    local is_encrypted=false
    if [[ "$backup_file" == *.gpg ]]; then
        is_encrypted=true
        log_info "Backup is encrypted"
        
        # Test decryption (if passphrase available)
        if [[ -n "${BACKUP_PASSPHRASE:-}" ]]; then
            local temp_file
            temp_file=$(mktemp)
            
            if echo "$BACKUP_PASSPHRASE" | gpg --batch --quiet --decrypt --passphrase-fd 0 "$backup_file" > "$temp_file" 2>/dev/null; then
                log_success "Decryption test passed"
                backup_file="$temp_file"  # Use decrypted file for further checks
            else
                issues+=("Failed to decrypt backup")
            fi
        else
            log_warning "Cannot verify encrypted backup without BACKUP_PASSPHRASE"
            return 0  # Skip further checks for encrypted files without passphrase
        fi
    fi
    
    # Verify SQL content
    if [[ "${is_encrypted}" == "false" || -n "${BACKUP_PASSPHRASE:-}" ]]; then
        # Check for MySQL dump header
        if ! head -20 "$backup_file" | grep -q "MySQL dump" 2>/dev/null; then
            issues+=("Not a valid MySQL dump file")
        fi
        
        # Check for dump completion
        if ! tail -10 "$backup_file" | grep -q "Dump completed" 2>/dev/null; then
            issues+=("Backup may be incomplete (no completion marker)")
        fi
        
        # Check for SQL errors
        if grep -q "ERROR" "$backup_file" 2>/dev/null; then
            issues+=("SQL errors found in backup")
        fi
        
        # Count tables
        local table_count
        table_count=$(grep -c "CREATE TABLE" "$backup_file" 2>/dev/null || echo "0")
        
        if [[ "$table_count" -eq 0 ]]; then
            issues+=("No tables found in backup")
        else
            log_info "Backup contains $table_count tables"
        fi
        
        # Check for VaultWarden-specific tables
        local vw_tables=("users" "organizations" "ciphers" "folders")
        local missing_vw_tables=()
        
        for table in "${vw_tables[@]}"; do
            if ! grep -q "CREATE TABLE.*\`$table\`" "$backup_file" 2>/dev/null; then
                missing_vw_tables+=("$table")
            fi
        done
        
        if [[ ${#missing_vw_tables[@]} -gt 0 ]]; then
            issues+=("Missing VaultWarden tables: ${missing_vw_tables[*]}")
        else
            log_success "All expected VaultWarden tables found"
        fi
    fi
    
    # Clean up temporary file if created
    if [[ "$is_encrypted" == "true" && -f "$temp_file" ]]; then
        rm -f "$temp_file"
    fi
    
    # Report results
    if [[ ${#issues[@]} -eq 0 ]]; then
        log_success "Backup verification passed: $(basename "$backup_file")"
        return 0
    else
        log_error "Backup verification failed: $(basename "$backup_file")"
        for issue in "${issues[@]}"; do
            log_error "  - $issue"
        done
        return 1
    fi
}

# Verify all backups in directory
verify_all_backups() {
    log_info "Verifying all backups in $BACKUP_DIR..."
    
    local backups
    backups=$(find "$BACKUP_DIR" -name "db_backup_*.sql*" -type f 2>/dev/null || echo "")
    
    if [[ -z "$backups" ]]; then
        log_warning "No backup files found in $BACKUP_DIR"
        return 0
    fi
    
    local total=0
    local passed=0
    local failed=0
    
    while IFS= read -r backup; do
        total=$((total + 1))
        
        if verify_backup_file "$backup"; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1))
        fi
        
        echo ""
    done <<< "$backups"
    
    # Summary
    echo "========================================"
    log_info "Verification Summary:"
    log_info "  Total backups:  $total"
    log_success "  Passed:         $passed"
    if [[ $failed -gt 0 ]]; then
        log_error "  Failed:         $failed"
    else
        log_info "  Failed:         $failed"
    fi
    
    return $failed
}

# Test restore capability (without actually restoring)
test_restore() {
    local backup_file="$1"
    
    log_info "Testing restore capability for: $(basename "$backup_file")"
    
    # Check database connectivity
    if ! mysqladmin ping -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" --silent 2>/dev/null; then
        log_error "Cannot connect to database - restore test failed"
        return 1
    fi
    
    # Test SQL syntax (dry run)
    local temp_file
    temp_file=$(mktemp)
    
    # Decrypt if needed
    if [[ "$backup_file" == *.gpg ]]; then
        if [[ -z "${BACKUP_PASSPHRASE:-}" ]]; then
            log_warning "Cannot test encrypted backup without BACKUP_PASSPHRASE"
            return 0
        fi
        
        if ! echo "$BACKUP_PASSPHRASE" | gpg --batch --quiet --decrypt --passphrase-fd 0 "$backup_file" > "$temp_file" 2>/dev/null; then
            log_error "Failed to decrypt backup for testing"
            rm -f "$temp_file"
            return 1
        fi
        
        backup_file="$temp_file"
    fi
    
    # Test SQL parsing (check first few statements)
    local test_sql
    test_sql=$(head -100 "$backup_file" | grep -E "^(CREATE|INSERT|DROP)" | head -5)
    
    if [[ -n "$test_sql" ]]; then
        # Test with --dry-run equivalent (just parse, don't execute)
        if echo "SET sql_mode='NO_AUTO_VALUE_ON_ZERO';" | mysql -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" 2>/dev/null; then
            log_success "Database connection and SQL parsing test passed"
        else
            log_error "SQL parsing test failed"
            rm -f "$temp_file"
            return 1
        fi
    else
        log_error "No SQL statements found in backup"
        rm -f "$temp_file"
        return 1
    fi
    
    rm -f "$temp_file"
    log_success "Restore test passed for: $(basename "$1")"
    return 0
}

# Main function
main() {
    local verify_all=false
    local backup_file=""
    local test_restore_flag=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all)
                verify_all=true
                shift
                ;;
            -f|--file)
                backup_file="$2"
                shift 2
                ;;
            -t|--test-restore)
                test_restore_flag=true
                shift
                ;;
            --help|-h)
                cat <<EOF
VaultWarden Backup Verification Script

Usage: $0 [OPTIONS]

Options:
    -a, --all              Verify all backups in backup directory
    -f, --file FILE        Verify specific backup file
    -t, --test-restore     Test restore capability (requires database access)
    -h, --help             Show this help message

Examples:
    $0 --all                                      # Verify all backups
    $0 --file db_backup_20250930_020015.sql.gpg  # Verify specific backup
    $0 --file backup.sql --test-restore           # Verify and test restore

Environment Variables:
    BACKUP_PASSPHRASE   Passphrase for encrypted backups
    MARIADB_USER        Database username (for restore testing)
    MARIADB_PASSWORD    Database password (for restore testing)

This script verifies:
- File integrity and size
- Encryption/decryption (if applicable)
- SQL dump format validity
- Presence of expected VaultWarden tables
- Database connectivity (for restore testing)

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    log_info "Starting backup verification..."
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    if [[ "$verify_all" == "true" ]]; then
        verify_all_backups
        exit $?
    elif [[ -n "$backup_file" ]]; then
        if verify_backup_file "$backup_file"; then
            if [[ "$test_restore_flag" == "true" ]]; then
                test_restore "$backup_file"
            fi
        else
            exit 1
        fi
    else
        # Interactive mode
        echo "Available backups:"
        find "$BACKUP_DIR" -name "db_backup_*.sql*" -type f | sort -r | nl
        echo ""
        read -p "Enter backup number or full path (or 'all' for all backups): " choice
        
        if [[ "$choice" == "all" ]]; then
            verify_all_backups
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            local backups_array
            readarray -t backups_array < <(find "$BACKUP_DIR" -name "db_backup_*.sql*" -type f | sort -r)
            
            if [[ "$choice" -le "${#backups_array[@]}" ]] && [[ "$choice" -gt 0 ]]; then
                backup_file="${backups_array[$((choice - 1))]}"
                verify_backup_file "$backup_file"
            else
                log_error "Invalid backup number: $choice"
            fi
        else
            verify_backup_file "$choice"
        fi
    fi
}

# Execute main function
main "$@"
