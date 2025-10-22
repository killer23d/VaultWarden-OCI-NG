#!/usr/bin/env bash
# lib/backup-core.sh - Core backup and restoration functionality

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[backup-core.sh][INFO] $*"; }
    log_warn() { echo "[backup-core.sh][WARN] $*"; }
    log_error() { echo "[backup-core.sh][ERROR] $*" >&2; }
    log_success() { echo "[backup-core.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    log_header() { echo "=== $* ==="; }
fi

# Source additional libraries
for lib in config constants system sops; do
    if [[ -f "$LIB_DIR/${lib}.sh" ]]; then
        # shellcheck source=/dev/null
        source "$LIB_DIR/${lib}.sh"
    else
        log_warn "Optional library not found: lib/${lib}.sh"
    fi
done

# P3 FIX: Set consistent logging prefix
_set_log_prefix "backup-core"

# --- Configuration Constants ---
readonly BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
readonly FULL_BACKUP_RETENTION_WEEKS="${FULL_BACKUP_RETENTION_WEEKS:-4}"

# --- Core Backup Functions ---

# Validate backup prerequisites
validate_backup_environment() {
    _log_section "Validating Backup Environment"
    local errors=0

    # Check Age key
    if [[ ! -f "${AGE_KEY_FILE:-secrets/keys/age-key.txt}" ]]; then
        log_error "Age encryption key not found: ${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
        ((errors++))
    fi

    # Check backup directory
    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    if [[ ! -d "$backup_dir" ]]; then
        log_info "Creating backup directory: $backup_dir"
        mkdir -p "$backup_dir" || {
            log_error "Failed to create backup directory: $backup_dir"
            ((errors++))
        }
    fi

    # Check required commands
    local required_commands=("age" "tar" "gzip" "sqlite3" "find")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            ((errors++))
        fi
    done

    if [[ $errors -eq 0 ]]; then
        log_success "Backup environment validation passed."
        return 0
    else
        log_error "Backup environment validation failed with $errors error(s)."
        return 1
    fi
}

# Create encrypted database backup
create_database_backup() {
    local backup_name="${1:-vaultwarden-db-backup}"
    local timestamp="${2:-$(date +%Y%m%d-%H%M%S)}"

    _log_section "Creating Database Backup"

    local db_path="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/db.sqlite3"
    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    local backup_file="$backup_dir/${backup_name}-${timestamp}.sqlite3.gz.age"

    if [[ ! -f "$db_path" ]]; then
        log_error "Database file not found: $db_path"
        return 1
    fi

    log_info "Creating database backup..."
    log_info "Source: $db_path"
    log_info "Target: $backup_file"

    # Verify database integrity before backup
    log_info "Verifying database integrity..."
    if ! sqlite3 "$db_path" "PRAGMA integrity_check;" | grep -q "ok"; then
        log_error "Database integrity check failed. Backup may contain corrupted data."
        return 1
    fi

    # Create backup with compression and encryption
    local age_key_file="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"

    if sqlite3 "$db_path" ".backup /dev/stdout" | \
       gzip | \
       age -r "$(age-keygen -y "$age_key_file")" > "$backup_file"; then

        local backup_size
        backup_size=$(du -h "$backup_file" | cut -f1)
        log_success "Database backup created: $backup_file ($backup_size)"

        # Verify backup integrity
        if verify_backup_integrity "$backup_file"; then
            log_success "Backup integrity verification passed."
            return 0
        else
            log_error "Backup integrity verification failed."
            rm -f "$backup_file"
            return 1
        fi
    else
        log_error "Database backup creation failed."
        rm -f "$backup_file" # Clean up partial file
        return 1
    fi
}

# Create full system backup
create_full_system_backup() {
    local backup_name="${1:-vaultwarden-full-backup}"
    local timestamp="${2:-$(date +%Y%m%d-%H%M%S)}"

    _log_section "Creating Full System Backup"

    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    local backup_file="$backup_dir/${backup_name}-${timestamp}.tar.gz.age"
    local temp_archive="/tmp/vaultwarden-full-backup.$$.tar.gz"

    # Ensure temp file cleanup
    trap 'rm -f "$temp_archive"' RETURN

    log_info "Creating full system backup..."
    log_info "Target: $backup_file"

    # Create temporary archive
    log_info "Archiving system files..."

    local include_paths=(
        ".env"
        ".sops.yaml"
        "docker-compose.yml"
        "caddy/Caddyfile"
        "caddy/cloudflare-ips.caddy"
        "fail2ban"
        "secrets/secrets.yaml"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata"
    )

    # Build tar command with existing files only
    local tar_args=("tar" "-czf" "$temp_archive" "-C" "$PROJECT_ROOT")

    for path in "${include_paths[@]}"; do
        if [[ -e "$PROJECT_ROOT/$path" ]]; then
            tar_args+=("$path")
        else
            log_warn "Skipping missing path: $path"
        fi
    done

    # Create archive
    if "${tar_args[@]}"; then
        log_success "Archive created: $temp_archive"
    else
        log_error "Failed to create system archive."
        return 1
    fi

    # Encrypt archive
    log_info "Encrypting archive..."
    local age_key_file="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"

    if age -r "$(age-keygen -y "$age_key_file")" -o "$backup_file" "$temp_archive"; then
        local backup_size
        backup_size=$(du -h "$backup_file" | cut -f1)
        log_success "Full system backup created: $backup_file ($backup_size)"

        # Verify backup integrity
        if verify_backup_integrity "$backup_file"; then
            log_success "Backup integrity verification passed."
            return 0
        else
            log_error "Backup integrity verification failed."
            rm -f "$backup_file"
            return 1
        fi
    else
        log_error "Failed to encrypt system backup."
        return 1
    fi
}

# Verify backup file integrity
verify_backup_integrity() {
    local backup_file="$1"

    _log_debug "Verifying backup integrity: $backup_file"

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi

    local age_key_file="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"

    # Test decryption and compression
    case "$backup_file" in
        *.sqlite3.gz.age)
            # Database backup: decrypt + decompress + basic validation
            if age -d -i "$age_key_file" "$backup_file" | gzip -t >/dev/null 2>&1; then
                _log_debug "Database backup integrity check passed: $backup_file"
                return 0
            else
                log_error "Database backup integrity check failed: $backup_file"
                return 1
            fi
            ;;
        *.tar.gz.age)
            # Full backup: decrypt + tar test
            if age -d -i "$age_key_file" "$backup_file" | tar -tz >/dev/null 2>&1; then
                _log_debug "Full backup integrity check passed: $backup_file"
                return 0
            else
                log_error "Full backup integrity check failed: $backup_file"
                return 1
            fi
            ;;
        *)
            log_warn "Unknown backup format, skipping integrity check: $backup_file"
            return 0
            ;;
    esac
}

# Enforce backup retention policies
enforce_backup_retention() {
    _log_section "Enforcing Backup Retention Policies"

    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"

    if [[ ! -d "$backup_dir" ]]; then
        log_warn "Backup directory not found: $backup_dir"
        return 1
    fi

    # Clean old database backups (daily retention)
    log_info "Cleaning database backups older than $BACKUP_RETENTION_DAYS days..."
    local db_cleaned
    db_cleaned=$(find "$backup_dir" -name "*-db-backup-*.sqlite3.gz.age" -type f -mtime +$BACKUP_RETENTION_DAYS -delete -print | wc -l)
    log_info "Removed $db_cleaned old database backup(s)."

    # Clean old full backups (weekly retention)
    log_info "Cleaning full backups older than $((FULL_BACKUP_RETENTION_WEEKS * 7)) days..."
    local full_cleaned
    full_cleaned=$(find "$backup_dir" -name "*-full-backup-*.tar.gz.age" -type f -mtime +$((FULL_BACKUP_RETENTION_WEEKS * 7)) -delete -print | wc -l)
    log_info "Removed $full_cleaned old full backup(s)."

    # Show current backup status
    local current_db_backups current_full_backups
    current_db_backups=$(find "$backup_dir" -name "*-db-backup-*.sqlite3.gz.age" -type f | wc -l)
    current_full_backups=$(find "$backup_dir" -name "*-full-backup-*.tar.gz.age" -type f | wc -l)

    log_info "Current backup inventory:"
    log_info "  Database backups: $current_db_backups"
    log_info "  Full backups: $current_full_backups"

    return 0
}

# List available backups with details
list_available_backups() {
    _log_section "Available Backups"

    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"

    if [[ ! -d "$backup_dir" ]]; then
        log_warn "Backup directory not found: $backup_dir"
        return 1
    fi

    echo
    echo "Database Backups:"
    echo "=================="

    while IFS= read -r -d '' backup_file; do
        local size timestamp status
        size=$(du -h "$backup_file" | cut -f1)
        timestamp=$(stat -c "%y" "$backup_file" | cut -d' ' -f1,2 | cut -d'.' -f1)

        if verify_backup_integrity "$backup_file" >/dev/null 2>&1; then
            status="✓ Valid"
        else
            status="✗ Invalid"
        fi

        echo "  $(basename "$backup_file") - $size - $timestamp - $status"
    done < <(find "$backup_dir" -name "*-db-backup-*.sqlite3.gz.age" -type f -print0 | sort -z)

    echo
    echo "Full System Backups:"
    echo "===================="

    while IFS= read -r -d '' backup_file; do
        local size timestamp status
        size=$(du -h "$backup_file" | cut -f1)
        timestamp=$(stat -c "%y" "$backup_file" | cut -d'.' -f1)

        if verify_backup_integrity "$backup_file" >/dev/null 2>&1; then
            status="✓ Valid"
        else
            status="✗ Invalid"
        fi

        echo "  $(basename "$backup_file") - $size - $timestamp - $status"
    done < <(find "$backup_dir" -name "*-full-backup-*.tar.gz.age" -type f -print0 | sort -z)

    echo
    return 0
}

# Get backup statistics
get_backup_statistics() {
    local backup_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"

    if [[ ! -d "$backup_dir" ]]; then
        echo "0:0:0:0"  # db_count:full_count:total_size_mb:valid_count
        return 1
    fi

    local db_count full_count total_size_kb valid_count=0

    db_count=$(find "$backup_dir" -name "*-db-backup-*.sqlite3.gz.age" -type f | wc -l)
    full_count=$(find "$backup_dir" -name "*-full-backup-*.tar.gz.age" -type f | wc -l)

    # Calculate total size
    total_size_kb=$(find "$backup_dir" -name "*.age" -type f -exec du -k {} + | awk '{sum+=$1} END {print sum+0}')
    local total_size_mb=$((total_size_kb / 1024))

    # Count valid backups (quick check)
    while IFS= read -r -d '' backup_file; do
        if verify_backup_integrity "$backup_file" >/dev/null 2>&1; then
            ((valid_count++))
        fi
    done < <(find "$backup_dir" -name "*.age" -type f -print0)

    echo "$db_count:$full_count:$total_size_mb:$valid_count"
}

# --- Script Execution ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     log_warn "lib/backup-core.sh is a library and should be sourced, not executed directly."
     log_info "Available functions:"
     log_info "  - validate_backup_environment"
     log_info "  - create_database_backup [name] [timestamp]"
     log_info "  - create_full_system_backup [name] [timestamp]"
     log_info "  - verify_backup_integrity <backup_file>"
     log_info "  - enforce_backup_retention"
     log_info "  - list_available_backups"
     log_info "  - get_backup_statistics"
     log_info "Running backup statistics demo..."

     # Demo: show backup statistics if directory exists
     echo "Current backup statistics: $(get_backup_statistics)"
else
      _log_debug "lib/backup-core.sh loaded successfully as a library."
fi
