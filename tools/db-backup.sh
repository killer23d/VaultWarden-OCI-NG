#!/usr/bin/env bash
# tools/db-backup.sh — Simplified SQLite backup with SOPS+Age integration and WAL-awareness

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB_DIR="$ROOT_DIR/lib"

# Load libraries in dependency order
source "$LIB_DIR/logging.sh"
source "$LIB_DIR/config.sh"
source "$LIB_DIR/backup-core.sh" 
source "$LIB_DIR/backup-formats.sh"

# Load SOPS integration if available
SOPS_AVAILABLE=false
if [[ -f "$LIB_DIR/sops.sh" ]]; then
    source "$LIB_DIR/sops.sh"
    SOPS_AVAILABLE=true
fi

# Set log prefix for this script
_set_log_prefix "db-backup"

# Enhanced backup initialization with SOPS
init_enhanced_backup() {
    _log_info "Initializing database backup system..."
    
    if ! load_config; then
        _log_error "Failed to load configuration"
        exit 1
    fi
    
    init_backup_core

    local backup_passphrase=""
    if [[ "$SOPS_AVAILABLE" == "true" ]] && [[ "$SECRETS_LOADED" == "true" ]]; then
        if backup_passphrase=$(get_secret "backup_passphrase" 2>/dev/null); then
            _log_success "Using backup passphrase from SOPS encrypted secrets"
        fi
    fi
    
    if [[ -z "$backup_passphrase" ]]; then
        _log_error "BACKUP_PASSPHRASE not found in SOPS secrets."
        exit 1
    fi
    
    export BACKUP_PASSPHRASE="$backup_passphrase"

    _detect_database_path || exit 1
    
    [[ -f "$DB_FILE" ]] || { _log_error "SQLite database not found at $DB_FILE"; exit 1; }

    TS="$(date +%Y%m%d-%H%M%S)"
    OUT_DIR="${BACKUP_DIR:-$PROJECT_STATE_DIR/backups/db}/$TS"
    mkdir -p "$OUT_DIR"

    _log_success "Backup initialized - Output: $OUT_DIR"
}

# Get DB path from config
_detect_database_path() {
    local db_url
    if ! db_url=$(get_config_value "DATABASE_URL"); then
        _log_error "DATABASE_URL not found in configuration."
        return 1
    fi

    if [[ "$db_url" =~ ^sqlite://(.+) ]]; then
        local relative_path="${BASH_REMATCH[1]}"
        DB_FILE="$PROJECT_STATE_DIR/data/bwdata/${relative_path#/data/}"
        _log_info "Detected database path from config: $DB_FILE"
    else
        _log_error "Unsupported DATABASE_URL format: $db_url"
        return 1
    fi
    return 0
}

perform_enhanced_backup() {
    _log_info "Starting database backup process"
    check_system_resources "$DB_FILE" "$OUT_DIR"

    if ! create_diverse_backups "$DB_FILE" "$OUT_DIR" "$TS"; then
        _log_error "Backup creation failed"
        exit 1
    fi

    _log_info "Compressing and encrypting backup file..."

    local encrypted_files=()
    local failures=()

    while IFS= read -r -d '' backup_file; do
        if [[ -f "$backup_file" && "$backup_file" != */manifest.json ]]; then
            local base_name="$_set_log_prefix "db-backup""
            _log_debug "Processing: $base_name"

            local compressed_file="${backup_file}.gz"
            if compress_with_resource_limits "$backup_file" "$compressed_file"; then
                local encrypted_file="${compressed_file}.gpg"
                if encrypt_backup_file "$compressed_file" "$BACKUP_PASSPHRASE" "$encrypted_file"; then
                    encrypted_files+=("$encrypted_file")
                    rm -f "$backup_file" "$compressed_file"
                else
                    failures+=("$base_name (encryption)")
                fi
            else
                failures+=("$base_name (compression)")
            fi
        fi
    done < <(find "$OUT_DIR" -maxdepth 1 -type f -print0)
    
    [[ ${#failures[@]} -gt 0 ]] && _log_warning "Some files failed processing: ${failures[*]}"
}

main() {
    local start_time end_time duration
    start_time="$(date +%s)"
    _log_header "VaultWarden Database Backup"

    init_enhanced_backup
    perform_enhanced_backup

    manage_backup_retention

    end_time="$(date +%s)"
    duration=$((end_time - start_time))
    _log_header "Backup Complete"
    _log_info "Duration: ${duration}s | Output: $OUT_DIR"
    
    local total_size
    total_size="$(du -sh "$OUT_DIR" | cut -f1)"
    _log_info "Total backup size: $total_size"
}

main "$@"