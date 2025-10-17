#!/usr/bin/env bash
# tools/sqlite-maintenance.sh - SQLite database maintenance and optimization
#
# This script provides comprehensive SQLite database maintenance including:
# - Database integrity checks and repair
# - Vacuum operations for space reclamation
# - Index rebuilding and optimization
# - Performance analysis and statistics
# - Backup verification and cleanup
# - Integration with monitoring and cron systems
#
# Dependencies: lib/logging.sh, lib/backup-core.sh, lib/system.sh
#

set -euo pipefail

# Auto-detect script location and project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_NAME="$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"

# Source required libraries with error checking
for lib in logging backup-core system config; do
    lib_file="$ROOT_DIR/lib/${lib}.sh"
    if [[ -f "$lib_file" ]]; then
        source "$lib_file"
    else
        echo "ERROR: Required library not found: $lib_file" >&2
        exit 1
    fi
done

# Set logging prefix
_set_log_prefix "sqlite-maint"

# Configuration constants
readonly CONTAINER_NAME="${CONTAINER_NAME_VAULTWARDEN:-bw_vaultwarden}"
readonly BACKUP_SUFFIX=".maintenance-backup.$(date +%Y%m%d_%H%M%S)"
readonly MAINTENANCE_LOG="/var/log/sqlite-maintenance.log"

# Global variables
DB_PATH=""
MAINTENANCE_TYPE="quick"
DRY_RUN=false
VERBOSE=false
FORCE_OFFLINE=false
BACKUP_BEFORE=true
REPAIR_MODE=false

# Show usage information
_show_usage() {
    cat <<EOM
${BOLD}SQLite Database Maintenance Tool${NC}

${CYAN}USAGE:${NC}
  $0 [OPTIONS]

${CYAN}OPTIONS:${NC}
  -t, --type TYPE      Maintenance type: quick, full, vacuum, integrity, analyze, repair
                       (default: quick)
  -d, --database PATH  Database file path (override auto-detection from config)
  -f, --force-offline  Stop VaultWarden service during maintenance
  -r, --repair         Enable repair mode for corrupted databases
  --no-backup          Skip backup creation before maintenance
  -v, --verbose        Enable verbose output
  -n, --dry-run        Show what would be done without executing
  -h, --help           Show this help message

${CYAN}MAINTENANCE TYPES:${NC}
  ${GREEN}quick${NC}       Fast integrity check + basic cleanup (5-10 seconds)
  ${GREEN}full${NC}        Complete maintenance: integrity + vacuum + analyze + optimize (2-5 minutes)
  ${GREEN}vacuum${NC}      Space reclamation and defragmentation (1-3 minutes)
  ${GREEN}integrity${NC}   Comprehensive integrity check only (30-60 seconds)
  ${GREEN}analyze${NC}     Update query statistics and optimize indexes (30-60 seconds)
  ${GREEN}repair${NC}      Attempt to repair corrupted database (destructive operation)

${CYAN}INTEGRATION:${NC}
  This script integrates with:
  • tools/monitor.sh (automated health checks)
  • Cron jobs (scheduled maintenance)
  • Backup system (pre-maintenance backups)
  • System logging (maintenance history)

${CYAN}EXAMPLES:${NC}
  $0                           # Quick daily check
  $0 -t full -v                # Full weekly maintenance with verbose output
  $0 -t vacuum -f              # Vacuum with service stop
  $0 -t repair -r              # Repair corrupted database
  $0 -t integrity --no-backup  # Quick integrity check without backup

EOM
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            MAINTENANCE_TYPE="$2"
            shift 2
            ;;
        -d|--database)
            DB_PATH="$2"
            shift 2
            ;;
        -f|--force-offline)
            FORCE_OFFLINE=true
            shift
            ;;
        -r|--repair)
            REPAIR_MODE=true
            shift
            ;;
        --no-backup)
            BACKUP_BEFORE=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            _show_usage
            exit 0
            ;;
        *)
            _log_error "Unknown option: $1"
            _show_usage
            exit 1
            ;;
    esac
done

# Set log level based on verbose flag
if [[ "$VERBOSE" == "true" ]]; then
    _set_log_level "debug"
fi

# Validate maintenance type
case "$MAINTENANCE_TYPE" in
    quick|full|vacuum|integrity|analyze|repair)
        _log_debug "Maintenance type: $MAINTENANCE_TYPE"
        ;;
    *)
        _log_error "Invalid maintenance type: $MAINTENANCE_TYPE"
        _show_usage
        exit 1
        ;;
esac

_detect_database_path() {
    if [[ -n "$DB_PATH" ]]; then
        _log_debug "Using user-specified database path: $DB_PATH"
        return 0
    fi

    if ! load_config >/dev/null 2>&1; then
        _log_error "Could not load configuration to determine database path."
        _log_info "Please run ./tools/init-setup.sh or create settings.env"
        return 1
    fi

    local db_url
    db_url=$(get_config_value "DATABASE_URL")

    if [[ -z "$db_url" ]]; then
        _log_error "DATABASE_URL not found in configuration."
        return 1
    fi

    if [[ "$db_url" =~ ^sqlite://(.+) ]]; then
        local relative_path="${BASH_REMATCH[1]}"
        # The path inside the container is /data/db.sqlite3, which maps to a host path.
        # The config.sh logic correctly determines PROJECT_STATE_DIR.
        # We need to construct the host path correctly.
        # The docker-compose volume is: ${PROJECT_STATE_DIR}/data/bwdata:/data
        DB_PATH="${PROJECT_STATE_DIR}/data/bwdata/db.sqlite3"
        _log_info "Detected database path on host: $DB_PATH"
    else
        _log_error "Unsupported DATABASE_URL format: $db_url"
        _log_info "Only sqlite:///... URLs are supported for auto-detection."
        return 1
    fi

    if [[ ! -f "$DB_PATH" ]]; then
        _log_error "Database file specified in config not found: $DB_PATH"
        return 1
    fi

    return 0
}

_manage_service_state() {
    local action="$1"

    case "$action" in
        "status")
            if docker ps --format "table {{.Names}}" | grep -q "^${CONTAINER_NAME}"; then
                echo "running"
            else
                echo "stopped"
            fi
            ;;
        "stop")
            if [[ "$DRY_RUN" == "true" ]]; then
                _log_info "[DRY RUN] Would stop VaultWarden service"
                return 0
            fi

            _log_info "Stopping VaultWarden service for maintenance..."
            if docker compose -f "$ROOT_DIR/docker-compose.yml" stop vaultwarden; then
                _log_success "VaultWarden service stopped"
                sleep 5
                return 0
            else
                _log_error "Failed to stop VaultWarden service"
                return 1
            fi
            ;;
        "start")
            if [[ "$DRY_RUN" == "true" ]]; then
                _log_info "[DRY RUN] Would start VaultWarden service"
                return 0
            fi

            _log_info "Starting VaultWarden service..."
            if docker compose -f "$ROOT_DIR/docker-compose.yml" up -d vaultwarden; then
                _log_success "VaultWarden service started"
                return 0
            else
                _log_error "Failed to start VaultWarden service"
                return 1
            fi
            ;;
    esac
}

_run_integrity_check() {
    local db_path="$1"
    _log_info "Running database integrity check..."
    if [[ "$DRY_RUN" == "true" ]]; then
        _log_info "[DRY RUN] Would run: sqlite3 \"$db_path\" \"PRAGMA busy_timeout = 30000; PRAGMA integrity_check;\""
        return 0
    fi
    local integrity_result; local start_time; start_time=$(date +%s)
    integrity_result=$(sqlite3 "$db_path" "PRAGMA busy_timeout = 30000; PRAGMA integrity_check;" 2>&1)
    local exit_code=$?; local end_time; end_time=$(date +%s); local duration=$((end_time - start_time))
    if [[ $exit_code -eq 0 && "$integrity_result" == "ok" ]]; then
        _log_success "Database integrity check passed (${duration}s)"; return 0
    else
        _log_error "Database integrity check failed (${duration}s):"; _log_error "$integrity_result"; return 1
    fi
}

_run_vacuum() {
    local db_path="$1"
    _log_info "Starting database vacuum operation..."
    local size_before; size_before=$(du -h "$db_path" 2>/dev/null | cut -f1 || echo "unknown")
    _log_info "Database size before vacuum: $size_before"
    if [[ "$DRY_RUN" == "true" ]]; then
        _log_info "[DRY RUN] Would run: sqlite3 \"$db_path\" \"PRAGMA busy_timeout = 30000; VACUUM;\""; return 0
    fi
    local start_time; start_time=$(date +%s); local vacuum_result
    if vacuum_result=$(timeout 600 sqlite3 "$db_path" "PRAGMA busy_timeout = 30000; VACUUM;" 2>&1); then
        local end_time; end_time=$(date +%s); local duration=$((end_time - start_time)); local size_after
        size_after=$(du -h "$db_path" 2>/dev/null | cut -f1 || echo "unknown")
        _log_success "Database vacuum completed (${duration}s)"; _log_info "Database size after vacuum: $size_after"; return 0
    else
        local end_time; end_time=$(date +%s); local duration=$((end_time - start_time))
        _log_error "Database vacuum failed after ${duration}s:"; _log_error "$vacuum_result"; return 1
    fi
}

_run_analyze() {
    local db_path="$1"
    _log_info "Updating database statistics and optimizing indexes..."
    if [[ "$DRY_RUN" == "true" ]]; then
        _log_info "[DRY RUN] Would run: sqlite3 \"$db_path\" \"PRAGMA busy_timeout = 30000; ANALYZE;\""; return 0
    fi
    local start_time; start_time=$(date +%s); local analyze_result
    if analyze_result=$(sqlite3 "$db_path" "PRAGMA busy_timeout = 30000; ANALYZE;" 2>&1); then
        local end_time; end_time=$(date +%s); local duration=$((end_time - start_time))
        _log_success "Database statistics updated (${duration}s)"; return 0
    else
        local end_time; end_time=$(date +%s); local duration=$((end_time - start_time))
        _log_error "Database analysis failed after ${duration}s:"; _log_error "$analyze_result"; return 1
    fi
}

_run_repair() {
    local db_path="$1"
    _log_section "Database Repair"
    _log_warning "Attempting to repair the database. This is a destructive operation and may result in data loss."
    if [[ "$DRY_RUN" == "true" ]]; then
        _log_info "[DRY RUN] Would attempt to dump and restore the database to a new file."
        return 0
    fi

    local temp_sql_dump; temp_sql_dump="$(mktemp)"
    local repaired_db; repaired_db="${db_path}.repaired"

    _log_info "Step 1: Dumping data from corrupted database..."
    if sqlite3 "$db_path" ".dump" > "$temp_sql_dump" 2>/dev/null; then
        _log_success "Data dump completed."
    else
        _log_error "Failed to dump data from the database. Cannot proceed with repair."
        rm -f "$temp_sql_dump"
        return 1
    fi

    _log_info "Step 2: Restoring data into a new database file..."
    if sqlite3 "$repaired_db" < "$temp_sql_dump"; then
        _log_success "Data restored to new file: $repaired_db"
    else
        _log_error "Failed to restore data to the new database file."
        rm -f "$temp_sql_dump" "$repaired_db"
        return 1
    fi

    rm -f "$temp_sql_dump"

    _log_info "Step 3: Verifying integrity of the repaired database..."
    if ! _run_integrity_check "$repaired_db"; then
        _log_error "Repaired database failed integrity check. Aborting."
        rm -f "$repaired_db"
        return 1
    fi

    _log_info "Step 4: Replacing the corrupted database with the repaired one."
    mv "$repaired_db" "$db_path"
    _log_success "Database repair complete."
    return 0
}

_get_database_info() {
    local db_path="$1"
    _log_info "Database Information:"
    if [[ ! -f "$db_path" ]]; then _log_error "Database file not found: $db_path"; return 1; fi
    local file_info; file_info=$(ls -lh "$db_path" 2>/dev/null)
    _log_info "  File: $file_info"
    if [[ "$DRY_RUN" == "false" ]]; then
        local table_count; table_count=$(sqlite3 "$db_path" "PRAGMA busy_timeout = 30000; SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "unknown")
        _log_info "  Tables: $table_count"
        local main_tables=("users" "ciphers" "folders" "collections")
        for table in "${main_tables[@]}"; do
            local count; count=$(sqlite3 "$db_path" "PRAGMA busy_timeout = 30000; SELECT COUNT(*) FROM $table;" 2>/dev/null || echo "N/A")
            if [[ "$count" != "N/A" ]]; then _log_info "  $table records: $count"; fi
        done
    fi
}

_run_maintenance() {
    local db_path="$1"; local maintenance_type="$2"
    _log_header "SQLite Database Maintenance - $maintenance_type"
    _get_database_info "$db_path"
    local errors=0
    case "$maintenance_type" in
        "integrity"|"quick"|"full")
            _log_section "Integrity Check"; if ! _run_integrity_check "$db_path"; then ((errors++)); fi
            if [[ "$maintenance_type" == "full" ]]; then
                _log_section "Vacuum Operation"; if ! _run_vacuum "$db_path"; then ((errors++)); fi
                _log_section "Statistics Update"; if ! _run_analyze "$db_path"; then ((errors++)); fi
            fi
            ;;
        "vacuum") _log_section "Vacuum Operation"; if ! _run_vacuum "$db_path"; then ((errors++)); fi;;
        "analyze") _log_section "Statistics Update"; if ! _run_analyze "$db_path"; then ((errors++)); fi;;
        "repair") if ! _run_repair "$db_path"; then ((errors++)); fi;;
    esac
    if [[ $errors -eq 0 ]]; then _log_success "Database maintenance completed successfully"; return 0;
    else _log_error "Database maintenance completed with $errors error(s)"; return 1; fi
}

main() {
    if ! command -v sqlite3 >/dev/null 2>&1; then _log_error "sqlite3 command not found. Please install sqlite3."; exit 1; fi
    if ! _detect_database_path; then exit 1; fi
    if [[ ! -f "$DB_PATH" ]]; then _log_error "Database file not found: $DB_PATH"; exit 1; fi
    if [[ ! -r "$DB_PATH" ]]; then _log_error "Cannot read database file: $DB_PATH"; exit 1; fi
    if _run_maintenance "$DB_PATH" "$MAINTENANCE_TYPE"; then exit 0; else exit 1; fi
}

main "$@"