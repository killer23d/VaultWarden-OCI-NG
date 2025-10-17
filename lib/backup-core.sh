#!/usr/bin/env bash
# lib/backup-core.sh — enhanced backup core functions with WAL-awareness and resource management

set -euo pipefail

# Color scheme for consistent logging
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Internal logging functions (prefixed with _ per project convention)
_backup_log() { printf "[backup-core] %s\n" "$*" >&2; }
_backup_info() { printf "[backup-core] ${GREEN}%s${NC}\n" "$*" >&2; }
_backup_warn() { printf "[backup-core] ${YELLOW}%s${NC}\n" "$*" >&2; }
_backup_error() { printf "[backup-core][error] ${RED}%s${NC}\n" "$*" >&2; }
_backup_debug() { [ "${DEBUG:-0}" = "1" ] && printf "[backup-core][debug] ${CYAN}%s${NC}\n" "$*" >&2 || true; }
_backup_die() { _backup_error "$*"; exit 1; }

# Dependency checks
_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || _backup_die "Required command not found: $1"
}

_validate_backup_environment() {
  _backup_debug "Validating backup environment"
  _require_cmd sqlite3
  _require_cmd gpg
  _require_cmd gzip
  _require_cmd du
  _require_cmd df
  
  # Optional commands
  command -v rclone >/dev/null 2>&1 || _backup_warn "rclone not found - cloud upload disabled"
  command -v ionice >/dev/null 2>&1 || _backup_warn "ionice not found - CPU priority control disabled"
  command -v bc >/dev/null 2>&1 || _backup_warn "bc not found - advanced calculations disabled"
}

# Resource monitoring and management
check_system_resources() {
  local db_file="${1:?Database file required}"
  local out_dir="${2:?Output directory required}"
  
  _backup_debug "Checking system resources for backup operation"
  
  # Calculate database size and requirements
  local db_size_mb=$(du -m "$db_file" 2>/dev/null | cut -f1 || echo "0")
  local required_space_mb=$((db_size_mb * 4))  # DB + multiple formats + compressed + encrypted
  
  # Check available disk space
  local available_mb=$(df "$out_dir" | tail -1 | awk '{print int($4/1024)}')
  if [ "$available_mb" -lt "$required_space_mb" ]; then
    _backup_die "Insufficient disk space. Required: ${required_space_mb}MB, Available: ${available_mb}MB"
  fi
  
  _backup_info "Disk space check: ${available_mb}MB available, ${required_space_mb}MB required"
  
  # Check memory availability for compression
  local available_mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print int($7*0.8)}' || echo "1024")
  local required_mem_mb=$((db_size_mb / 4))  # Conservative estimate for compression
  
  if [ "$available_mem_mb" -lt "$required_mem_mb" ]; then
    _backup_warn "Limited memory available. Using streaming compression."
    export USE_STREAMING_COMPRESSION=1
  fi
  
  # Check CPU load
  if command -v bc >/dev/null 2>&1; then
    local cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
    local cpu_cores=$(nproc)
    local high_load_threshold=$((cpu_cores * 2))
    
    if (( $(echo "$cpu_load > $high_load_threshold" | bc -l 2>/dev/null || echo 0) )); then
      _backup_warn "High CPU load detected (${cpu_load}). Using low priority execution."
      export USE_LOW_PRIORITY=1
    fi
  fi
  
  export DB_SIZE_MB="$db_size_mb"
  _backup_debug "Database size: ${db_size_mb}MB, Resource checks complete"
}

# Intelligent timeout calculation based on database characteristics
calculate_backup_timeout() {
  local db_file="${1:?Database file required}"
  
  local db_size_mb="${DB_SIZE_MB:-$(du -m "$db_file" 2>/dev/null | cut -f1 || echo "10")}"
  local base_timeout=30
  local size_factor=$((db_size_mb / 100))  # 1 second per 100MB
  local calculated_timeout=$((base_timeout + size_factor))
  
  # Check for WAL file and adjust timeout
  local wal_file="${db_file}-wal"
  if [ -f "$wal_file" ]; then
    local wal_size_mb=$(du -m "$wal_file" 2>/dev/null | cut -f1 || echo "0")
    local wal_factor=$((wal_size_mb / 50))  # Additional time for WAL processing
    calculated_timeout=$((calculated_timeout + wal_factor))
    _backup_debug "WAL file detected (${wal_size_mb}MB), adjusting timeout"
  fi
  
  # Apply bounds: minimum 30s, maximum 600s (10 minutes)
  local timeout=$(( calculated_timeout < 30 ? 30 : (calculated_timeout > 600 ? 600 : calculated_timeout) ))
  
  _backup_debug "Calculated timeout: ${timeout}s for ${db_size_mb}MB database"
  echo "$timeout"
}

# WAL-aware database preparation
prepare_database_for_backup() {
  local db_file="${1:?Database file required}"
  local timeout="${2:-60}"
  
  _backup_debug "Preparing database for backup"
  
  # Check if database is in WAL mode
  local journal_mode
  journal_mode=$(sqlite3 "$db_file" "PRAGMA journal_mode;" 2>/dev/null || echo "unknown")
  
  if [ "$journal_mode" = "wal" ]; then
    _backup_info "Database is in WAL mode, performing pre-backup optimization"
    
    local wal_file="${db_file}-wal"
    if [ -f "$wal_file" ]; then
      local wal_size_mb=$(du -m "$wal_file" 2>/dev/null | cut -f1 || echo "0")
      _backup_info "WAL file size: ${wal_size_mb}MB"
      
      # Force checkpoint if WAL is large
      if [ "$wal_size_mb" -gt 100 ]; then
        _backup_warn "Large WAL detected (${wal_size_mb}MB), performing checkpoint"
        sqlite3 "$db_file" ".timeout $timeout" "PRAGMA wal_checkpoint(RESTART);" || {
          _backup_warn "WAL checkpoint failed, proceeding with backup (may be slower)"
          return 1
        }
        _backup_info "WAL checkpoint completed successfully"
      fi
    fi
  else
    _backup_debug "Database journal mode: $journal_mode"
  fi
  
  return 0
}

# Enhanced backup verification with comprehensive checks
verify_backup_integrity() {
  local backup_file="${1:?Backup file required}"
  local original_db="${2:-}"
  
  _backup_debug "Performing comprehensive backup integrity verification"
  
  # Basic SQLite integrity check
  if ! sqlite3 "$backup_file" "PRAGMA integrity_check;" | grep -q '^ok$'; then
    _backup_error "SQLite integrity check failed for: $backup_file"
    return 1
  fi
  
  _backup_debug "SQLite integrity check passed"
  
  # If original database provided, perform comparative verification
  if [ -n "$original_db" ] && [ -f "$original_db" ]; then
    local orig_tables backup_tables
    orig_tables=$(sqlite3 "$original_db" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "0")
    backup_tables=$(sqlite3 "$backup_file" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo "0")
    
    if [ "$orig_tables" != "$backup_tables" ]; then
      _backup_warn "Table count mismatch (original: $orig_tables, backup: $backup_tables)"
      return 1
    fi
    
    _backup_debug "Table count verification passed (${orig_tables} tables)"
    
    # Quick row count check on main tables (if accessible)
    local main_table
    main_table=$(sqlite3 "$original_db" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1;" 2>/dev/null || echo "")
    
    if [ -n "$main_table" ]; then
      local orig_rows backup_rows
      orig_rows=$(sqlite3 "$original_db" "SELECT COUNT(*) FROM \"$main_table\";" 2>/dev/null || echo "unknown")
      backup_rows=$(sqlite3 "$backup_file" "SELECT COUNT(*) FROM \"$main_table\";" 2>/dev/null || echo "unknown")
      
      if [ "$orig_rows" != "unknown" ] && [ "$backup_rows" != "unknown" ]; then
        if [ "$orig_rows" != "$backup_rows" ]; then
          _backup_warn "Row count mismatch in table '$main_table' (original: $orig_rows, backup: $backup_rows)"
          return 1
        fi
        _backup_debug "Row count verification passed for table '$main_table' (${orig_rows} rows)"
      fi
    fi
  fi
  
  _backup_info "Backup integrity verification completed successfully"
  return 0
}

# Resource-aware compression function
compress_with_resource_limits() {
  local input_file="${1:?Input file required}"
  local output_file="${2:?Output file required}"
  
  _backup_debug "Compressing with resource awareness: $(basename "$input_file")"
  
  local compress_cmd="gzip"
  local compress_args="-9"
  
  # Apply resource limits if needed
  if [ "${USE_LOW_PRIORITY:-0}" = "1" ] && command -v nice >/dev/null 2>&1 && command -v ionice >/dev/null 2>&1; then
    compress_cmd="nice -n 10 ionice -c 3 $compress_cmd"
    _backup_debug "Using low priority compression"
  fi
  
  if [ "${USE_STREAMING_COMPRESSION:-0}" = "1" ]; then
    # Streaming compression to avoid memory issues
    _backup_debug "Using streaming compression to conserve memory"
    $compress_cmd -c "$input_file" > "$output_file"
    rm -f "$input_file"
  else
    # Standard in-place compression
    $compress_cmd $compress_args "$input_file"
    mv "${input_file}.gz" "$output_file"
  fi
  
  _backup_info "Compression completed: $(basename "$output_file")"
}

# Secure encryption with improved error handling
encrypt_backup_file() {
  local input_file="${1:?Input file required}"
  local passphrase="${2:?Passphrase required}"
  local output_file="${3:-${input_file}.gpg}"
  
  _backup_debug "Encrypting backup file: $(basename "$input_file")"
  
  # Create temporary passphrase file for secure GPG operation
  local passphrase_file
  passphrase_file=$(mktemp -p "${TMPDIR:-/tmp}" backup-pass.XXXXXX)
  chmod 600 "$passphrase_file"
  echo "$passphrase" > "$passphrase_file"
  
  # Encrypt with passphrase file instead of command line
  if gpg --batch --yes --quiet --cipher-algo AES256 \
         --compress-algo 2 --symmetric \
         --passphrase-file "$passphrase_file" \
         --output "$output_file" \
         "$input_file"; then
    
    # Secure cleanup
    shred -u "$passphrase_file" 2>/dev/null || rm -f "$passphrase_file"
    shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
    
    _backup_info "Encryption completed: $(basename "$output_file")"
    return 0
  else
    # Cleanup on failure
    shred -u "$passphrase_file" 2>/dev/null || rm -f "$passphrase_file"
    rm -f "$output_file"
    _backup_error "Encryption failed for: $(basename "$input_file")"
    return 1
  fi
}

# Initialize backup core functions
init_backup_core() {
  _backup_debug "Initializing backup core functions"
  _validate_backup_environment
  
  # Set default values for resource management
  export USE_STREAMING_COMPRESSION="${USE_STREAMING_COMPRESSION:-0}"
  export USE_LOW_PRIORITY="${USE_LOW_PRIORITY:-0}"
  export DEBUG="${DEBUG:-0}"
  
  _backup_info "Backup core initialization completed"
}
