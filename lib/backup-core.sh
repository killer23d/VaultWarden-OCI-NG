#!/usr/bin/env bash
# lib/backup-core.sh — enhanced backup core functions with WAL-awareness and resource management

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing (only if needed) ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    _backup_log() { echo "[backup-core] $*"; } # Rename internal logger to avoid potential conflict
    _backup_info() { echo "[backup-core][INFO] $*"; }
    _backup_warn() { echo "[backup-core][WARN] $*"; }
    _backup_error() { echo "[backup-core][ERROR] $*" >&2; }
    _backup_debug() { :; }
    _backup_die() { _backup_error "$*"; exit 1; }
    # Define colors or leave them empty if logging.sh is missing
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' NC='' BOLD=''
fi
# Note: This script originally defined its own internal logging functions.
# They are kept but prefixed with _backup_ for clarity and to avoid conflicts if logging.sh loads successfully.
# Ideally, replace _backup_log etc. calls with standard log_info, log_error etc. later.

# --- Library functions follow ---

# Original Color scheme (kept for reference, use logging.sh versions preferably)
# readonly RED='\033[0;31m'
# readonly GREEN='\033[0;32m'
# readonly YELLOW='\033[0;33m'
# readonly BLUE='\033[0;34m'
# readonly CYAN='\033[0;36m'
# readonly NC='\033[0m' # No Color

# Internal logging functions (prefixed with _backup_ per project convention now)
_backup_log() { printf "[backup-core] %s\n" "$*" >&2; }
_backup_info() { printf "[backup-core] ${GREEN}%s${NC}\n" "$*" >&2; }
_backup_warn() { printf "[backup-core] ${YELLOW}%s${NC}\n" "$*" >&2; }
_backup_error() { printf "[backup-core][error] ${RED}%s${NC}\n" "$*" >&2; }
_backup_debug() { [[ "${DEBUG:-0}" = "1" ]] && printf "[backup-core][debug] ${CYAN}%s${NC}\n" "$*" >&2 || true; }
_backup_die() { _backup_error "$*"; exit 1; }

# Dependency checks
_require_cmd() {
  # Use _have_cmd from system.sh if available, otherwise fallback
  local check_func="_have_cmd"
  if ! declare -f "$check_func" > /dev/null; then check_func="command -v"; fi

  if ! "$check_func" "$1" >/dev/null 2>&1; then
      _backup_die "Required command not found: $1"
  fi
}

_validate_backup_environment() {
  _backup_debug "Validating backup environment"
  _require_cmd sqlite3
  _require_cmd gpg # Assuming GPG encryption; change if using Age
  _require_cmd gzip
  _require_cmd du
  _require_cmd df
  _require_cmd stat # Added stat
  _require_cmd mktemp # Added mktemp
  _require_cmd shred # Added shred

  # Optional commands
  # Check existence before warning
  command -v rclone >/dev/null 2>&1 || _backup_warn "rclone not found - cloud upload disabled"
  command -v ionice >/dev/null 2>&1 || _backup_warn "ionice not found - CPU/IO priority control disabled"
  command -v nice >/dev/null 2>&1 || _backup_warn "nice not found - CPU priority control disabled" # Added nice check
  command -v bc >/dev/null 2>&1 || _backup_warn "bc not found - advanced resource calculations disabled"
  command -v nproc >/dev/null 2>&1 || _backup_warn "nproc not found - CPU core count unavailable" # Added nproc check
}

# Resource monitoring and management
check_system_resources() {
  local db_file="${1:?Database file required}"
  local out_dir="${2:?Output directory required}"

  _backup_debug "Checking system resources for backup operation"

  # Validate input file/dir exist
  [[ ! -f "$db_file" ]] && { _backup_error "Database file not found: $db_file"; return 1; }
  [[ ! -d "$out_dir" ]] && { _backup_error "Output directory not found: $out_dir"; return 1; }


  # Calculate database size and requirements
  local db_size_mb db_size_bytes required_space_mb available_mb
  db_size_bytes=$(stat -c%s "$db_file" 2>/dev/null || echo "0")
  db_size_mb=$(( (db_size_bytes + 1024*1024 - 1) / (1024*1024) )) # Ceiling division for MB
  # Estimate required space (DB + multiple formats + compressed + encrypted) - adjust multiplier as needed
  required_space_mb=$((db_size_mb * 4 + 50)) # Add small buffer

  # Check available disk space in output directory
  available_mb=$(df -P -BM "$out_dir" 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/M//' || echo "0") # Get MB directly
  if [[ "$available_mb" -lt "$required_space_mb" ]]; then
    _backup_error "Insufficient disk space in '$out_dir'. Required: ~${required_space_mb}MB, Available: ${available_mb}MB"
    return 1 # Changed to error and return 1
  fi

  _backup_info "Disk space check passed: ${available_mb}MB available, ~${required_space_mb}MB estimated requirement"

  # Check memory availability for compression
  local available_mem_mb required_mem_mb
  # Get Available memory (MemAvailable from /proc/meminfo or calculation from free)
  if [[ -r /proc/meminfo ]]; then
      available_mem_mb=$(awk '/MemAvailable/ {printf "%d", $2 / 1024}' /proc/meminfo || echo "1024")
  else
      available_mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/ {print int($7 * 0.8)}' || echo "1024") # Fallback using 'free'
  fi
  required_mem_mb=$((db_size_mb / 4 + 100))  # Conservative estimate for compression + buffer

  if [[ "$available_mem_mb" -lt "$required_mem_mb" ]]; then
    _backup_warn "Limited memory available (${available_mem_mb}MB < ~${required_mem_mb}MB estimated). Compression might be slow or fail."
    # Decide if USE_STREAMING_COMPRESSION should be set based on available tools/methods
    # export USE_STREAMING_COMPRESSION=1 # Example
  fi

  # Check CPU load (only if bc and nproc available)
  local cpu_cores=1 # Default to 1 core if nproc fails
  command -v nproc >/dev/null && cpu_cores=$(nproc 2>/dev/null || echo 1)

  if command -v bc >/dev/null; then
    local cpu_load load_threshold high_load_threshold
    # Get 1-minute load average
    cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ' || echo "0.0")
    # Define thresholds based on cores
    load_threshold=$(echo "scale=1; $cpu_cores * 1.5" | bc) # Warning threshold
    high_load_threshold=$(echo "scale=1; $cpu_cores * 2.5" | bc) # High load threshold for using low priority

    _backup_debug "Current load: $cpu_load, Cores: $cpu_cores, High load threshold: $high_load_threshold"

    if (( $(echo "$cpu_load > $high_load_threshold" | bc -l 2>/dev/null || echo 0) )); then
      _backup_warn "High CPU load detected (${cpu_load} > ${high_load_threshold}). Backup performance may be affected. Consider using lower priority execution if supported."
      # Suggests using low priority, but doesn't force it here
      # export USE_LOW_PRIORITY=1 # Could be set here if desired
    elif (( $(echo "$cpu_load > $load_threshold" | bc -l 2>/dev/null || echo 0) )); then
      _backup_info "CPU load is elevated (${cpu_load} > ${load_threshold}). Monitoring performance."
    fi
  else
      _backup_warn "bc command not found. Skipping detailed CPU load check."
  fi

  # Store DB size for other functions
  export DB_SIZE_MB="$db_size_mb"
  _backup_debug "Database size: ${db_size_mb}MB. Resource checks complete."
  return 0
}

# Intelligent timeout calculation based on database characteristics
calculate_backup_timeout() {
  local db_file="${1:?Database file required}"

  # Get DB size from env var if set by check_system_resources, else calculate
  local db_size_mb="${DB_SIZE_MB:-$(stat -c%s "$db_file" 2>/dev/null | awk '{printf "%d", ($1 + 1024*1024 - 1) / (1024*1024)}' || echo "10")}"
  local base_timeout=30 # Minimum timeout in seconds
  local size_factor=$((db_size_mb / 50))  # Increase timeout by 1 second per 50MB (adjust rate as needed)
  local calculated_timeout=$((base_timeout + size_factor))

  # Check for WAL file and adjust timeout if WAL exists and is large
  local wal_file="${db_file}-wal"
  if [[ -f "$wal_file" ]]; then
    local wal_size_bytes wal_size_mb wal_factor
    wal_size_bytes=$(stat -c%s "$wal_file" 2>/dev/null || echo "0")
    wal_size_mb=$(( (wal_size_bytes + 1024*1024 - 1) / (1024*1024) ))
    if [[ "$wal_size_mb" -gt 50 ]]; then # Only add significant time if WAL is large
        wal_factor=$((wal_size_mb / 25))  # Add 1 second per 25MB of WAL file
        calculated_timeout=$((calculated_timeout + wal_factor))
        _backup_debug "WAL file detected (${wal_size_mb}MB), added ${wal_factor}s to timeout."
    fi
  fi

  # Apply bounds: minimum 30s, maximum 600s (10 minutes)
  local timeout=$(( calculated_timeout < 30 ? 30 : (calculated_timeout > 600 ? 600 : calculated_timeout) ))

  _backup_debug "Calculated timeout: ${timeout}s for ${db_size_mb}MB database"
  echo "$timeout" # Return the calculated timeout
}

# WAL-aware database preparation
prepare_database_for_backup() {
  local db_file="${1:?Database file required}"
  local timeout="${2:-$(calculate_backup_timeout "$db_file")}" # Use calculated timeout if not provided

  _backup_debug "Preparing database for backup (timeout: ${timeout}s)"

  # Check if database is in WAL mode
  local journal_mode
  journal_mode=$(sqlite3 "$db_file" "PRAGMA journal_mode;" 2>/dev/null || echo "error")

  if [[ "$journal_mode" == "error" ]]; then
       _backup_warn "Could not determine database journal mode for '$db_file'."
       return 1 # Indicate potential issue
  elif [[ "$journal_mode" == "wal" ]]; then
    _backup_info "Database is in WAL mode. Performing pre-backup optimization."

    local wal_file="${db_file}-wal"
    if [[ -f "$wal_file" ]]; then
      local wal_size_bytes wal_size_mb
      wal_size_bytes=$(stat -c%s "$wal_file" 2>/dev/null || echo "0")
      wal_size_mb=$(( (wal_size_bytes + 1024*1024 - 1) / (1024*1024) ))
      _backup_info "Current WAL file size: ${wal_size_mb}MB"

      # Checkpoint to reduce WAL size before backup (helps consistency)
      # Use PRAGMA wal_checkpoint(PASSIVE) first (non-blocking)
      # Then maybe TRUNCATE if still large? TRUNCATE can block writers.
      _backup_info "Attempting passive WAL checkpoint..."
      if ! sqlite3 "$db_file" ".timeout $timeout" "PRAGMA wal_checkpoint(PASSIVE);" >/dev/null 2>&1; then
          _backup_warn "Passive WAL checkpoint command failed or timed out. Backup might take longer."
          # Don't return error, just warn
      else
          _backup_success "Passive WAL checkpoint completed."
          # Optionally check size again and run TRUNCATE if needed, but adds complexity/blocking risk
      fi
    else
      _backup_debug "No WAL file found, checkpoint not needed."
    fi
  else
    _backup_debug "Database journal mode is '$journal_mode' (not WAL). No WAL-specific preparation needed."
  fi

  return 0
}

# Enhanced backup verification with comprehensive checks
verify_backup_integrity() {
  local backup_file="${1:?Backup file required}"
  local original_db="${2:-}" # Optional: Path to original DB for comparison

  _backup_debug "Performing comprehensive backup integrity verification on: $(basename "$backup_file")"

  if [[ ! -f "$backup_file" ]]; then
     _backup_error "Backup file not found: $backup_file"
     return 1
  fi

  # Basic SQLite integrity check
  local integrity_output integrity_rc
  _backup_info "Running SQLite PRAGMA integrity_check..."
  integrity_output=$(sqlite3 "$backup_file" "PRAGMA integrity_check;" 2>&1)
  integrity_rc=$?

  if [[ $integrity_rc -ne 0 ]]; then
       _backup_error "SQLite command failed during integrity check (rc=$integrity_rc)."
       _backup_error "Output: $integrity_output"
       return 1
  elif [[ "$integrity_output" == "ok" ]]; then
       _backup_success "SQLite integrity_check passed."
  else
       _backup_error "SQLite integrity_check FAILED."
       _backup_error "Details: $integrity_output"
       return 1
  fi

  # If original database provided, perform comparative verification (optional but recommended)
  if [[ -n "$original_db" ]] && [[ -f "$original_db" ]]; then
    _backup_info "Comparing backup with original database: $(basename "$original_db")"
    local orig_tables backup_tables orig_rows backup_rows main_table

    # Compare table count
    orig_tables=$(sqlite3 "$original_db" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';" 2>/dev/null || echo "-1")
    backup_tables=$(sqlite3 "$backup_file" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';" 2>/dev/null || echo "-1")

    if [[ "$orig_tables" == "-1" || "$backup_tables" == "-1" ]]; then
        _backup_warn "Could not get table counts for comparison."
    elif [[ "$orig_tables" -ne "$backup_tables" ]]; then
      _backup_error "Table count mismatch! Original: $orig_tables, Backup: $backup_tables"
      return 1
    else
      _backup_success "Table count matches ($orig_tables tables)."
    fi

    # Quick row count check on a major table (e.g., 'users' or 'ciphers' if they exist)
    main_table=""
    # Check for likely table names
    for table_name in users ciphers collections; do
        if sqlite3 "$original_db" "SELECT 1 FROM sqlite_master WHERE type='table' AND name='$table_name';" 2>/dev/null | grep -q 1; then
            main_table="$table_name"
            break
        fi
    done

    if [[ -n "$main_table" ]]; then
      _backup_debug "Performing row count check on table '$main_table'..."
      orig_rows=$(sqlite3 "$original_db" "SELECT COUNT(*) FROM \"$main_table\";" 2>/dev/null || echo "-1")
      backup_rows=$(sqlite3 "$backup_file" "SELECT COUNT(*) FROM \"$main_table\";" 2>/dev/null || echo "-1")

      if [[ "$orig_rows" == "-1" || "$backup_rows" == "-1" ]]; then
          _backup_warn "Could not get row counts for table '$main_table' comparison."
      elif [[ "$orig_rows" -ne "$backup_rows" ]]; then
          # Allow small tolerance if WAL was active? Maybe not for core tables.
          _backup_error "Row count mismatch in table '$main_table'! Original: $orig_rows, Backup: $backup_rows"
          return 1
      else
         _backup_success "Row count matches for table '$main_table' ($orig_rows rows)."
      fi
    else
        _backup_warn "Could not find a common table (users/ciphers/collections) for row count comparison."
    fi
  else
      _backup_info "Original database path not provided or not found. Skipping comparative verification."
  fi

  _backup_success "Backup integrity verification completed successfully for: $(basename "$backup_file")"
  return 0
}

# Resource-aware compression function (using gzip)
compress_with_resource_limits() {
  local input_file="${1:?Input file required}"
  local output_file="${2:?Output file required}"

  _backup_debug "Compressing with resource awareness: $(basename "$input_file") -> $(basename "$output_file")"

  if [[ ! -f "$input_file" ]]; then
     _backup_error "Input file for compression not found: $input_file"
     return 1
  fi

  local compress_cmd="gzip"
  local compress_args=("-9" "-f") # -f to overwrite output file if exists
  local final_cmd_prefix=""

  # Apply resource limits if USE_LOW_PRIORITY is set (e.g., by check_system_resources)
  if [[ "${USE_LOW_PRIORITY:-0}" == "1" ]]; then
      local nice_cmd ionice_cmd
      _have_cmd nice && nice_cmd="nice -n 10"
      _have_cmd ionice && ionice_cmd="ionice -c 3" # Idle I/O priority
      if [[ -n "$nice_cmd" || -n "$ionice_cmd" ]]; then
          final_cmd_prefix="$nice_cmd $ionice_cmd " # Combine nice and ionice
          _backup_debug "Using low priority compression: $final_cmd_prefix"
      fi
  fi

  # Decide between streaming or in-place based on USE_STREAMING_COMPRESSION
  if [[ "${USE_STREAMING_COMPRESSION:-0}" == "1" ]]; then
    # Streaming compression (input -> gzip -> output)
    _backup_debug "Using streaming compression to conserve memory."
    if ! ${final_cmd_prefix} ${compress_cmd} -c "${compress_args[@]}" "$input_file" > "$output_file"; then
        _backup_error "Streaming compression failed for $(basename "$input_file")."
        rm -f "$output_file" # Clean up potentially incomplete output
        return 1
    fi
    # Securely delete original input file after successful streaming compression
     _backup_debug "Securely deleting original file after streaming compression: $(basename "$input_file")"
     if _have_cmd shred; then
          shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
     else
          rm -f "$input_file"
     fi
  else
    # Standard in-place compression (creates .gz, then rename)
    # Gzip creates input_file.gz
    if ! ${final_cmd_prefix} ${compress_cmd} "${compress_args[@]}" "$input_file"; then
        _backup_error "In-place compression failed for $(basename "$input_file")."
        # gzip might leave .gz file on error, try cleaning up
        rm -f "${input_file}.gz"
        return 1
    fi
    # Rename the .gz file to the desired output name
    if ! mv "${input_file}.gz" "$output_file"; then
        _backup_error "Failed to rename compressed file to $(basename "$output_file")."
        # Try to clean up .gz file
        rm -f "${input_file}.gz"
        return 1
    fi
  fi

  _backup_success "Compression completed: $(basename "$output_file")"
  return 0
}

# Secure encryption with improved error handling (using GPG)
# TODO: Adapt this if Age encryption is preferred system-wide
encrypt_backup_file_gpg() {
  local input_file="${1:?Input file required}"
  local passphrase="${2:?Passphrase required}"
  local output_file="${3:-${input_file}.gpg}"

  _backup_debug "Encrypting backup file using GPG: $(basename "$input_file") -> $(basename "$output_file")"

  if [[ ! -f "$input_file" ]]; then
     _backup_error "Input file for encryption not found: $input_file"
     return 1
  fi
  # Check for gpg command
  _require_cmd gpg

  # Create temporary passphrase file for secure GPG operation
  local passphrase_file
  passphrase_file=$(mktemp -p "${TMPDIR:-/tmp}" backup-pass.XXXXXX) || { _backup_error "Failed to create temp passphrase file"; return 1; }
  chmod 600 "$passphrase_file" || { _backup_error "Failed to set permissions on temp passphrase file"; rm -f "$passphrase_file"; return 1; }
  # Ensure cleanup of passphrase file
  trap '_backup_debug "Cleaning up passphrase file"; shred -u "$passphrase_file" 2>/dev/null || rm -f "$passphrase_file"; trap - RETURN' RETURN

  # Write passphrase to file
  echo "$passphrase" > "$passphrase_file" || { _backup_error "Failed to write to temp passphrase file"; return 1; }

  # Encrypt using symmetric encryption with AES256 and passphrase file
  # Use --compress-algo 0 to avoid double compression if input is already gzipped
  local compress_algo=2 # Default: zlib
  [[ "$input_file" == *.gz ]] && compress_algo=0 # No compression if already gzipped

  if gpg --batch --yes --quiet --cipher-algo AES256 \
         --compress-algo "$compress_algo" --symmetric \
         --passphrase-file "$passphrase_file" \
         --output "$output_file" \
         "$input_file"; then

    # Secure cleanup of original input file
    _backup_debug "Securely deleting original file after encryption: $(basename "$input_file")"
    if _have_cmd shred; then
        shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
    else
        rm -f "$input_file"
    fi

    # Passphrase file cleaned by trap
    _backup_success "GPG encryption completed: $(basename "$output_file")"
    return 0
  else
    # Cleanup on failure
    # Passphrase file cleaned by trap
    rm -f "$output_file" # Remove potentially incomplete encrypted file
    _backup_error "GPG encryption failed for: $(basename "$input_file"). Check GPG version or input file."
    return 1
  fi
}

# TODO: Add encrypt_backup_file_age function if switching to Age

# Initialize backup core functions
init_backup_core() {
  _backup_debug "Initializing backup core functions..."
  _validate_backup_environment

  # Set default values for resource management flags (can be overridden by env vars)
  export USE_STREAMING_COMPRESSION="${USE_STREAMING_COMPRESSION:-0}"
  export USE_LOW_PRIORITY="${USE_LOW_PRIORITY:-0}"
  # Ensure DEBUG is honored if set externally
  export DEBUG="${DEBUG:-false}"
  [[ "$DEBUG" == "true" ]] && export DEBUG=1 || export DEBUG=0 # Normalize DEBUG to 1 or 0

  _backup_info "Backup core initialization completed."
}

# --- Initialization Call ---
# Run initialization when the library is sourced
init_backup_core
