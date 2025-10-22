#!/usr/bin/env bash
# lib/backup-formats.sh — Backup creation formats (using core library)

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
    log_info() { echo "[backup-formats.sh][INFO] $*"; }
    log_warn() { echo "[backup-formats.sh][WARN] $*"; }
    log_error() { echo "[backup-formats.sh][ERROR] $*" >&2; }
    log_success() { echo "[backup-formats.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi
# Source backup core functions (essential)
if [[ -f "$LIB_DIR/backup-core.sh" ]]; then
    source "$LIB_DIR/backup-core.sh"
    # Initialize core functions after sourcing
    init_backup_core || { log_error "Failed to initialize backup core library."; exit 1; }
else
     log_error "CRITICAL: Backup core library (lib/backup-core.sh) not found."
     exit 1
fi
# Source config library (optional, for Age keys etc if not passed)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then source "$LIB_DIR/config.sh"; CONFIG_LOADED_SUCCESS=true; fi
# Source constants library (optional, paths etc)
if [[ -f "$LIB_DIR/constants.sh" ]]; then source "$LIB_DIR/constants.sh"; fi

# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "backup-formats"


# --- Internal Logging Aliases (using logging.sh functions) ---
_format_log() { log_info "$*"; } # Use standard info for general messages
_format_info() { log_success "$*"; } # Use success for format-specific info
_format_warn() { log_warn "$*"; }
_format_error() { log_error "$*"; }
_format_debug() { _log_debug "$*"; } # Use debug from logging.sh

# --- Backup Format Creation Functions ---

# Create binary SQLite backup with transaction safety using API snapshot
# Usage: create_binary_backup_api <output_file> [api_url] [admin_token]
create_binary_backup_api() {
  local output_file="${1:?Output file path required}"
  # Get API URL/Token from config if not passed (use get_config_value/get_secret)
  local api_url="${2:-$(get_config_value "VAULTWARDEN_API_URL" "http://localhost:8080")}"
  local admin_token="${3:-$(get_secret "admin_token" "")}"

  _format_debug "Creating binary SQLite backup via API snapshot"

  if [[ -z "$admin_token" ]]; then
       _format_error "Admin token not provided or found in secrets. Cannot use API backup."
       return 1
  fi
  if ! command -v curl >/dev/null; then _format_error "curl command not found."; return 1; fi

  _format_info "Requesting database snapshot from API (${api_url})..."
  local http_code
  # Capture HTTP status code, use output file directly
  http_code=$(curl -s -w "%{http_code}" -X POST "${api_url}/api/admin/db/backup" \
      -H "Authorization: Bearer ${admin_token}" \
      -o "$output_file" --max-time 120) # Increased timeout

  if [[ "$http_code" -ne 200 ]]; then
      _format_error "API snapshot request failed (HTTP Status: $http_code)."
      # Clean up potentially failed output file
      rm -f "$output_file"
      return 1
  fi
   if [[ ! -s "$output_file" ]]; then
       _format_error "API snapshot downloaded successfully but file is empty."
       return 1
   fi
  _format_info "API snapshot downloaded to: $(basename "$output_file")"
  return 0
}

# Create SQL dump backup (requires DB file path)
# Usage: create_sql_dump_backup <db_file> <output_file> [timeout]
create_sql_dump_backup() {
  local db_file="${1:?Database file path required}"
  local output_file="${2:?Output file path required}"
  local timeout="${3:-$(calculate_backup_timeout "$db_file")}" # Use calculated timeout

  _format_debug "Creating SQL dump backup from: $(basename "$db_file")"
  [[ ! -f "$db_file" ]] && { _format_error "Database file not found: $db_file"; return 1; }

  # Execute sqlite3 .dump command with timeout
  if sqlite3 "$db_file" ".timeout $timeout" ".dump" > "$output_file"; then
      _format_info "SQL dump backup created: $(basename "$output_file")"
      return 0
  else
      _format_error "Failed to create SQL dump."
      rm -f "$output_file" # Clean up potentially incomplete file
      return 1
  fi
}


# --- Main Orchestration Function (creates multiple formats) ---
# Creates API snapshot (binary) and optionally SQL dump, compresses, verifies.
# Usage: create_diverse_backups <output_dir> <timestamp> [create_sql_dump_flag]
# Assumes config (API token etc) is loaded.
create_diverse_backups() {
  local output_dir="${1:?Output directory required}"
  local timestamp="${2:?Timestamp required}"
  local create_sql_dump="${3:-false}" # Default to not creating SQL dump

  _format_info "Creating diverse database backups (Timestamp: $timestamp)..."

  # Load config if not already done
  if [[ "$CONFIG_LOADED_SUCCESS" != "true" ]]; then
      if ! load_config; then
           _format_error "Failed to load configuration. Cannot proceed."
           return 1
      fi
  fi

  # Determine DB file path from config (needed for SQL dump and size checks if used)
  local db_file="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata/db.sqlite3"

  # Perform resource check (optional, requires db_file)
  # check_system_resources "$db_file" "$output_dir" || return 1 # Exit if resources insufficient

  # Prepare database (optional, WAL checkpoint - requires db_file)
  # prepare_database_for_backup "$db_file" "$(calculate_backup_timeout "$db_file")" || _format_warn "Database preparation had issues, continuing."

  # --- Backup Creation ---
  local backup_files=() failed_formats=() errors=0

  # 1. Native SQLite binary backup via API snapshot (Primary Method)
  local bin_out="$output_dir/db-api-snapshot-$timestamp.sqlite3"
  if create_binary_backup_api "$bin_out"; then
    if verify_backup_integrity "$bin_out"; then # Verify API snapshot
      backup_files+=("$bin_out")
      _format_success "API Snapshot backup verified."
    else
      failed_formats+=("api-snapshot-binary (verify failed)")
      rm -f "$bin_out"
      errors=1
    fi
  else
    failed_formats+=("api-snapshot-binary (create failed)")
    errors=1
  fi

  # 2. Optional: SQL Dump backup (Requires direct DB file access)
  if [[ "$create_sql_dump" == "true" ]]; then
       _format_info "Creating SQL dump format..."
       local sql_out="$output_dir/db-sql-dump-$timestamp.sql"
       if create_sql_dump_backup "$db_file" "$sql_out"; then
           # Optionally verify SQL dump? (Difficult, maybe check size > 0)
           if [[ -s "$sql_out" ]]; then
                backup_files+=("$sql_out")
                _format_success "SQL Dump backup created."
           else
                failed_formats+=("sql-dump (empty file)")
                rm -f "$sql_out"
           fi
       else
            failed_formats+=("sql-dump (create failed)")
       fi
  fi

  # --- Compression and Encryption ---
  if [[ ${#backup_files[@]} -eq 0 ]]; then
      _format_error "Backup creation failed. No valid backup files generated."
      # Manifest generation skipped if no files
      return 1
  fi

  _format_info "Compressing and encrypting successful backup files..."
  local encrypted_files=() final_encrypted_paths=() # Store paths of successfully encrypted files
  local age_pub_key_file="${PUBLIC_KEY_FILE:-secrets/keys/age-public-key.txt}"
  if [[ ! -r "$age_pub_key_file" ]]; then
       _format_error "Age public key file not found or not readable: $age_pub_key_file"
       return 1
  fi
  local public_key_content
  public_key_content=$(cat "$age_pub_key_file") || { _format_error "Failed to read public key."; return 1; }


  for file in "${backup_files[@]}"; do
      local compressed_file="${file}.gz"
      local encrypted_file="${compressed_file}.age"

      _format_info "Processing: $(basename "$file")"
      # Compress first
      if compress_with_resource_limits "$file" "$compressed_file"; then
           # Encrypt compressed file using Age
           if encrypt_backup_file_age "$compressed_file" "$public_key_content" "$encrypted_file"; then
                encrypted_files+=("$(basename "$encrypted_file")") # Add basename to manifest list
                final_encrypted_paths+=("$encrypted_file") # Keep full path for potential cleanup
                # Securely delete the intermediate compressed file (handled by encrypt function now)
           else
                failed_formats+=("$(basename "$file") (encryption failed)")
                rm -f "$compressed_file" "$encrypted_file" # Clean up intermediates
                errors=1
           fi
      else
           failed_formats+=("$(basename "$file") (compression failed)")
           # compress function should clean up source file on failure if streaming
           rm -f "$file" "$compressed_file" # Clean up source and potential partial compressed
           errors=1
      fi
      # Original uncompressed file ($file) should be cleaned up by compress or encrypt function
  done

  # --- Manifest Generation ---
  create_backup_manifest "$output_dir" "$timestamp" "$db_file" "${encrypted_files[@]}" "${failed_formats[@]}"

  # --- Final Status ---
  if [[ $errors -eq 0 && ${#encrypted_files[@]} -gt 0 ]]; then
    _format_success "Diverse backup creation process completed successfully."
    return 0
  else
    _format_error "Diverse backup creation process finished with errors."
    # Optionally list failed formats again
    [[ ${#failed_formats[@]} -gt 0 ]] && _format_error "Failed formats/steps: ${failed_formats[*]}"
    return 1
  fi
}

# Wrapper for Age encryption (replaces GPG version)
# Usage: encrypt_backup_file_age <input_file> <public_key_content> [output_file]
encrypt_backup_file_age() {
  local input_file="${1:?Input file required}"
  local public_key="${2:?Public key content required}"
  local output_file="${3:-${input_file}.age}"

  _format_debug "Encrypting backup file with Age: $(basename "$input_file")"

  # Encrypt using Age with recipient public key
  if age -r "$public_key" -o "$output_file" "$input_file"; then
    # Secure cleanup of the unencrypted input file
    shred -u "$input_file" 2>/dev/null || rm -f "$input_file"
    _format_info "Age encryption completed: $(basename "$output_file")"
    return 0
  else
    # Cleanup on failure
    rm -f "$output_file"
    # Do NOT shred input on failure, it might be needed for retry/debug
    _format_error "Age encryption failed for: $(basename "$input_file")"
    return 1
  fi
}


# Create backup manifest with metadata
# Usage: create_backup_manifest <output_dir> <timestamp> <db_file> <successful_encrypted_basenames_array> <failed_formats_array>
create_backup_manifest() {
  local output_dir="${1:?Output directory required}"
  local timestamp="${2:?Timestamp required}"
  local db_file="${3:?Database file required}" # Source DB file path
  # Pass arrays by name reference (requires Bash 4.3+)
  local -n successful_files_ref=$4
  local -n failed_formats_ref=$5

  local manifest_file="$output_dir/backup-manifest-${timestamp}.json"
  _format_debug "Creating backup manifest: $(basename "$manifest_file")"

  # Safely get DB size info
  local db_size_bytes="0" db_size_human="unknown"
  if [[ -f "$db_file" ]]; then
       db_size_bytes=$(stat -c%s "$db_file" 2>/dev/null || stat -f%z "$db_file" 2>/dev/null || echo "0")
       db_size_human=$(du -h "$db_file" 2>/dev/null | cut -f1 || echo "unknown")
  else
       _format_warn "Source database file '$db_file' not found for manifest size info."
  fi

  # Generate JSON content using printf for portability
  {
      printf '{\n'
      printf '  "backup_manifest": {\n'
      printf '    "created_utc": "%s",\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
      printf '    "timestamp": "%s",\n' "$timestamp"
      printf '    "generator": "VaultWarden-OCI-NG Backup System",\n'
      printf '    "manifest_version": "1.2",\n' # Updated version
      printf '    "source_database": {\n'
      printf '      "assumed_path": "%s",\n' "$(basename "$db_file")"
      printf '      "size_bytes": %s,\n' "$db_size_bytes"
      printf '      "size_human": "%s"\n' "$db_size_human"
      printf '    },\n'
      printf '    "backup_files_created": [\n'
      # Loop through successful files array
      local first=true
      for file in "${successful_files_ref[@]}"; do
           [[ "$first" == false ]] && printf ',\n' || first=false
           printf '      "%s"' "$file"
      done
       printf '\n    ],\n'
      printf '    "failed_formats_or_steps": [\n'
      # Loop through failed formats array
      first=true
      for format in "${failed_formats_ref[@]}"; do
            [[ "$first" == false ]] && printf ',\n' || first=false
           printf '      "%s"' "$format"
      done
       printf '\n    ]\n'
      printf '  }\n'
      printf '}\n'
  } > "$manifest_file"

   if [[ -s "$manifest_file" ]]; then
       _format_info "Backup manifest created: $(basename "$manifest_file")"
       return 0
   else
        _format_error "Failed to create or write backup manifest file: $manifest_file"
        return 1
   fi
}


# --- Self-Test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/backup-formats.sh is a library and should be sourced, not executed directly."
     # Add basic self-tests here if needed
     # Example: Test manifest creation
     # mkdir -p /tmp/backup_test
     # touch /tmp/backup_test/db.sqlite3
     # s_files=("db-api-snapshot-123.sqlite3.gz.age")
     # f_files=("sql-dump (create failed)")
     # create_backup_manifest /tmp/backup_test 123 /tmp/backup_test/db.sqlite3 s_files f_files
     # cat /tmp/backup_test/backup-manifest-123.json
     # rm -rf /tmp/backup_test
     exit 0
else
      _log_debug "lib/backup-formats.sh loaded successfully as a library."
fi
