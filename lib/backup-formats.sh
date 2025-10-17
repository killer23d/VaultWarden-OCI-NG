#!/usr/bin/env bash
# lib/backup-formats.sh — Simplified backup creation for binary format.

set -euo pipefail

# Source backup core functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/backup-core.sh"

# Internal logging functions
_format_log() { printf "[backup-formats] %s\n" "$*" >&2; }
_format_info() { printf "[backup-formats] ${GREEN}%s${NC}\n" "$*" >&2; }
_format_warn() { printf "[backup-formats] ${YELLOW}%s${NC}\n" "$*" >&2; }
_format_error() { printf "[backup-formats][error] ${RED}%s${NC}\n" "$*" >&2; }
_format_debug() { [ "${DEBUG:-0}" = "1" ] && printf "[backup-formats][debug] ${CYAN}%s${NC}\n" "$*" >&2 || true; }

# Create binary SQLite backup with transaction safety
create_binary_backup() {
  local db_file="${1:?Database file required}"
  local output_file="${2:?Output file required}"
  local timeout="${3:-60}"
  
  _format_debug "Creating binary SQLite backup"
  
  # Use transaction isolation for consistency
  sqlite3 "$db_file" <<EOF || return 1
.timeout $timeout
BEGIN IMMEDIATE;
.backup '$output_file'
COMMIT;
EOF
  
  _format_info "Binary backup created: $(basename "$output_file")"
}

# Simplified function to create only the essential binary backup
create_diverse_backups() {
  local db_file="${1:?Database file required}"
  local output_dir="${2:?Output directory required}"
  local timestamp="${3:?Timestamp required}"
  
  _format_info "Creating encrypted binary backup..."
  
  local timeout
  timeout=$(calculate_backup_timeout "$db_file")
  _format_debug "Using calculated timeout: ${timeout}s"
  
  # Prepare database for backup (WAL checkpoint if needed)
  prepare_database_for_backup "$db_file" "$timeout" || _format_warn "Database preparation had issues, continuing."
  
  local backup_files=()
  local failed_formats=()
  
  # Create Native SQLite binary backup
  local bin_out="$output_dir/db-native-$timestamp.sqlite3"
  if create_binary_backup "$db_file" "$bin_out" "$timeout"; then
    if verify_backup_integrity "$bin_out" "$db_file"; then
      backup_files+=("$bin_out")
    else
      failed_formats+=("binary")
      rm -f "$bin_out"
    fi
  else
    failed_formats+=("binary")
  fi
  
  if [ ${#backup_files[@]} -gt 0 ]; then
    _format_info "Binary backup created successfully."
  else
    _format_error "Backup creation failed."
    return 1
  fi
  
  create_backup_manifest "$output_dir" "$timestamp" "$db_file" backup_files[@] failed_formats[@]
  
  return 0
}

# Create backup manifest with metadata
create_backup_manifest() {
  local output_dir="${1:?Output directory required}"
  local timestamp="${2:?Timestamp required}"
  local db_file="${3:?Database file required}"
  local -n successful_files=$4
  local -n failed_formats_ref=$5
  
  local manifest_file="$output_dir/backup-manifest.json"
  
  _format_debug "Creating backup manifest"
  
  cat > "$manifest_file" << EOF
{
  "backup_manifest": {
    "created": "$(date -u '+%Y-%m-%d %H:%M:%S UTC')",
    "timestamp": "$timestamp",
    "generator": "VaultWarden-OCI-Minimal Simplified Backup System",
    "manifest_version": "1.1",
    "source_database": {
      "file": "$(basename "$db_file")",
      "size_bytes": $(stat -c%s "$db_file" 2>/dev/null || echo "0"),
      "size_human": "$(du -h "$db_file" 2>/dev/null | cut -f1 || echo "unknown")"
    },
    "backup_formats": {
      "successful": [ "binary" ],
      "failed": [
$(printf '        "%s"' "${failed_formats_ref[@]}" | paste -sd ',' | sed 's/,/",\n        "/g' | sed 's/$/"/g' 2>/dev/null || echo "")
      ]
    }
  }
}
EOF
  
  _format_info "Backup manifest created: $(basename "$manifest_file")"
}