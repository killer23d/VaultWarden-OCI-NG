#!/usr/bin/env bash
# lib/restore-lib.sh — shared restore helpers (stop/start, decrypt, restore db/volumes, health)

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
    log_info() { echo "[restore-lib.sh][INFO] $*"; }
    log_warn() { echo "[restore-lib.sh][WARN] $*"; }
    log_error() { echo "[restore-lib.sh][ERROR] $*" >&2; }
    log_success() { echo "[restore-lib.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi

# Source config library (essential for container names, state dir)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh. Using defaults."
        # Define defaults if config fails
        COMPOSE_PROJECT_NAME="vaultwarden"
        PROJECT_STATE_DIR="/var/lib/vaultwarden"
    fi
else
    log_error "CRITICAL: Config library (lib/config.sh) not found."
    # Define defaults if config lib missing
    COMPOSE_PROJECT_NAME="vaultwarden"
    PROJECT_STATE_DIR="/var/lib/vaultwarden"
fi
# Source system library (optional, for compose helpers)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then source "$LIB_DIR/system.sh"; SYSTEM_LIB_AVAILABLE=true; fi
# Source constants if available
if [[ -f "$LIB_DIR/constants.sh" ]]; then source "$LIB_DIR/constants.sh"; fi


# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "restore-lib"


# Use logging functions defined by logging.sh or fallback
rlog() { log_info "$*"; } # Alias log_info
rdie() { log_error "$*"; exit 1; } # Alias log_error and exit
need() { command -v "$1" >/dev/null 2>&1 || rdie "Missing required command: $1"; }

# Check essential commands at load time
need docker
need age # Changed from gpg to age
need sqlite3
need shred
need gunzip # For handling .gz archives
need tar # For handling .tar archives
need mktemp
need stat # For checking file size/existence


# --- Global Variables from Config/Defaults ---
# Get container names using get_config_value for safety
BW_VW=$(get_config_value "CONTAINER_NAME_VAULTWARDEN" "${COMPOSE_PROJECT_NAME:-vaultwarden}_vaultwarden")
BW_CADDY=$(get_config_value "CONTAINER_NAME_CADDY" "${COMPOSE_PROJECT_NAME:-vaultwarden}_caddy")
# Define data directory path based on config
DATA_DIR="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data/bwdata"


# Decrypt Age encrypted file to a secure temp file; caller must securely remove temp file
# Usage: tmp_file=$(decrypt_age_to_tmp <src_age_file> <age_key_file> [temp_dir])
decrypt_age_to_tmp() {
  local src="$1"
  local key_file="${2:?Age key file required}"
  local tmp_dir="${3:-/tmp}" # Allow specifying temp dir, default to /tmp
  local tmp_file suffix=""

  # Check key file readability
  [[ ! -r "$key_file" ]] && rdie "Age key file not found or not readable: $key_file"

  # Determine suffix based on source file name (e.g., .tar.gz, .sqlite3.gz)
  if [[ "$src" == *.tar.gz.age ]]; then suffix=".tar.gz";
  elif [[ "$src" == *.sqlite3.gz.age ]]; then suffix=".sqlite3.gz";
  elif [[ "$src" == *.sql.gz.age ]]; then suffix=".sql.gz";
  elif [[ "$src" == *.gz.age ]]; then suffix=".gz"; # Generic gzip
  else suffix=".decrypted"; fi # Fallback suffix

  tmp_file=$(mktemp -p "$tmp_dir" "decrypted-${RANDOM}XXXXXX${suffix}") || rdie "Failed to create temporary file in $tmp_dir"
  _log_debug "Created temporary file for decryption: $tmp_file"

  # Decrypt using Age identity file
  _log_debug "Attempting decryption: age -d -i '$key_file' -o '$tmp_file' '$src'"
  if ! age -d -i "$key_file" -o "$tmp_file" "$src"; then
      # Securely remove potentially partially decrypted file on failure
      shred -u "$tmp_file" 2>/dev/null || rm -f "$tmp_file"
      rdie "Age decryption failed for $src. Check key file and source file integrity."
  fi

  # Check if decrypted file has content
  if [[ ! -s "$tmp_file" ]]; then
      shred -u "$tmp_file" 2>/dev/null || rm -f "$tmp_file"
      rdie "Decryption succeeded but resulted in an empty file: $tmp_file"
  fi

  # Return the path to the temporary decrypted file
  # Caller is responsible for cleaning up this file using shred/rm
  printf '%s' "$tmp_file"
}

# Wrapper for docker compose down
compose_down() {
    log_info "Stopping Docker Compose stack (project: ${COMPOSE_PROJECT_NAME:-vaultwarden})..."
    # Use system lib helper if available
    if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _run_command >/dev/null; then
         _run_command "Stop stack via compose down" docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" down --remove-orphans || rdie "compose down failed"
    else
         # Fallback direct execution
         (cd "$PROJECT_ROOT" && docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" down --remove-orphans) || rdie "compose down failed"
    fi
    log_success "Stack stopped."
}

# Wrapper for docker compose up -d
compose_up() {
    log_info "Starting Docker Compose stack (project: ${COMPOSE_PROJECT_NAME:-vaultwarden})..."
     if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _run_command >/dev/null; then
          _run_command "Start stack via compose up" docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" up -d --remove-orphans || rdie "compose up failed"
     else
          (cd "$PROJECT_ROOT" && docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" up -d --remove-orphans) || rdie "compose up failed"
     fi
     log_success "Stack started."
}

# Wrapper for docker compose restart
compose_restart() {
    log_info "Restarting Docker Compose stack (project: ${COMPOSE_PROJECT_NAME:-vaultwarden})..."
     if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]] && declare -f _run_command >/dev/null; then
          _run_command "Restart stack via compose restart" docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" restart || rdie "compose restart failed"
     else
          (cd "$PROJECT_ROOT" && docker compose -p "${COMPOSE_PROJECT_NAME:-vaultwarden}" restart) || rdie "compose restart failed"
     fi
     log_success "Stack restarted."
}

# Health check function, uses container names from config
health_check() {
  local retries="${1:-30}" # Default retries: 30
  local sleep_s="${2:-5}" # Default sleep: 5 seconds
  local ok=false # Use boolean flag

  # Ensure container names are set
  if [[ -z "$BW_VW" || -z "$BW_CADDY" ]]; then
       rdie "Container names (BW_VW, BW_CADDY) not defined. Config load likely failed."
  fi

  rlog "Performing health check on critical containers: $BW_VW, $BW_CADDY (up to $retries attempts)"
  local i vw_health caddy_health vw_status caddy_status

  for i in $(seq 1 "$retries"); do
    _log_debug "Health check attempt $i/$retries..."
    # Get status and health using docker inspect
    vw_info=$(docker inspect "$BW_VW" 2>/dev/null) || vw_info=""
    caddy_info=$(docker inspect "$BW_CADDY" 2>/dev/null) || caddy_info=""

    # Extract status and health safely using jq if available, else grep/awk
    if command -v jq >/dev/null; then
        vw_status=$(echo "$vw_info" | jq -r '.[0].State.Status // "error"')
        vw_health=$(echo "$vw_info" | jq -r '.[0].State.Health.Status // "none"')
        caddy_status=$(echo "$caddy_info" | jq -r '.[0].State.Status // "error"')
        caddy_health=$(echo "$caddy_info" | jq -r '.[0].State.Health.Status // "none"')
    else
         # Fallback parsing (less robust)
         vw_status=$(echo "$vw_info" | grep '"Status":' | head -n1 | sed -e 's/.*"Status": "\(.*\)",/\1/' || echo "error")
         vw_health=$(echo "$vw_info" | grep '"Status":' | tail -n1 | sed -e 's/.*"Status": "\(.*\)",/\1/' || echo "none") # Rough guess for health
         caddy_status=$(echo "$caddy_info" | grep '"Status":' | head -n1 | sed -e 's/.*"Status": "\(.*\)",/\1/' || echo "error")
         caddy_health=$(echo "$caddy_info" | grep '"Status":' | tail -n1 | sed -e 's/.*"Status": "\(.*\)",/\1/' || echo "none")
    fi


    _log_debug "Status - VW: $vw_status ($vw_health), Caddy: $caddy_status ($caddy_health)"

    # Check conditions for success:
    # - Both containers must be 'running'
    # - Vaultwarden must be 'healthy'
    # - Caddy must be 'healthy' OR 'none' (if no health check defined)
    if [[ "$vw_status" == "running" && "$caddy_status" == "running" ]] && \
       [[ "$vw_health" == "healthy" ]] && \
       [[ "$caddy_health" == "healthy" || "$caddy_health" == "none" ]]; then
      ok=true
      break # Exit loop on success
    fi

    # Log specific reasons for waiting if possible
    local wait_reason=""
    [[ "$vw_status" != "running" ]] && wait_reason+="VW not running; "
    [[ "$caddy_status" != "running" ]] && wait_reason+="Caddy not running; "
    [[ "$vw_health" == "unhealthy" ]] && wait_reason+="VW unhealthy; "
    [[ "$vw_health" == "starting" ]] && wait_reason+="VW starting; "
    [[ "$caddy_health" == "unhealthy" ]] && wait_reason+="Caddy unhealthy; "
    [[ "$caddy_health" == "starting" ]] && wait_reason+="Caddy starting; "

    rlog "Health check attempt $i/$retries failed (${wait_reason%,* }). Retrying in ${sleep_s}s..."
    sleep "$sleep_s"
  done

  if [[ "$ok" == true ]]; then
       log_success "Health check passed."
       return 0
  else
       log_error "Health check failed after $retries attempts."
       # Log final status again for clarity
       log_error "Final Status - VW: $vw_status ($vw_health), Caddy: $caddy_status ($caddy_health)"
       return 1
  fi
}

# Restores SQLite DB from a decrypted .sqlite3 file into the data directory
# Usage: restore_db_sqlite <decrypted_sqlite_file>
restore_db_sqlite() {
  local decrypted_sqlite="$1"
  local target="$DATA_DIR/db.sqlite3" # Use defined DATA_DIR
  # Secure temporary file within DATA_DIR if possible, else /tmp
  local temp_target
  if [[ -w "$DATA_DIR" ]]; then
       temp_target=$(mktemp -p "$DATA_DIR" "db.sqlite3.tmp.XXXXXX") || temp_target=$(mktemp "/tmp/db.sqlite3.tmp.XXXXXX")
  else
       temp_target=$(mktemp "/tmp/db.sqlite3.tmp.XXXXXX")
  fi
  [[ -z "$temp_target" ]] && rdie "Failed to create temporary file for DB restore."

  # Ensure temp target is cleaned up
  trap 'log_info "Cleaning up temporary DB file: $temp_target"; shred -u "$temp_target" 2>/dev/null || rm -f "$temp_target"' RETURN EXIT INT TERM

  log_info "Restoring SQLite database to $target from $(basename "$decrypted_sqlite")"

  # Ensure target directory exists (use system lib helper if available)
  if declare -f _create_directory_secure >/dev/null; then
       _create_directory_secure "$DATA_DIR" || rdie "Failed to create/access target directory $DATA_DIR"
  else
       mkdir -p "$DATA_DIR" || rdie "Failed to create target directory $DATA_DIR"
  fi


  # Copy source to temp file first for integrity check
  _log_debug "Copying source DB to temporary location: $temp_target"
  if ! cp -f "$decrypted_sqlite" "$temp_target"; then
      rdie "Failed to copy source database '$decrypted_sqlite' to temporary location '$temp_target'"
  fi

  # Check integrity of the copied temp file before moving
  log_info "Verifying integrity of the staged database..."
  local integrity_output integrity_rc
  integrity_output=$(sqlite3 "$temp_target" "PRAGMA integrity_check;" 2>&1)
  integrity_rc=$?
  if [[ $integrity_rc -ne 0 ]]; then
      rdie "sqlite3 command failed during integrity check on staged DB (rc=$integrity_rc). Output: $integrity_output"
  elif [[ "$integrity_output" != "ok" ]]; then
      rdie "Restored database integrity check FAILED on staged file. Details: $integrity_output"
  fi
  log_success "Staged database integrity verified."


  # Atomically move the verified temp file to the final target
  log_info "Moving verified database to final location: $target"
  # Use mv -f to overwrite existing file
  if ! mv -f "$temp_target" "$target"; then
      rdie "Failed to move temporary database '$temp_target' to final location '$target'"
  fi
  # Trap will handle cleanup of temp_target placeholder if mv fails, but mv removes it on success

  # Set appropriate permissions (e.g., owned by user 1000 for non-root container)
  log_info "Setting permissions on restored database file..."
  local target_owner="1000:1000" # Default for non-root VW container
  # Use chown with sudo if needed? Assume script runs as root for restore.
  if chown "$target_owner" "$target" && chmod 640 "$target"; then
       log_success "Permissions set for $target."
  else
       log_warn "Failed to set owner/permissions on restored database $target. Manual adjustment might be needed."
  fi

  log_success "Database successfully restored to $target."
  # Source file cleanup happens in the caller function's trap for decrypt_age_to_tmp
}


# Restores DB from a decrypted .sql dump file
# Usage: restore_db_from_sql_dump <decrypted_sql_file>
restore_db_from_sql_dump() {
  local decrypted_sql="$1"
  local target="$DATA_DIR/db.sqlite3" # Use defined DATA_DIR

  log_info "Restoring SQLite database to $target from SQL dump $(basename "$decrypted_sql")"

  # Ensure target directory exists
  if declare -f _create_directory_secure >/dev/null; then
       _create_directory_secure "$DATA_DIR" || rdie "Failed to create/access target directory $DATA_DIR"
  else
       mkdir -p "$DATA_DIR" || rdie "Failed to create target directory $DATA_DIR"
  fi

  # Remove existing DB file if it exists, before importing dump
  log_info "Removing existing database file (if any) at $target"
  rm -f "$target"

  # Import SQL dump into the new target file using sqlite3
  log_info "Importing SQL dump into new database file..."
  local import_output import_rc=0
  # Pipe dump content into sqlite3 command
  import_output=$(sqlite3 "$target" < "$decrypted_sql" 2>&1) || import_rc=$?

  if [[ $import_rc -ne 0 ]]; then
      rm -f "$target" # Clean up potentially corrupt target file
      rdie "Failed to import SQL dump into database (rc=$import_rc). Output: $import_output"
  fi
  # Check if target file was actually created and has size
  if [[ ! -s "$target" ]]; then
       rdie "SQL import command succeeded but database file '$target' is empty or missing."
  fi
  log_success "SQL dump imported successfully."


  # Check integrity of the newly created database
  log_info "Verifying integrity of the database created from SQL dump..."
  local integrity_output integrity_rc
  integrity_output=$(sqlite3 "$target" "PRAGMA integrity_check;" 2>&1)
  integrity_rc=$?
   if [[ $integrity_rc -ne 0 ]]; then
       rm -f "$target" # Clean up failed db
       rdie "sqlite3 command failed during integrity check after SQL import (rc=$integrity_rc). Output: $integrity_output"
   elif [[ "$integrity_output" != "ok" ]]; then
       rm -f "$target" # Clean up failed db
       rdie "Restored database integrity check FAILED after SQL import. Details: $integrity_output"
   fi
  log_success "Database integrity verified after SQL import."

  # Set permissions
  log_info "Setting permissions on restored database file..."
  local target_owner="1000:1000"
  if chown "$target_owner" "$target" && chmod 640 "$target"; then
       log_success "Permissions set for $target."
  else
       log_warn "Failed to set owner/permissions on restored database $target. Manual adjustment might be needed."
  fi

  log_success "Database successfully restored from SQL dump to $target."
  # Source file cleanup happens in the caller function's trap for decrypt_age_to_tmp
}

# Restore a Docker volume from a decrypted .tar.gz file
# Usage: restore_volume_from_tar <volume_name> <decrypted_tar_gz_file>
restore_volume_from_tar() {
  local vol="$1"
  local tar_gz_file="$2"

  log_info "Restoring Docker volume '$vol' from $(basename "$tar_gz_file")"

  # Ensure tarball exists and is readable
  [[ ! -r "$tar_gz_file" ]] && rdie "Tarball file not found or not readable: $tar_gz_file"

  # Ensure volume exists (create if not)
  if ! docker volume inspect "$vol" >/dev/null 2>&1; then
       log_info "Volume '$vol' does not exist. Creating it..."
       if ! docker volume create "$vol"; then
            rdie "Failed to create Docker volume '$vol'"
       fi
  fi

  # Run the restore container using alpine image
  # Mount the target volume to /v inside the container
  # Mount the directory containing the tarball as read-only to /backup
  log_info "Running restore container to extract tarball into volume '$vol'..."
  local restore_cmd restore_rc=0
  # Use docker run with --rm, volume mounts, and tar command inside alpine
  restore_cmd=(docker run --rm
       -v "$vol:/v" # Mount target volume
       -v "$(dirname "$tar_gz_file"):/backup:ro" # Mount backup dir read-only
       alpine:latest # Use a recent alpine image
       sh -lc "cd /v && tar -xzf /backup/$(basename "$tar_gz_file")" # Extract inside volume
  )

  _log_debug("Executing restore command: ${restore_cmd[*]}")
  if ! "${restore_cmd[@]}"; then
       rdie "Failed to restore volume '$vol' using restore container. Check Docker permissions and tarball integrity."
  fi

  log_success "Volume '$vol' successfully restored from '$(basename "$tar_gz_file")'."
  # Source file cleanup happens in the caller function's trap for decrypt_age_to_tmp
}


# Find latest encrypted DB backup file (now uses Age naming)
# Usage: latest_db=$(find_latest_db_encrypted [backup_root_dir])
find_latest_db_encrypted() {
  local root="${1:-$PROJECT_ROOT/backups/db}" # Default backup dir relative to project root
  # Look for files ending in .sqlite3.gz.age or .sql.gz.age
  _log_debug "Searching for latest encrypted DB backup in '$root'..."
  # Use find with -printf '%T@ %p\n', sort numerically reverse, take first line, extract path
  find "$root" -maxdepth 1 -type f \( -name 'vaultwarden-db-*.sqlite3.gz.age' -o -name 'vaultwarden-db-*.sql.gz.age' \) -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || echo ""
}

# Find latest encrypted Full backup file (now uses Age naming)
# Usage: latest_full=$(find_latest_full_encrypted [backup_root_dir])
find_latest_full_encrypted() {
  local root="${1:-$PROJECT_ROOT/backups/full}" # Default backup dir relative to project root
  _log_debug "Searching for latest encrypted Full backup in '$root'..."
  find "$root" -maxdepth 1 -type f -name 'vaultwarden-full-*.tar.gz.age' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || echo ""
}


# --- Self-Test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/restore-lib.sh is a library and should be sourced, not executed directly."
     # Add basic self-tests here if needed
     # Example: check commands, try finding backups
     _log_section "Restore Library Self-Test"
     export DEBUG=true
     need docker && log_success "Command check: docker found."
     need age && log_success "Command check: age found."
     need sqlite3 && log_success "Command check: sqlite3 found."
     need shred && log_success "Command check: shred found."
     need gunzip && log_success "Command check: gunzip found."
     need tar && log_success "Command check: tar found."

     _log_info "Testing backup find functions..."
     mkdir -p backups/db backups/full # Create dummy dirs if needed
     touch backups/db/vaultwarden-db-20250101-000000.sqlite3.gz.age
     touch backups/full/vaultwarden-full-20250101-000000.tar.gz.age
     latest_db=$(find_latest_db_encrypted)
     [[ -n "$latest_db" ]] && log_success "Found latest DB backup: $latest_db" || log_warn "Could not find dummy DB backup."
     latest_full=$(find_latest_full_encrypted)
     [[ -n "$latest_full" ]] && log_success "Found latest Full backup: $latest_full" || log_warn "Could not find dummy Full backup."
     rm -rf backups # Clean up dummy files/dirs

     _log_info "Self-test finished."
     exit 0
else
      _log_debug "lib/restore-lib.sh loaded successfully as a library."
fi
