#!/usr/bin/env bash
# tools/db-backup.sh - Creates a secure, encrypted backup of the SQLite database using Age via API snapshot.

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
# Source config first for PROJECT_STATE_DIR and ADMIN_TOKEN
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh. Using defaults."
        # Define necessary defaults if config fails
        PROJECT_STATE_DIR="/var/lib/vaultwarden"
        ADMIN_TOKEN="" # Backup will fail without this
    fi
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    exit 1
fi
# Source constants if available (for paths)
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---


# --- Main Backup Function ---
main() {
    log_header "VaultWarden Database Backup (API Snapshot)"

    # Load configuration again just in case (load_config is idempotent)
    if ! load_config; then
        log_error "Fatal: Could not load project configuration. Aborting database backup."
        exit 1
    fi

    # --- Configuration Validation ---
    # Database path inside the container volume mount (for reference, not directly used)
    # local db_path_in_volume="/data/db.sqlite3"
    # Get state directory from loaded config or use default
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    # Host path to DB (for potential future checks, not used for API backup)
    # local host_db_path="${state_dir}/data/bwdata/db.sqlite3"
    local backup_dir="${PROJECT_ROOT}/backups/db" # Backups relative to project root
    # Use Age key file constant from constants.sh or default
    local public_key_file="${AGE_KEY_FILE:-secrets/keys/age-public-key.txt}"
    # Get ADMIN_TOKEN from secrets using get_secret
    local admin_token
    admin_token=$(get_secret "admin_token" "")
    # Vaultwarden API URL - assume localhost access is possible from where script runs
    local vaultwarden_api_url="http://localhost:8080" # Default, could be configurable

     # Check required commands
     local required_commands=("curl" "sqlite3" "gzip" "age" "mktemp" "shred" "rm" "file" "mkdir" "chmod" "cat")
      for cmd in "${required_commands[@]}"; do
          if ! command -v "$cmd" >/dev/null 2>&1; then
              log_error "Required command not found: $cmd"
              exit 1
          fi
      done


    # Validate essential variables/files needed for API backup
    if [[ -z "$admin_token" ]]; then log_error "ADMIN_TOKEN not found in loaded configuration/secrets. Cannot perform API backup."; exit 1; fi
    if [[ ! -f "$public_key_file" ]]; then log_error "Age public key file not found at $public_key_file"; exit 1; fi

    # Ensure backup directory exists
     if ! mkdir -p "$backup_dir"; then
         log_error "Failed to create backup directory: $backup_dir"
         exit 1
     fi
     log_success "Prerequisites checked successfully."

    # --- Backup Process ---
    local timestamp temp_db_backup final_backup_file
    timestamp=$(date +%Y%m%d-%H%M%S)
    # Create temp file securely in /tmp, ensure cleanup
    temp_db_backup=$(mktemp "/tmp/vw-db-snapshot-${timestamp}.XXXXXX.sqlite3") || { log_error "Failed to create temporary snapshot file"; exit 1; }
    # Ensure temp file is cleaned up securely on any exit
    trap 'log_info "Cleaning up temporary DB snapshot..."; shred -u "$temp_db_backup" 2>/dev/null || rm -f "$temp_db_backup"' EXIT HUP INT TERM

    final_backup_file="${backup_dir}/vaultwarden-db-${timestamp}.sqlite3.gz.age"

    # Use the /api/admin/db/backup endpoint for a safe, consistent snapshot
    log_info "Requesting database snapshot from VaultWarden API (${vaultwarden_api_url})..."
    local http_code curl_output
    # Capture HTTP status code separately, handle errors, add timeout
    http_code=$(curl -s -w "%{http_code}" -X POST "${vaultwarden_api_url}/api/admin/db/backup" \
        -H "Authorization: Bearer ${admin_token}" \
        -o "$temp_db_backup" --max-time 120) # Increased timeout to 2 minutes for potentially large DBs

    # Check HTTP status code
    if [[ "$http_code" -ne 200 ]]; then
        log_error "Failed to get database snapshot from API. HTTP Status: $http_code."
        log_error "Check if VaultWarden service is running, accessible at '$vaultwarden_api_url', ADMIN_TOKEN is correct, and API endpoint '/api/admin/db/backup' exists."
        # Optionally show response body if error (it's written to temp_db_backup on failure usually)
        if [[ -s "$temp_db_backup" ]]; then
             log_error "API Response Body (potential error message):"
             log_error "$(head -c 500 "$temp_db_backup")" # Show first 500 bytes
        fi
        exit 1 # Exit on API failure
    fi

    # Verify the downloaded snapshot is a valid SQLite file and has content
     if [[ ! -s "$temp_db_backup" ]]; then
          log_error "API request succeeded (HTTP 200) but downloaded snapshot file is empty or missing."
          exit 1
     fi
     # Use 'file' command to check type
     if ! file "$temp_db_backup" | grep -q "SQLite 3.x database"; then
         log_error "Downloaded file does not appear to be a valid SQLite database."
         log_error "File type detected: $(file "$temp_db_backup")"
         exit 1
     fi
     log_success "Database snapshot downloaded successfully."

    # Verify the snapshot integrity using sqlite3 PRAGMA check
    log_info "Verifying integrity of the downloaded snapshot..."
    local integrity_output integrity_rc
    integrity_output=$(sqlite3 "$temp_db_backup" "PRAGMA integrity_check;" 2>&1)
    integrity_rc=$?
    if [[ $integrity_rc -ne 0 ]]; then
        log_error "sqlite3 command failed during integrity check (rc=$integrity_rc)."
        log_error "Output: $integrity_output"
        exit 1
    elif [[ "$integrity_output" != "ok" ]]; then
        log_error "Snapshot integrity check FAILED. The downloaded database file may be corrupt."
        log_error "Details: $integrity_output"
        exit 1
    fi
    log_success "Database snapshot integrity verified successfully."


    # Compress and Encrypt using Age pipeline
    log_info "Compressing and encrypting backup to $(basename "$final_backup_file")..."
    # Read public key content directly
    local public_key_content
    public_key_content=$(cat "$public_key_file") || { log_error "Failed to read public key file '$public_key_file'"; exit 1; }

    # Pipeline: cat temp_db -> gzip -> age -> final_backup_file
    local pipeline_rc=0
    { cat "$temp_db_backup" | gzip -c | age -r "$public_key_content" > "$final_backup_file"; } || pipeline_rc=$?

    if [[ $pipeline_rc -eq 0 && -s "$final_backup_file" ]]; then
        chmod 640 "$final_backup_file" # Set reasonable permissions on backup file
        log_success "Encrypted database backup created successfully: $(basename "$final_backup_file")"
        log_info "Backup size: $(du -h "$final_backup_file" | cut -f1)"
    else
        log_error "Compression or Age encryption pipeline failed (rc=$pipeline_rc)."
        rm -f "$final_backup_file" # Clean up potentially incomplete encrypted file
        exit 1
    fi

    # Temp file is cleaned up by EXIT trap

    log_header "Database Backup Complete: $(basename "$final_backup_file")"
    return 0
}

# --- Script Entry Point ---
# Run main execution logic
main
