#!/usr/bin/env bash
# tools/create-full-backup.sh - Creates a full system backup (data + config) using Age.

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
        ADMIN_TOKEN="" # Backup will likely fail without this
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
    log_header "VaultWarden Full System Backup"

    # Load configuration again just in case (load_config is idempotent)
    if ! load_config; then
        log_error "Fatal: Could not load configuration. Aborting full backup."
        exit 1
    fi

    # --- Configuration Validation ---
    # Use constants if available, else defaults
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    local backup_dir="${PROJECT_ROOT}/backups/full" # Store backups relative to project root
    local public_key_file="${AGE_KEY_FILE:-secrets/keys/age-public-key.txt}"
    # Secure temp file location
    local temp_db_backup
    temp_db_backup=$(mktemp "/tmp/vw-full-db-snapshot-$(date +%Y%m%d-%H%M%S).XXXXXX.sqlite3") || { log_error "Failed to create temporary DB file"; exit 1; }
    # Ensure temp DB file is cleaned up securely
    trap 'log_info "Cleaning up temporary DB snapshot..."; shred -u "$temp_db_backup" 2>/dev/null || rm -f "$temp_db_backup"' EXIT HUP INT TERM

    # Check required commands
    local required_commands=("curl" "sqlite3" "tar" "gzip" "age" "rsync" "mkdir" "mktemp" "shred" "rm")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            # Ensure trap cleans up if we exit here
            exit 1
        fi
    done


    # Validate essential config/files
    # Check data directory structure
    if [[ ! -d "$state_dir/data/bwdata" ]]; then log_error "Vaultwarden data directory not found at $state_dir/data/bwdata"; exit 1; fi
    # Check Age public key
    if [[ ! -f "$public_key_file" ]]; then log_error "Age public key file not found at $public_key_file"; exit 1; fi
    # Check ADMIN_TOKEN (must be retrieved after load_config)
    local admin_token
    admin_token=$(get_secret "admin_token" "") # Get from secrets
    if [[ -z "$admin_token" ]]; then log_error "ADMIN_TOKEN not found in loaded secrets. Cannot perform API backup."; exit 1; fi

    # Ensure backup directory exists
    if ! mkdir -p "$backup_dir"; then log_error "Failed to create backup directory: $backup_dir"; exit 1; fi
    log_success "Prerequisites checked successfully."

    # --- Backup Process ---
    log_info "Requesting a safe database snapshot via VaultWarden API..."
    local http_code vaultwarden_api_url="http://localhost:8080" # Assume local access from host
    # Capture HTTP status code separately, handle errors
    http_code=$(curl -s -w "%{http_code}" -X POST "${vaultwarden_api_url}/api/admin/db/backup" \
        -H "Authorization: Bearer ${admin_token}" \
        -o "$temp_db_backup" --max-time 120) # Increased timeout to 2 mins

    if [[ "$http_code" -ne 200 ]]; then
        log_error "Failed to get database snapshot from API. HTTP Status: $http_code."
        log_error "Check if VaultWarden service is running, accessible at '$vaultwarden_api_url', and ADMIN_TOKEN is correct."
        exit 1
    fi
    # Check if downloaded file is empty or not SQLite
     if ! file "$temp_db_backup" | grep -q "SQLite 3.x database"; then
         log_error "Downloaded snapshot file does not appear to be a valid SQLite database."
         log_error "File type: $(file "$temp_db_backup")"
         exit 1
     fi
     log_success "Database snapshot downloaded successfully."

    # Verify the snapshot integrity
    log_info "Verifying integrity of the downloaded snapshot..."
    if ! sqlite3 "$temp_db_backup" "PRAGMA integrity_check;" | grep -q "ok"; then
        log_error "Downloaded snapshot integrity check FAILED. The database file may be corrupt."
        exit 1
    fi
    log_success "Database snapshot integrity verified."

    # --- Create Full Archive ---
    local timestamp temp_tar_file final_backup_file temp_bwdata_dir
    timestamp=$(date +%Y%m%d-%H%M%S)
    temp_tar_file=$(mktemp "/tmp/vw-full-backup-${timestamp}.XXXXXX.tar") || { log_error "Failed to create temporary TAR file"; exit 1; }
    # Ensure temp TAR file is cleaned up securely
    trap 'log_info "Cleaning up temporary files..."; shred -u "$temp_db_backup" 2>/dev/null || rm -f "$temp_db_backup"; shred -u "$temp_tar_file" 2>/dev/null || rm -f "$temp_tar_file"; rm -rf "$temp_bwdata_dir"' EXIT HUP INT TERM

    temp_bwdata_dir=$(mktemp -d "/tmp/bwdata_tmp.XXXXXX") || { log_error "Failed to create temporary bwdata directory"; exit 1; }
    # Trap already handles cleanup of this dir if it exists

    final_backup_file="${backup_dir}/vaultwarden-full-${timestamp}.tar.gz.age"

    log_info "Staging files for the full backup archive..."

    # Create a temporary bwdata structure
    # Copy the verified snapshot into the staging dir with the correct name
    cp "$temp_db_backup" "$temp_bwdata_dir/db.sqlite3" || { log_error "Failed to copy DB snapshot to staging"; exit 1; }
    chmod 640 "$temp_bwdata_dir/db.sqlite3" # Set permissions in staging

    # Copy other non-database files (attachments, config.json etc.) from the live data directory using rsync
    # Exclude SQLite database and related files (-wal, -shm)
    log_info "Syncing non-database files from live data directory..."
    rsync -a --exclude 'db.sqlite3*' "${state_dir}/data/bwdata/" "$temp_bwdata_dir/" || log_warn "Rsync failed for some non-database files. Backup might be incomplete."

    log_info "Creating temporary TAR archive..."
    # List of files and directories (relative to PROJECT_ROOT) to include in the backup
    # Use absolute paths for source files/dirs for tar for clarity
    local files_to_include=(
        "$temp_bwdata_dir" # Staged bwdata including safe DB snapshot
        # Configuration files
        "$PROJECT_ROOT/caddy/Caddyfile"
        "$PROJECT_ROOT/caddy/cloudflare-ips.caddy" # Include even if potentially outdated, updated daily
        "$PROJECT_ROOT/fail2ban/jail.local"
        "$PROJECT_ROOT/.env"
        "$PROJECT_ROOT/docker-compose.yml"
        # Secrets (encrypted)
        "$PROJECT_ROOT/secrets/secrets.yaml"
        "$PROJECT_ROOT/secrets/keys/age-key.txt" # Include private key for easier recovery
        "$PROJECT_ROOT/secrets/keys/age-public-key.txt"
        # Optional: Include templates? Maybe not essential for restore if git clone is done first.
        # "$PROJECT_ROOT/templates/ddclient.conf.tmpl"
        # Optional: Include fail2ban filters?
        # "$PROJECT_ROOT/fail2ban/filter.d"
    )
    local tar_options=(
        "--create"
        "--file=$temp_tar_file"
        "--absolute-names" # Store absolute paths in tar? Or relative? Relative is better for restore.
        # Use --transform to create relative paths inside the archive
        "--transform=s|^${temp_bwdata_dir}|data/bwdata|" # Stage dir -> data/bwdata
        "--transform=s|^${PROJECT_ROOT}/caddy|config/caddy|"
        "--transform=s|^${PROJECT_ROOT}/fail2ban|config/fail2ban|"
        "--transform=s|^${PROJECT_ROOT}/.env|config/.env|"
        "--transform=s|^${PROJECT_ROOT}/docker-compose.yml|config/docker-compose.yml|"
        "--transform=s|^${PROJECT_ROOT}/secrets/secrets.yaml|secrets/secrets.yaml|"
        "--transform=s|^${PROJECT_ROOT}/secrets/keys/|secrets/keys/|"
        # Add more transforms if including templates or filters
        # Ensure only specified files/dirs are added
        "--no-recursion" # Prevent adding unexpected subdirs unless explicitly listed
    )

    # Add files/dirs to tar command, checking existence first
    local missing_files=0
    for item in "${files_to_include[@]}"; do
        if [[ -e "$item" ]]; then
            tar_options+=("$item")
        else
            log_warn "Item not found, skipping from backup: $item"
            ((missing_files++))
        fi
    done

    # Create the archive
    if ! tar "${tar_options[@]}"; then
        log_error "Failed to create temporary TAR archive '$temp_tar_file'."
        exit 1
    fi

    # Verify tar file was created and is not empty
    if [[ ! -s "$temp_tar_file" ]]; then
        log_error "Temporary TAR archive is empty or was not created."
        exit 1
    fi
    log_success "Temporary TAR archive created successfully."

    # Compress and Encrypt using Age pipeline
    log_info "Compressing and encrypting backup to $(basename "$final_backup_file")..."
    # Read public key content directly
    local public_key_content
    public_key_content=$(cat "$public_key_file") || { log_error "Failed to read public key file '$public_key_file'"; exit 1; }

    # Pipeline: cat tar -> gzip -> age -> output file
    if cat "$temp_tar_file" | gzip -c | age -r "$public_key_content" > "$final_backup_file"; then
        chmod 640 "$final_backup_file" # Set reasonable permissions
        log_success "Full backup created successfully: $final_backup_file"
    else
        log_error "Compression or Age encryption pipeline failed."
        rm -f "$final_backup_file" # Clean up potentially incomplete encrypted file
        exit 1
    fi

    # Secure cleanup happens via EXIT trap

    log_header "Full Backup Complete: $(basename "$final_backup_file")"
    # Optional: Log size
    log_info "Backup size: $(du -h "$final_backup_file" | cut -f1)"
}

# --- Script Entry Point ---
# Run main execution logic
main
