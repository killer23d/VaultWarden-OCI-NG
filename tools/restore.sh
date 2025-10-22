#!/usr/bin/env bash
# tools/restore.sh — unified interactive restore (DB-only or Full using Age)

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" # Change directory for consistency, relative paths might be used

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    # Define minimal log functions if logging.sh failed
    log_info() { echo "[restore.sh][INFO] $*"; }
    log_warn() { echo "[restore.sh][WARN] $*"; }
    log_error() { echo "[restore.sh][ERROR] $*" >&2; }
    log_success() { echo "[restore.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    log_header() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
else
    # Source logging if found
    source "lib/logging.sh"
fi

# Additional libraries as needed (add after logging.sh)
# Source config first (needed for paths, container names)
CONFIG_LOADED_SUCCESS=false
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    # load_config is called later
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    exit 1
fi
# Source restore library (contains core restore logic)
if [[ -f "lib/restore-lib.sh" ]]; then
    source "lib/restore-lib.sh"
else
     log_error "CRITICAL: Required library not found: lib/restore-lib.sh"
     exit 1
fi
# Source constants if available
if [[ -f "lib/constants.sh" ]]; then source "lib/constants.sh"; fi

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# Use logging functions defined above (from logging.sh or fallback)
log() { log_info "$*"; } # Alias log_info for internal messages
die() { log_error "$*"; exit 1; } # Alias log_error and exit


# --- Configuration and Checks ---
# Ensure necessary variables are loaded via load_config
if ! load_config; then
     die "Failed to load project configuration. Cannot proceed with restore."
fi

# Check if Age key file exists (needed for decryption)
readonly AGE_KEY_FILE="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
if [[ ! -r "$AGE_KEY_FILE" ]]; then
    die "Age private key file not found or not readable: $AGE_KEY_FILE"
fi

# Check required commands (some are checked in restore-lib.sh already)
need gunzip # For .gz archives
need tar   # For .tar archives
need find
need sort
need tail
need cut
need head # For interactive menu
need read # For interactive menu
need ls # For interactive menu


# --- Functions ---

# Helper function to prompt user for file selection interactively
# Usage: selected_file=$(choose_file "Prompt message" "backup_dir/*.age")
choose_file() {
  local prompt="$1"
  local pattern="${2:-*.age}" # Default pattern
  local files=() file_count=0 choice=0 selected=""

  log_info "$prompt" # Use log_info for prompt

  # Find files matching the pattern, handle spaces in names with null separator
  while IFS= read -r -d $'\0' file; do
    files+=("$file")
  done < <(find "$(dirname "$pattern")" -maxdepth 1 -type f -name "$(basename "$pattern")" -printf '%T@ %p\0' 2>/dev/null | sort -znr | cut -z -d' ' -f2-) # Sort newest first

  file_count=${#files[@]}

  if [[ $file_count -eq 0 ]]; then
      log_warn "No backup files found matching pattern: $pattern"
      return 1 # Indicate no file found
  fi

  # Present options
  echo "Available backups (newest first):"
  for i in $(seq 0 $((file_count - 1))); do
       # Display basename and modification time
       local filename mtime
       filename=$(basename "${files[$i]}")
       mtime=$(date -d "@$(stat -c %Y "${files[$i]}")" '+%Y-%m-%d %H:%M:%S')
       printf "  %d) %s (%s)\n" "$((i+1))" "$filename" "$mtime"
  done
  echo "  0) Cancel"

  # Get user choice
  while true; do
      read -p "Select backup file number [1-$file_count, 0 to cancel]: " choice
      # Validate input
      if [[ "$choice" =~ ^[0-9]+$ && $choice -ge 0 && $choice -le $file_count ]]; then
          if [[ $choice -eq 0 ]]; then
               log_info "Restore cancelled by user."
               return 1 # Indicate cancellation
          fi
          selected="${files[$((choice-1))]}"
          printf '%s' "$selected" # Output selected file path
          return 0 # Indicate success
      else
          log_error "Invalid selection. Please enter a number between 0 and $file_count."
      fi
  done
}

# Restore flow for Database Only backup
# Usage: restore_db_flow [source_age_file]
restore_db_flow() {
  local src="${1:-}" # Optional source file path
  local decrypted_file="" temp_uncompressed="" cleanup_files=() errors=0

  # --- Select Backup File ---
  if [[ -z "$src" ]]; then
    # Interactive selection or find latest automatically? Let's try interactive.
    # Use choose_file helper function
    src=$(choose_file "Select Database Backup to Restore:" "backups/db/vaultwarden-db-*.age") || return 1 # Exit if cancelled or none found
    if [[ -z "$src" ]]; then log_warn "No database backup file selected or found."; return 1; fi
  fi

  # Validate selected file exists
  [[ ! -f "$src" ]] && die "Selected backup file not found: $src"
  log "Selected DB backup for restore: $(basename "$src")"

  # --- Confirmation ---
  log_warn "!!! WARNING !!!"
  log_warn "This will STOP the VaultWarden service and OVERWRITE the current database."
  read -p "Are you absolutely sure you want to restore from '$(basename "$src")'? Type 'YES' to proceed: " -r confirm
  if [[ "$confirm" != "YES" ]]; then
      log_info "Restore cancelled by user."
      return 1
  fi


  # --- Execute Restore ---
  log_info "Proceeding with database restore..."

  log_info "Stopping VaultWarden service..."
  # Use compose down for just the service? Or stop? Stop is less disruptive.
  (cd "$PROJECT_ROOT" && docker compose stop vaultwarden) || log_warn "Failed to stop Vaultwarden service (maybe not running?). Continuing..."


  # --- Decrypt and Decompress ---
  log_info "Decrypting backup file..."
  decrypted_file=$(decrypt_age_to_tmp "$src" "$AGE_KEY_FILE") || errors=1
  cleanup_files+=("$decrypted_file") # Add to cleanup list

  if [[ $errors -eq 0 ]]; then
      log_info "Decompressing data..."
      # Check file type based on expected naming or magic bytes if needed
      if [[ "$decrypted_file" == *.sqlite3.gz ]]; then
          temp_uncompressed="${decrypted_file%.gz}"
          cleanup_files+=("$temp_uncompressed")
          if gunzip -c "$decrypted_file" > "$temp_uncompressed"; then
               log_success "Decompression successful."
          else
               log_error "Failed to decompress '$decrypted_file' using gunzip."
               errors=1
          fi
      elif [[ "$decrypted_file" == *.sql.gz ]]; then
           temp_uncompressed="${decrypted_file%.gz}"
           cleanup_files+=("$temp_uncompressed")
          if gunzip -c "$decrypted_file" > "$temp_uncompressed"; then
               log_success "Decompression successful."
          else
               log_error "Failed to decompress '$decrypted_file' using gunzip."
               errors=1
          fi
      else
          log_error "Unknown compression format for decrypted file: $decrypted_file"
          errors=1
      fi
  fi

  # --- Restore Database ---
  if [[ $errors -eq 0 ]]; then
      log_info "Restoring database..."
      if [[ "$temp_uncompressed" == *.sqlite3 ]]; then
           restore_db_sqlite "$temp_uncompressed" || errors=1 # restore_db_sqlite handles its own cleanup of source
           # Remove from cleanup list as restore_db_sqlite handles it
           cleanup_files=("${cleanup_files[@]/$temp_uncompressed}")
      elif [[ "$temp_uncompressed" == *.sql ]]; then
           restore_db_from_sql_dump "$temp_uncompressed" || errors=1 # restore_db_from_sql_dump handles its own cleanup
           cleanup_files=("${cleanup_files[@]/$temp_uncompressed}")
      else
           log_error "Cannot determine restore method for uncompressed file: $temp_uncompressed"
           errors=1
      fi
  fi


  # --- Cleanup Temporary Files ---
  log_info "Cleaning up temporary decryption/decompression files..."
  for file in "${cleanup_files[@]}"; do
       if [[ -n "$file" && -f "$file" ]]; then # Check if not empty string and exists
            log_debug "Shredding/removing: $file"
            shred -u "$file" 2>/dev/null || rm -f "$file"
       fi
  done


  # --- Restart Service and Health Check ---
  if [[ $errors -eq 0 ]]; then
      log_info "Starting VaultWarden service..."
      # Use compose up to ensure container is created if it was down/removed
      (cd "$PROJECT_ROOT" && docker compose up -d vaultwarden) || die "Failed to start VaultWarden service after restore."

      log_info "Performing health check (waiting up to ~2.5 minutes)..."
      # Use health_check function from restore-lib.sh
      if ! health_check 30 5; then # 30 retries * 5 sec = 150 seconds max wait
           log_error "VaultWarden health check FAILED after database restore. Check container logs."
           die "Restore completed but service is unhealthy."
      fi
      log_success "Database restore complete and service is healthy."
  else
      log_error "Database restore FAILED due to errors."
      log_info "VaultWarden service was not restarted. Manual intervention required."
      die "Restore process failed."
  fi
}


# Restore flow for Full System Backup
# Usage: restore_full_flow [source_age_file]
restore_full_flow() {
  local src="${1:-}" # Optional source file path
  local decrypted_file="" temp_tarfile="" staging_dir="" cleanup_files=() errors=0

  # --- Select Backup File ---
  if [[ -z "$src" ]]; then
    src=$(choose_file "Select Full Backup to Restore:" "backups/full/vaultwarden-full-*.tar.gz.age") || return 1
    if [[ -z "$src" ]]; then log_warn "No full backup file selected or found."; return 1; fi
  fi

  [[ ! -f "$src" ]] && die "Selected full backup file not found: $src"
  log "Selected Full backup for restore: $(basename "$src")"

  # --- Confirmation ---
  log_warn "!!! WARNING !!!"
  log_warn "This will STOP ALL services (VaultWarden, Caddy, etc.)"
  log_warn "This will OVERWRITE configuration files (.env, Caddyfile, docker-compose.yml, secrets) and the database."
  log_warn "It might also attempt to restore Docker volumes (Caddy data/config)."
  read -p "Are you absolutely sure you want to perform a FULL restore from '$(basename "$src")'? Type 'YES' to proceed: " -r confirm
  if [[ "$confirm" != "YES" ]]; then
      log_info "Restore cancelled by user."
      return 1
  fi


  # --- Execute Restore ---
  log_info "Proceeding with full system restore..."

  log_info "Stopping entire Docker Compose stack..."
  compose_down # Use helper from restore-lib.sh


  # --- Decrypt and Extract ---
  log_info "Decrypting backup file..."
  decrypted_file=$(decrypt_age_to_tmp "$src" "$AGE_KEY_FILE") || errors=1
  cleanup_files+=("$decrypted_file")

  if [[ $errors -eq 0 ]]; then
      if [[ "$decrypted_file" != *.tar.gz ]]; then
           log_error "Decrypted file is not a .tar.gz archive: $decrypted_file"
           errors=1
      else
           log_info "Decompressing archive..."
           temp_tarfile="${decrypted_file%.gz}" # Path for the .tar file
           cleanup_files+=("$temp_tarfile")
           if gunzip -c "$decrypted_file" > "$temp_tarfile"; then
                log_success "Decompression successful."
           else
                log_error "Failed to decompress '$decrypted_file' using gunzip."
                errors=1
           fi
      fi
  fi

  if [[ $errors -eq 0 ]]; then
       log_info "Creating staging directory for extraction..."
       staging_dir=$(mktemp -d -p "$PROJECT_ROOT" "restore-stage.${RANDOM}XXXXXX") || { log_error "Failed to create staging directory"; errors=1; }
       # Add staging dir to cleanup, ensure recursive removal
       trap 'log_info "Cleaning up staging directory: $staging_dir"; rm -rf "$staging_dir"' RETURN EXIT INT TERM # Append to existing trap? No, create local trap.

       if [[ $errors -eq 0 ]]; then
            log_info "Extracting archive to staging directory: $staging_dir"
            # Extract tarball content into the staging directory
            if tar -xf "$temp_tarfile" -C "$staging_dir"; then
                 log_success "Archive extracted successfully."
            else
                 log_error "Failed to extract tar archive '$temp_tarfile'."
                 errors=1
            fi
       fi
  fi

  # --- Restore Components ---
  if [[ $errors -eq 0 ]]; then
       # Restore Config Files (overwrite existing files in project root)
       log_info "Restoring configuration files..."
       if [[ -d "$staging_dir/config" ]]; then
            # Use rsync for potentially safer copy? Or just cp -a? cp -a is simpler.
            # Overwrite existing files in PROJECT_ROOT from staging_dir/config
             if cp -a "$staging_dir/config/." "$PROJECT_ROOT/"; then # Copy contents of config/
                  log_success "Configuration files restored."
             else
                  log_warn "Failed to copy some configuration files. Manual check might be needed."
                  # Don't mark as critical error? Depends. Let's warn for now.
             fi
       else
            log_warn "No 'config' directory found in backup archive staging area. Skipping config file restore."
       fi

       # Restore Secrets (Age key, secrets.yaml - overwrite existing)
       log_info "Restoring secrets..."
       if [[ -d "$staging_dir/secrets" ]]; then
            # Be careful with permissions here
            # Copy secrets.yaml
            if [[ -f "$staging_dir/secrets/secrets.yaml" ]]; then
                 cp -a "$staging_dir/secrets/secrets.yaml" "$PROJECT_ROOT/secrets/" || log_error "Failed to restore secrets.yaml"
                 # Permissions should be set correctly on startup/validation, but set 600 for safety?
                 chmod 600 "$PROJECT_ROOT/secrets/secrets.yaml" || log_warn "Failed to set permissions on secrets.yaml"
            else log_warn "secrets.yaml not found in backup staging."; fi
            # Copy Age keys
            if [[ -d "$staging_dir/secrets/keys" ]]; then
                 mkdir -p "$PROJECT_ROOT/secrets/keys" # Ensure keys dir exists
                 cp -a "$staging_dir/secrets/keys/." "$PROJECT_ROOT/secrets/keys/" || log_error "Failed to restore Age keys"
                 # Enforce permissions on restored keys
                 chmod 700 "$PROJECT_ROOT/secrets/keys" || log_warn "Failed to set permissions on secrets/keys dir"
                 chmod 600 "$PROJECT_ROOT/secrets/keys/age-key.txt" || log_warn "Failed to set permissions on restored private key"
                 chmod 644 "$PROJECT_ROOT/secrets/keys/age-public-key.txt" || log_warn "Failed to set permissions on restored public key"
                 log_success "Secrets and keys restored."
            else log_warn "Age keys directory not found in backup staging."; fi
       else
            log_warn "No 'secrets' directory found in backup archive staging area. Skipping secrets restore."
       fi

       # Restore Database (from embedded data/bwdata/db.sqlite3 in staging)
       log_info "Restoring database from archive..."
       local db_in_staging="$staging_dir/data/bwdata/db.sqlite3"
       if [[ -f "$db_in_staging" ]]; then
            # Use restore_db_sqlite helper, it handles copy, verify, move, permissions
            restore_db_sqlite "$db_in_staging" || errors=1 # Pass staging path as source
            # restore_db_sqlite doesn't cleanup its source, staging dir cleanup handles it.
       else
            log_warn "No database file (data/bwdata/db.sqlite3) found in backup staging area. Skipping database restore."
            log_warn "If you need to restore the DB, use a separate DB backup file."
       fi

        # Restore Attachments (if they exist in staging)
        local attachments_in_staging="$staging_dir/data/bwdata/attachments"
        if [[ -d "$attachments_in_staging" ]]; then
            log_info "Restoring attachments..."
            local target_attachments_dir="$DATA_DIR/attachments"
            mkdir -p "$target_attachments_dir" || log_error "Failed to create target attachments directory."
            # Use rsync to copy attachments
            if rsync -a --delete "$attachments_in_staging/" "$target_attachments_dir/"; then
                 log_success "Attachments restored."
                 # Set permissions (owned by user 1000)
                 chown -R 1000:1000 "$target_attachments_dir" || log_warn "Failed to set ownership on attachments."
                 chmod -R u=rwX,g=rX,o= "$target_attachments_dir" || log_warn "Failed to set permissions on attachments."
            else
                 log_error "Failed to restore attachments using rsync."
                 errors=1
            fi
        else
             _log_debug("No attachments directory found in backup staging. Skipping attachment restore.")
        fi


       # Restore Caddy Volumes (Optional - Docker volumes are usually persistent)
       # Maybe skip this by default unless user explicitly requests?
       # Example: Check if volume tarballs exist in staging
       # if [[ -f "$staging_dir/volume-caddy_data.tar.gz" ]]; then
       #     log_info "Restoring Caddy data volume..."
       #     restore_volume_from_tar "caddy_data" "$staging_dir/volume-caddy_data.tar.gz" || errors=1
       # fi
       # if [[ -f "$staging_dir/volume-caddy_config.tar.gz" ]]; then
       #     log_info "Restoring Caddy config volume..."
       #     restore_volume_from_tar "caddy_config" "$staging_dir/volume-caddy_config.tar.gz" || errors=1
       # fi
       log_info "Skipping Docker volume restore (volumes are typically persistent). Restore manually if needed."

  fi


  # --- Cleanup Temporary Files ---
  # Staging dir cleanup handled by trap
  log_info "Cleaning up temporary decryption/decompression files..."
  for file in "${cleanup_files[@]}"; do
       if [[ -n "$file" && -f "$file" ]]; then
            log_debug "Shredding/removing: $file"
            shred -u "$file" 2>/dev/null || rm -f "$file"
       fi
  done


  # --- Restart Stack and Health Check ---
  if [[ $errors -eq 0 ]]; then
      log_info "Full restore process appears complete. Starting services..."
      compose_up || die "Failed to start services after full restore."

      log_info "Performing health check (waiting up to ~2.5 minutes)..."
      if ! health_check 30 5; then
           log_error "Stack health check FAILED after full restore. Check container logs."
           die "Restore completed but stack is unhealthy."
      fi
      log_success "Full restore complete and stack is healthy."
  else
       log_error "Full restore FAILED due to errors during component restoration."
       log_info "Services were not restarted. Manual intervention required."
       die "Restore process failed."
  fi
}


# --- Usage and Main Logic ---
usage() {
  cat << EOF
Usage: $0 [--db [<db-backup.age>] | --full [<full-archive.age>] | --interactive]
Performs a restore of either the database or the full system state.

Options:
  --db [<file.age>]   Restore database only. If no file specified, prompts interactively.
                      Restores from the latest backup automatically if non-interactive and no file given.
  --full [<file.age>] Restore full system (config, secrets, DB, attachments). Prompts if no file.
                      Restores from latest automatically if non-interactive and no file given.
  --interactive       Force interactive menu to choose restore type and file.
  --help              Show this help message.

WARNING: Restore operations stop services and overwrite data. Use with caution.
EOF
}

# --- Main Execution Logic ---
# Default to interactive if no args provided
if [[ $# -eq 0 ]]; then
    log_info "No options provided. Starting interactive mode."
    set -- "--interactive" # Set interactive flag
fi

# Parse arguments
RESTORE_TYPE="" # 'db' or 'full'
SOURCE_FILE=""
INTERACTIVE=false

while [[ $# -gt 0 ]]; do
  case "${1}" in
    --db)
        RESTORE_TYPE="db"
        # Check if next argument exists and is not another option flag
        if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then
            SOURCE_FILE="$2"
            shift 2
        else
             # No file provided after --db, will prompt or find latest later
             shift 1
        fi
        ;;
    --full)
        RESTORE_TYPE="full"
        if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then
            SOURCE_FILE="$2"
            shift 2
        else
             shift 1
        fi
        ;;
    --interactive)
        INTERACTIVE=true
        shift 1
        ;;
    --help)
         usage
         exit 0
         ;;
    *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
  esac
done

# --- Execute based on parsed options ---
if [[ "$INTERACTIVE" == true ]]; then
  echo "Select restore mode:"
  echo "  1) Database-only restore"
  echo "  2) Full system restore"
  echo "  0) Cancel"
  local choice=""
  while true; do
      read -p "Choice [1, 2, 0]: " choice
      case "$choice" in
        1) restore_db_flow ""; break ;; # Pass empty string to trigger file selection
        2) restore_full_flow ""; break ;; # Pass empty string to trigger file selection
        0) log_info "Restore cancelled."; exit 0 ;;
        *) log_error "Invalid choice." ;;
      esac
  done
elif [[ "$RESTORE_TYPE" == "db" ]]; then
    # Non-interactive DB restore
    if [[ -z "$SOURCE_FILE" ]]; then
         log_info "No DB source file specified, attempting to restore from latest..."
         SOURCE_FILE=$(find_latest_db_encrypted) || SOURCE_FILE=""
         if [[ -z "$SOURCE_FILE" ]]; then
              die "Could not find latest DB backup file automatically."
         fi
         log_info "Using latest DB backup: $(basename "$SOURCE_FILE")"
    fi
    restore_db_flow "$SOURCE_FILE"
elif [[ "$RESTORE_TYPE" == "full" ]]; then
    # Non-interactive Full restore
     if [[ -z "$SOURCE_FILE" ]]; then
         log_info "No Full source file specified, attempting to restore from latest..."
         SOURCE_FILE=$(find_latest_full_encrypted) || SOURCE_FILE=""
          if [[ -z "$SOURCE_FILE" ]]; then
              die "Could not find latest Full backup file automatically."
          fi
          log_info "Using latest Full backup: $(basename "$SOURCE_FILE")"
     fi
    restore_full_flow "$SOURCE_FILE"
else
    # Should not happen if argument parsing is correct, but catch anyway
    log_error "Invalid state: No restore type determined."
    usage
    exit 1
fi

# Exit with success if restore function didn't exit with error
exit 0
