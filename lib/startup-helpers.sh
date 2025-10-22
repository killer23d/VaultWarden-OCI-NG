#!/usr/bin/env bash
# lib/startup-helpers.sh - Helper functions extracted from startup.sh for modularity.

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
    log_info() { echo "[startup-helpers.sh][INFO] $*"; }
    log_warn() { echo "[startup-helpers.sh][WARN] $*"; }
    log_error() { echo "[startup-helpers.sh][ERROR] $*" >&2; }
    log_success() { echo "[startup-helpers.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    _print_key_value() { printf "%-20s: %s\n" "$1" "$2"; }
    log_error_with_help() { log_error "$1"; log_info "💡 Try: $2"; } # Basic fallback
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi

# Source other required libraries AFTER logging
# Source SOPS library (needed for prepare_docker_secrets)
SOPS_AVAILABLE=false
if [[ -f "$LIB_DIR/sops.sh" ]]; then
    source "$LIB_DIR/sops.sh"
    # Check if SOPS lib loaded successfully
    if [[ "${SOPS_LIB_LOADED:-false}" == "true" ]]; then
        SOPS_AVAILABLE=true
    else
        log_error "Failed to properly load SOPS library (lib/sops.sh)."
    fi
else
    log_error "CRITICAL: SOPS library not found: lib/sops.sh. Cannot manage secrets."
fi

# Source config library (needed everywhere)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then
    source "$LIB_DIR/config.sh"
    # Config is loaded later by startup.sh, but ensure library is available
else
    log_error "CRITICAL: Config library not found: lib/config.sh."
fi

# Source system library (for _have_cmd, _create_directory_secure etc)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then
    source "$LIB_DIR/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
    log_error "CRITICAL: System library not found: lib/system.sh."
    # Define fallback for _have_cmd if system lib fails?
     _have_cmd() { command -v "$1" >/dev/null 2>&1 && [[ -x "$(command -v "$1")" ]]; }
     # Fallbacks for other system functions might be needed if system.sh is critical
fi
# Source constants library (provides paths, permissions)
CONSTANTS_AVAILABLE=false
if [[ -f "$LIB_DIR/constants.sh" ]]; then
    source "$LIB_DIR/constants.sh"
    CONSTANTS_AVAILABLE=true
else
     log_warn "Constants library not found: lib/constants.sh. Using default values."
     # Define essential defaults if constants lib missing
     COMPOSE_FILE="docker-compose.yml"
     AGE_KEY_FILE="secrets/keys/age-key.txt"
     AGE_KEY_PERMISSIONS="600"
     DOCKER_SECRETS_DIR="secrets/.docker_secrets"
     DOCKER_SECRETS_DIR_PERMISSIONS="700"
     DOCKER_SECRET_FILE_PERMISSIONS="600"
     DEFAULT_COMPOSE_TIMEOUT_SECONDS=60
     HEALTH_CHECK_WAIT_SECONDS=30
fi

# --- Library functions follow ---


# Set prefix after sourcing logging
_set_log_prefix "startup-helpers"

# --- Functions ---

# Basic validation checks before startup
# Relies on constants and system library functions
basic_validation() {
    log_info "Running basic startup validation..."
    local errors=0

    # Use _have_cmd if available
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    # Docker checks
    if ! "$check_cmd_func" docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
        log_error_with_help "Docker daemon is not running, not installed, or user lacks permissions." "Check 'sudo systemctl status docker' or add user to 'docker' group (and relogin)."
        ((errors++))
    elif ! docker compose version >/dev/null 2>&1; then
         log_error_with_help "Docker Compose plugin (v2) not found or not working." "Install via 'sudo apt install docker-compose-plugin' or Docker Desktop."
         ((errors++))
    else
         _log_debug("Docker and Compose plugin checks passed.")
    fi

    # Config file checks (use constants for paths)
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Docker Compose file not found: $COMPOSE_FILE"
        ((errors++))
    fi
    if [[ ! -f ".env" ]]; then
         log_warn ".env file not found at $PROJECT_ROOT/.env. Using defaults might cause issues."
         # Allow continuing, maybe defaults are sufficient
    fi

    # SOPS/Age environment checks
    if [[ "$SOPS_AVAILABLE" == "true" ]]; then
        # Check Age key file existence and permissions rigorously
        if [[ ! -f "$AGE_KEY_FILE" ]]; then
             log_error "Age key file '$AGE_KEY_FILE' not found!"
             ((errors++))
        elif [[ ! -r "$AGE_KEY_FILE" ]]; then
             log_error "Age key file '$AGE_KEY_FILE' exists but is not readable!"
             ((errors++))
        else
            # Enforce permissions (use constant if available)
            local key_perms_target="${AGE_KEY_PERMISSIONS:-600}"
            local key_perms_actual
            key_perms_actual=$(stat -c "%a" "$AGE_KEY_FILE" 2>/dev/null) || key_perms_actual="unknown"

            # Check if permissions are exactly target OR 400 (read-only is also secure)
            if [[ "$key_perms_actual" != "$key_perms_target" && "$key_perms_actual" != "400" ]]; then
                log_warn "Incorrect permissions ($key_perms_actual) on Age key: $AGE_KEY_FILE. Attempting to set to $key_perms_target..."
                # Attempt to fix permissions (might need sudo if run by non-owner)
                local chmod_cmd="chmod"
                [[ $EUID -ne 0 && $(stat -c "%u" "$AGE_KEY_FILE") != "$(id -u)" ]] && chmod_cmd="sudo chmod"
                if ! $chmod_cmd "$key_perms_target" "$AGE_KEY_FILE"; then
                    log_error "Failed to set required $key_perms_target permissions on '$AGE_KEY_FILE'. Check ownership and privileges."
                    ((errors++))
                else
                     log_success "Corrected permissions on '$AGE_KEY_FILE' to $key_perms_target."
                fi
            else
                 _log_debug("Age key permissions ($key_perms_actual) are secure.")
            fi
        fi

        # Call validate_sops_environment from sops.sh AFTER checking key file explicitly
        if [[ $errors -eq 0 ]]; then
            if ! validate_sops_environment; then
                # Error messages logged by validate_sops_environment
                log_error "SOPS & Age environment validation failed. Cannot proceed without decrypting secrets."
                ((errors++))
            else
                 log_success "SOPS & Age environment validated successfully."
            fi
        fi
    else
         log_error "SOPS library is missing or failed to load. Cannot manage secrets."
         ((errors++))
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Basic validation failed with $errors critical error(s)."
        return 1
    fi

    log_success "Basic validation passed."
    return 0
}

# Centralized log directory creation
# Relies on system library functions and loaded config (PROJECT_STATE_DIR)
ensure_log_directories() {
    log_info "Ensuring necessary log and data directories exist..."
    local errors=0
    # Get state dir from loaded config or default
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    local log_owner owner_set=false target_owner=""

    # Determine the target owner:group for directories/logs
    # Prefer owner of state_dir if it exists, else try SUDO_USER, else current user
    if [[ -d "$state_dir" ]]; then
        target_owner=$(stat -c '%U:%G' "$state_dir" 2>/dev/null) || target_owner=""
        [[ -n "$target_owner" ]] && owner_set=true
    fi
    if [[ "$owner_set" == false && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        target_owner="${SUDO_USER}:${SUDO_GROUP:-${SUDO_USER}}" # Use SUDO_GROUP or guess group=user
        owner_set=true
    fi
    if [[ "$owner_set" == false ]]; then
        target_owner="$(id -u):$(id -g)" # Fallback to current user:group
    fi
    log_debug "Using target owner:group '$target_owner' for state/log directories."

    # List of directories to ensure exist (relative paths possible if state_dir is base)
    local dirs_to_ensure=(
        "$state_dir"                     # Base state directory
        "$state_dir/logs"                # Main log directory
        "$state_dir/logs/caddy"          # Caddy logs
        "$state_dir/logs/fail2ban"       # Fail2ban logs
        "$state_dir/data/bwdata"         # Vaultwarden persistent data (DB, attachments, etc.)
        # Add notification log dir based on LOG_FILE from notifications.sh?
        # Requires notifications.sh to export LOG_FILE or define it here based on state_dir
        "$state_dir/logs/notifications.log" # Assume notifications log is here, ensure parent dir
        # System log directory (ensure it exists, permissions handled by system)
        "/var/log/vaultwarden"
    )
    # Get unique directory paths
    local unique_dirs=() dir path
    for path in "${dirs_to_ensure[@]}"; do
        # If it's a file path, get the directory part
        [[ "$path" == */* && ! "$path" =~ /$ ]] && dir=$(dirname "$path") || dir="$path"
        # Add unique directory to the list
        [[ -n "$dir" ]] && ! printf '%s\n' "${unique_dirs[@]}" | grep -Fxq "$dir" && unique_dirs+=("$dir")
    done
    _log_debug "Directories to ensure exist: ${unique_dirs[*]}"


    # Use _create_directory_secure from system.sh if available
    local create_func="_create_directory_secure" dir_perm="775"
    if ! declare -f "$create_func" > /dev/null; then
         log_warn "_create_directory_secure function not available (system.sh missing/failed?). Using basic mkdir."
         create_func="mkdir -p" # Fallback, doesn't handle owner/perms well
         # Define fallback permissions here if needed
    fi

    for dir in "${unique_dirs[@]}"; do
        # Adjust permissions based on directory type
        case "$dir" in
             "$state_dir/data/bwdata") dir_perm="750" ;; # More restrictive for data
             "$state_dir/logs"*) dir_perm="775" ;;      # Group writable for logs
             "/var/log/vaultwarden") dir_perm="755" ;; # Standard log dir perms
             *) dir_perm="750" ;;                      # Default restrictive for state base
        esac
        # Call create function
        "$create_func" "$dir" "$dir_perm" "$target_owner" || ((errors++))
    done

    if [[ $errors -gt 0 ]]; then
        log_error "Failed to create or set permissions on some required directories. Check logs above."
        return 1
    fi
    log_success "Required state, log, and data directories ensured."
    return 0
}

# Securely decrypts SOPS secrets, validates required ones, prepares for Docker secrets.
# Relies on SOPS library functions (load_secrets, get_secret) and constants.
prepare_docker_secrets() {
    log_info "Preparing Docker secrets from encrypted source '$SECRETS_FILE'..."

    # Ensure SOPS library is available
    if [[ "$SOPS_AVAILABLE" != "true" ]]; then
        log_error "SOPS library not available. Cannot prepare Docker secrets."
        return 1
    fi

    # Load secrets into memory using SOPS library function (idempotent)
    if ! load_secrets; then
        log_error_with_help "Could not load/decrypt secrets from SOPS file '$SECRETS_FILE'. Aborting." "Run './tools/edit-secrets.sh' to create or fix it. Check Age key and permissions."
        return 1
    fi
    log_success "Secrets successfully decrypted into memory."


    # --- Validate Required Secrets ---
    log_info "Validating presence of required secrets..."
    # Define which secrets are absolutely required for startup
    local required_secrets=("admin_token" "admin_basic_auth_hash")
    # Conditionally add secrets based on configuration
    # SMTP: Check if SMTP_HOST and SMTP_USERNAME are set in config (implying SMTP is configured)
    if [[ -n "$(get_config_value "SMTP_HOST" "")" && -n "$(get_config_value "SMTP_USERNAME" "")" ]]; then
        required_secrets+=("smtp_password")
        _log_debug "SMTP seems configured, requiring 'smtp_password' secret."
    fi
    # PUSH Notifications: Check PUSH_ENABLED config
    if [[ "$(get_config_value "PUSH_ENABLED" "false")" == "true" ]]; then
        required_secrets+=("push_installation_id" "push_installation_key")
        _log_debug "Push notifications enabled, requiring 'push_installation_id' and 'push_installation_key' secrets."
    fi
    # DDClient (Cloudflare): Check DDCLIENT_ENABLED and DDCLIENT_PROTOCOL config
    if [[ "$(get_config_value "DDCLIENT_ENABLED" "false")" == "true" && "$(get_config_value "DDCLIENT_PROTOCOL" "")" == "cloudflare" ]]; then
        required_secrets+=("cloudflare_api_token")
        _log_debug "DDClient (Cloudflare) enabled, requiring 'cloudflare_api_token' secret."
    fi
    # Remove duplicates just in case
    required_secrets=($(printf "%s\n" "${required_secrets[@]}" | sort -u))
    _log_debug "Required secrets list: ${required_secrets[*]}"

    local validation_errors=0 secret_value
    for secret_name in "${required_secrets[@]}"; do
        # Use get_secret with a marker for missing values
        secret_value=$(get_secret "$secret_name" "__MISSING__")
        if [[ "$secret_value" == "__MISSING__" || -z "$secret_value" ]]; then
             # Check if it exists but is empty vs truly missing
             if has_secret "$secret_name" && [[ -z "$secret_value" ]]; then
                 log_error "Required secret '$secret_name' is present but EMPTY in '$SECRETS_FILE'."
             else
                 log_error "Required secret '$secret_name' is MISSING from '$SECRETS_FILE'."
             fi
            ((validation_errors++))
        else
             _log_debug("Required secret '$secret_name' found.")
             # Optional: Check for placeholder values?
             if [[ "$secret_value" =~ ^CHANGE_ME|^PASTE_.*_HERE$|^\[auto-generated|^\[auto-bcrypt ]]; then
                 log_warn "Required secret '$secret_name' appears to contain a placeholder value ('${secret_value:0:20}...'). Ensure it's correctly set."
                 # Don't fail validation for placeholder, just warn
             fi
        fi
    done

    if [[ $validation_errors -gt 0 ]]; then
        log_error_with_help "Cannot proceed due to $validation_errors missing or empty required secret(s)." "Run './tools/edit-secrets.sh' to add/correct them."
        return 1
    fi
    log_success "Required secrets validated successfully."


    # --- Write Secrets to Docker Secret Files ---
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would create Docker secrets directory '$DOCKER_SECRETS_DIR' and write secret files."
        return 0
    fi

    # Ensure Docker secrets directory exists with correct permissions
    # Use constant for permissions if available
    local secrets_dir_perms="${DOCKER_SECRETS_DIR_PERMISSIONS:-700}"
    # Use _create_directory_secure (handles sudo if needed)
    _create_directory_secure "$DOCKER_SECRETS_DIR" "$secrets_dir_perms" "$(id -u):$(id -g)" || return 1

    # Define mapping: SecretName -> FileNameInDockerSecretsDir
    local secrets_to_write_map=(
        "admin_token:admin_token"
        "smtp_password:smtp_password"
        "backup_passphrase:backup_passphrase" # Include backup passphrase if defined
        "push_installation_key:push_installation_key"
        "cloudflare_api_token:cloudflare_api_token"
        # Add others if needed by compose file
    )

    local secrets_created=0 write_errors=0
    # Use constant for file permissions if available
    local secret_file_perms="${DOCKER_SECRET_FILE_PERMISSIONS:-600}"

    for mapping in "${secrets_to_write_map[@]}"; do
        local secret_name="${mapping%%:*}"
        local file_name="${mapping##*:}"
        local secret_file="$DOCKER_SECRETS_DIR/$file_name"
        local secret_value

        # Get secret value, use marker if not found
        secret_value=$(get_secret "$secret_name" "__NOT_FOUND__")

        if [[ "$secret_value" != "__NOT_FOUND__" ]]; then
            # Secret exists, write it to the file
            # Use _create_file_secure (handles content writing, perms, owner, sudo)
            if _create_file_secure "$secret_file" "$secret_file_perms" "$secret_value" "$(id -u):$(id -g)"; then
                _log_debug "Wrote secret '$secret_name' to '$file_name'"
                # Count non-empty secrets written
                [[ -n "$secret_value" ]] && ((secrets_created++))
            else
                log_error "Failed to write Docker secret file: $secret_file"
                ((write_errors++))
            fi
        else
            # Secret does not exist in secrets.yaml
            # Check if compose file *references* this secret file. If yes, create empty file.
             if grep -q "file: ./secrets/.docker_secrets/${file_name}" "$COMPOSE_FILE"; then
                 log_warn "Optional secret '$secret_name' not found, but referenced by compose file. Creating empty secret file '$file_name'."
                 # Create empty file with secure permissions
                 if ! _create_file_secure "$secret_file" "$secret_file_perms" "" "$(id -u):$(id -g)"; then
                      log_error "Failed to create empty Docker secret file: $secret_file"
                      ((write_errors++))
                 fi
             else
                  _log_debug("Optional secret '$secret_name' not found and not referenced by compose file. Skipping file creation.")
                  # Clean up potentially existing file from previous runs? Maybe not necessary.
                  # if [[ -f "$secret_file" ]]; then rm -f "$secret_file"; fi
             fi
        fi
    done

    if [[ $write_errors -gt 0 ]]; then
         log_error "Encountered $write_errors errors while writing Docker secret files."
         return 1
    fi

    log_success "Prepared Docker secret files in '$DOCKER_SECRETS_DIR' ($secrets_created non-empty values written)."
    return 0
}

# Start all services defined in the Compose file
# Relies on constants and system library
start_services() {
    log_info "Starting VaultWarden services via Docker Compose..."

    # Use constant for compose file path
    local compose_file_path="${COMPOSE_FILE:-docker-compose.yml}"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        log_info "[DRY RUN] Would run 'docker compose -f \"$compose_file_path\" up -d --remove-orphans'"
        return 0
    fi

    # Check compose file again, just in case
    if [[ ! -f "$compose_file_path" ]]; then
        log_error "Compose file '$compose_file_path' not found. Cannot start services."
        return 1
    fi

    # Use constant for timeout if available
    local timeout_secs="${DEFAULT_COMPOSE_TIMEOUT_SECONDS:-60}"
    local compose_args=("-f" "$compose_file_path" "up" "-d" "--remove-orphans" "--timeout" "$timeout_secs")

    # Add --force-recreate if FORCE_RESTART flag is globally set (assumed to be exported or passed)
    if [[ "${FORCE_RESTART:-false}" == "true" ]]; then
        log_info "Adding --force-recreate due to FORCE_RESTART flag..."
        compose_args+=("--force-recreate")
    fi

    # Use _run_command for execution and logging
    if _run_command "Start services via compose up" docker compose "${compose_args[@]}"; then
        # Success logged by _run_command
        # Optional: Add extra wait time after 'up'?
        # log_info "Waiting briefly for services to stabilize..."
        # sleep 5
        return 0
    else
        # Error logged by _run_command
        log_error_with_help "Failed to start services using Docker Compose." "Run 'docker compose logs --tail=50' to see recent errors."
        return 1
    fi
}

# Run a quick post-startup health check
# Relies on constants and system library
post_startup_health_check() {
    # Check global SKIP_HEALTH flag (assumed exported or passed)
    if [[ "${SKIP_HEALTH:-false}" == "true" ]]; then
        log_info "Skipping post-startup health check as requested (--skip-health)."
        return 0
    fi

    # Use constant for wait time if available
    local wait_secs="${HEALTH_CHECK_WAIT_SECONDS:-30}"
    log_info "Waiting for services to initialize before running health check (approx ${wait_secs} seconds)..."
    sleep "$wait_secs"

    # Assume health script is in tools/ relative to PROJECT_ROOT
    local health_script="$PROJECT_ROOT/tools/check-health.sh"
    if [[ -x "$health_script" ]]; then
        log_info "Running post-startup health check ('$health_script')..."
        # Execute health script, capture status but don't fail startup helper if health check fails
        if ! "$health_script"; then
            log_warn "Post-startup health check reported issues. Services started, but may not be fully functional."
            log_warn "Review details above or run '$health_script --comprehensive' manually."
        else
             log_success "Post-startup health check passed."
        fi
    else
        log_warn "Health check script '$health_script' not found or not executable. Skipping post-startup check."
    fi
    # Always return success from this helper, even if health check fails
    return 0
}


# --- Self-Test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/startup-helpers.sh is a library and should be sourced, not executed directly."
     # Can add basic self-tests here if needed, e.g., calling basic_validation
     # Requires being run from project root and config files potentially existing
     # cd "$PROJECT_ROOT" # Ensure in project root for tests
     # export DEBUG=true
     # basic_validation
     # ensure_log_directories
     # prepare_docker_secrets # Requires secrets file and key
     exit 0
else
      _log_debug "lib/startup-helpers.sh loaded successfully as a library."
fi
