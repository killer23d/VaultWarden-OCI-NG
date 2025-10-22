#!/usr/bin/env bash
# lib/config.sh - Load configuration and secrets with precedence and consistency checks

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
    log_info() { echo "[config.sh][INFO] $*"; }
    log_warn() { echo "[config.sh][WARN] $*"; }
    log_error() { echo "[config.sh][ERROR] $*" >&2; }
    _log_debug() { :; } # No-op debug if logging fails
fi

CONFIG_LOADED=false
# Declare VAULTWARDEN_CONFIG as a global associative array to store all loaded values
declare -gA VAULTWARDEN_CONFIG

# --- Helper Functions ---

# Retrieves a configuration value by key from the VAULTWARDEN_CONFIG map.
# Usage: local my_val=$(get_config_value "MY_KEY" "default_value")
# Returns 1 and prints nothing if key not found and no default provided.
get_config_value() {
    local key="$1"
    local default_value="${2:-}" # Optional second argument for default

    if [[ -v VAULTWARDEN_CONFIG["$key"] ]]; then
        printf '%s' "${VAULTWARDEN_CONFIG[$key]}"
        return 0
    elif [[ -n "$default_value" ]]; then
        # Return default value if key not found and default is provided
        printf '%s' "$default_value"
        return 0
    else
        # Return nothing and exit code 1 if key not found and no default
        _log_debug "Config key '$key' not found and no default provided."
        return 1
    fi
}

# Loads variables from .env file into the environment and VAULTWARDEN_CONFIG map
load_dotenv() {
    local dotenv_file="$PROJECT_ROOT/.env"
    if [[ -f "$dotenv_file" ]]; then
        _log_debug "Loading .env file: $dotenv_file"
        # Read line by line to avoid issues with complex values and handle comments/empty lines
        local line key value
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Remove leading/trailing whitespace
            line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            # Skip comments and empty lines
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            # Split on the first '='
            key="${line%%=*}"
            value="${line#*=}"
            # Remove potential quotes around value (simple case)
            value="${value#\"}"; value="${value%\"}"
            value="${value#\'}"; value="${value%\'}"

            # Validate key format (simple alphanumeric + underscore)
            if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                # Export to environment and store in map
                export "$key"="$value"
                VAULTWARDEN_CONFIG["$key"]="$value"
                _log_debug "Loaded from .env: $key"
            else
                 log_warn "Skipping invalid variable name in .env: '$key'"
            fi
        done < "$dotenv_file"
        _log_debug ".env loading complete."
    else
         log_warn ".env file not found at '$dotenv_file'. Using defaults or secrets only."
    fi
}

# Loads and decrypts secrets.yaml, overlays into environment and VAULTWARDEN_CONFIG map
load_secrets_yaml() {
    local secrets_file="$PROJECT_ROOT/secrets/secrets.yaml"
    local age_key_file="$PROJECT_ROOT/secrets/keys/age-key.txt"
    local tmpfile decrypted_content yq_out yq_rc

    if [[ -f "$secrets_file" ]]; then
        _log_debug "Attempting to load secrets from: $secrets_file"
        # Check dependencies
        if ! command -v age >/dev/null 2>&1 || ! command -v yq >/dev/null 2>&1; then
            log_warn "age or yq command not available. Skipping secrets overlay."
            return 0 # Not a fatal error, maybe secrets aren't used
        fi
        if [[ ! -f "$age_key_file" ]]; then
             log_error "Age key file not found at '$age_key_file'. Cannot decrypt secrets."
             return 1 # Fatal if secrets file exists but key doesn't
        fi

        # Decrypt to temp file
        tmpfile=$(mktemp "/tmp/secrets.dec.XXXXXX") || { log_error "Failed to create temp file for decryption."; return 1; }
        # Ensure temp file is removed on exit/error
        trap 'rm -f "$tmpfile"' RETURN

        _log_debug "Decrypting secrets to temporary file..."
        if ! age -d -i "$age_key_file" "$secrets_file" > "$tmpfile" 2>/dev/null; then
            log_error "Failed to decrypt secrets file '$secrets_file' using key '$age_key_file'."
            log_info "Ensure the key is correct and file is not corrupted."
            return 1 # Decryption failure is critical
        fi
        _log_debug "Decryption successful."

        # Parse with yq and export/store
        _log_debug "Parsing decrypted secrets with yq..."
        # Use yq to output key=value pairs, handling nested structures if needed (adjust yq query if structure is complex)
        # Assuming simple key-value pairs at the root for this example
        yq_out=$(yq eval 'to_entries | map(.key + "=" + .value) | .[]' "$tmpfile" 2>/dev/null) || yq_rc=$?
        yq_rc=${yq_rc:-0}

        # Securely remove the temporary decrypted file immediately after parsing attempt
        # Use shred if available for better security
        if command -v shred > /dev/null; then
             shred -u "$tmpfile" 2>/dev/null || rm -f "$tmpfile" # Fallback rm if shred fails
        else
             rm -f "$tmpfile"
        fi
        # Clear trap explicitly after successful removal
        trap - RETURN
        _log_debug "Temporary decrypted file removed."


        if [[ $yq_rc -ne 0 ]]; then
            log_error "yq failed to parse decrypted secrets (rc=$yq_rc). Check secrets file syntax."
            return 1 # Parsing failure is critical
        fi

        local line key value
        while IFS='=' read -r line || [[ -n "$line" ]]; do
            # Extract key and value more robustly
            key="${line%%=*}"
            value="${line#*=}"
            # Basic validation
            if [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
                # Export and store, overwriting any value from .env
                export "$key"="$value"
                VAULTWARDEN_CONFIG["$key"]="$value"
                _log_debug "Loaded from secrets.yaml: $key (overrides .env if duplicate)"
            else
                log_warn "Skipping invalid variable name from secrets.yaml: '$key'"
            fi
        done <<< "$yq_out"
        _log_debug "Secrets loading complete."
    else
        log_info "Encrypted secrets file not found at '$secrets_file'. Using .env or defaults only."
    fi
    return 0
}

# Checks for common configuration inconsistencies or potential issues
check_consistency() {
    log_info "Performing configuration consistency checks..."
    local warnings=0 errors=0

    # PUSH Notifications check
    if [[ "${VAULTWARDEN_CONFIG[PUSH_ENABLED]:-false}" == "true" ]]; then
        if [[ -z "${VAULTWARDEN_CONFIG[PUSH_INSTALLATION_ID]:-}" || -z "${VAULTWARDEN_CONFIG[PUSH_INSTALLATION_KEY]:-}" ]]; then
            log_warn "PUSH_ENABLED=true but PUSH_INSTALLATION_ID or PUSH_INSTALLATION_KEY is missing/empty in secrets. Push notifications will likely fail."
            ((warnings++))
        else
             _log_debug "Push notification config seems complete."
        fi
    fi

    # DOMAIN format check (should not contain protocol)
    if [[ -v VAULTWARDEN_CONFIG["DOMAIN"] && "${VAULTWARDEN_CONFIG[DOMAIN]}" =~ ^https?:// ]]; then
        log_error "Configuration Error: DOMAIN variable ('${VAULTWARDEN_CONFIG[DOMAIN]}') must contain only the domain name (e.g., vault.example.com), not the protocol (http:// or https://)."
        ((errors++))
    elif [[ -v VAULTWARDEN_CONFIG["DOMAIN"] && -z "${VAULTWARDEN_CONFIG[DOMAIN]}" ]]; then
         log_error "Configuration Error: DOMAIN variable is set but empty. A valid domain name is required."
         ((errors++))
    elif [[ ! -v VAULTWARDEN_CONFIG["DOMAIN"] ]]; then
         log_error "Configuration Error: DOMAIN variable is not set. A valid domain name is required."
         ((errors++))
    else
         _log_debug "DOMAIN format appears correct."
    fi

    # ADMIN_EMAIL format check
    if [[ -v VAULTWARDEN_CONFIG["ADMIN_EMAIL"] ]]; then
         local admin_email="${VAULTWARDEN_CONFIG[ADMIN_EMAIL]}"
         if [[ -z "$admin_email" ]]; then
              log_error "Configuration Error: ADMIN_EMAIL variable is set but empty. A valid admin email is required."
              ((errors++))
         # Basic email format check
         elif [[ ! "$admin_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
              log_error "Configuration Error: ADMIN_EMAIL ('$admin_email') does not appear to be a valid email address."
              ((errors++))
         else
             _log_debug "ADMIN_EMAIL format appears correct."
         fi
    else
         log_error "Configuration Error: ADMIN_EMAIL variable is not set. A valid admin email is required."
         ((errors++))
    fi

    # Report summary
    if [[ $errors -gt 0 ]]; then
        log_error "$errors critical configuration error(s) found. Please correct them in .env or secrets/secrets.yaml."
        return 1
    elif [[ $warnings -gt 0 ]]; then
        log_warn "$warnings configuration warning(s) found. System may operate with limitations."
        return 0 # Warnings don't prevent loading
    else
        log_success "Configuration consistency checks passed."
        return 0
    fi
}

# Main function to load all configuration sources
load_config() {
    # Idempotency check: Don't reload if already loaded successfully
    if [[ "$CONFIG_LOADED" == true ]]; then
        _log_debug "Configuration already loaded. Skipping reload."
        return 0
    fi

    _log_debug "Loading configuration..."
    # Reset map before loading
    VAULTWARDEN_CONFIG=()

    # Load sources in order of precedence (later sources override earlier ones)
    load_dotenv
    if ! load_secrets_yaml; then
        # If secrets loading fails critically (decryption, parsing), stop config loading
        log_error "Critical error loading secrets. Configuration incomplete."
        CONFIG_LOADED=false # Mark as failed
        return 1
    fi

    # Run consistency checks after loading everything
    if ! check_consistency; then
        # If consistency checks find critical errors, mark loading as failed
        log_error "Configuration consistency checks failed. Configuration incomplete or invalid."
        CONFIG_LOADED=false # Mark as failed
        return 1
    fi

    # Set calculated variables if needed (e.g., CLEAN_DOMAIN)
    if [[ -v VAULTWARDEN_CONFIG["DOMAIN"] ]]; then
         local clean_domain="${VAULTWARDEN_CONFIG[DOMAIN]}"
         clean_domain="${clean_domain#http://}"
         clean_domain="${clean_domain#https://}"
         export CLEAN_DOMAIN="$clean_domain"
         VAULTWARDEN_CONFIG["CLEAN_DOMAIN"]="$clean_domain"
         _log_debug "Set CLEAN_DOMAIN=$CLEAN_DOMAIN"
    fi


    CONFIG_LOADED=true
    log_info "Configuration loaded successfully."
    return 0
}

# --- Self-Test / Direct Execution ---
# Allow direct execution for testing purposes
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Running lib/config.sh self-test..."
    export DEBUG=true # Enable debug logging for test
    # Assume script is run from project root for test
    PROJECT_ROOT=$(pwd)
    LIB_DIR="$PROJECT_ROOT/lib"

    # Create dummy files for testing
    echo "TEST_VAR_DOTENV=dotenv_value" > .env
    echo "OVERRIDE_VAR=dotenv_original" >> .env
    mkdir -p secrets/keys
    # Use a known test key pair if available, or generate temporary ones
    if [[ ! -f secrets/keys/age-key.txt ]]; then
        echo "Generating temporary Age key for test..."
        age-keygen -o secrets/keys/age-key.txt
        age-keygen -y secrets/keys/age-key.txt > secrets/keys/age-public-key.txt
    fi
    # Create dummy encrypted secrets file
    echo "Creating dummy secrets.yaml..."
    cat << EOF > secrets/secrets.yaml.tmp
TEST_VAR_SECRETS: secrets_value
OVERRIDE_VAR: secrets_override
# Test complex value
# MULTILINE_SECRET: |
#  Line one
#  Line two
EOF
    sops -e secrets/secrets.yaml.tmp > secrets/secrets.yaml
    rm secrets/secrets.yaml.tmp

    # Test loading
    if load_config; then
        log_success "Self-test: load_config succeeded."
        # Verify values
        [[ "$(get_config_value TEST_VAR_DOTENV)" == "dotenv_value" ]] && log_success "✓ .env variable loaded" || log_error "✗ .env variable failed"
        [[ "$(get_config_value TEST_VAR_SECRETS)" == "secrets_value" ]] && log_success "✓ secrets variable loaded" || log_error "✗ secrets variable failed"
        [[ "$(get_config_value OVERRIDE_VAR)" == "secrets_override" ]] && log_success "✓ secrets override successful" || log_error "✗ secrets override failed"
        [[ -n "$(get_config_value CLEAN_DOMAIN)" ]] && log_success "✓ CLEAN_DOMAIN set" || log_error "✗ CLEAN_DOMAIN not set"

        # Test idempotency
        log_info "Testing idempotency (calling load_config again)..."
        load_config # Should log "already loaded" in debug mode
    else
        log_error "Self-test: load_config failed."
    fi

    # Cleanup dummy files
    rm -f .env secrets/secrets.yaml
    # Don't remove keys if they existed before test
    # rm -rf secrets/keys
    echo "Self-test complete."
fi
