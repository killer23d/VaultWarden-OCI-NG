#!/usr/bin/env bash
# lib/sops.sh - SOPS+Age integration library for encrypted secrets management

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
    log_info() { echo "[sops.sh][INFO] $*"; }
    log_warn() { echo "[sops.sh][WARN] $*"; }
    log_error() { echo "[sops.sh][ERROR] $*" >&2; }
    _log_debug() { :; }
fi
# Source constants if available (for paths)
if [[ -f "$LIB_DIR/constants.sh" ]]; then source "$LIB_DIR/constants.sh"; fi


# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "sops-lib"

# --- SOPS Constants (use constants.sh if available, else define defaults) ---
readonly SECRETS_FILE="${SECRETS_FILE:-$PROJECT_ROOT/secrets/secrets.yaml}"
readonly AGE_KEY_FILE="${AGE_KEY_FILE:-$PROJECT_ROOT/secrets/keys/age-key.txt}"
readonly SOPS_CONFIG="${SOPS_CONFIG:-$PROJECT_ROOT/.sops.yaml}"

# --- Global State ---
declare -gA DECRYPTED_SECRETS=() # Associative array to hold secrets in memory
declare -g SECRETS_LOADED=false # Flag to track if secrets are loaded

# Validates the SOPS/Age environment, checking for necessary tools and files.
# Returns 0 on success, 1 on any failure. Logs details.
validate_sops_environment() {
    _log_debug "Validating SOPS/Age environment..."
    local errors=0

    # Check for required commands (use basic command -v as system lib might not be sourced yet)
    if ! command -v sops >/dev/null 2>&1; then log_error "SOPS command not found. Install sops."; ((errors++)); fi
    if ! command -v age >/dev/null 2>&1; then log_error "Age command not found. Install age."; ((errors++)); fi
    if ! command -v age-keygen >/dev/null 2>&1; then log_error "age-keygen command not found. Install age."; ((errors++)); fi

    # Check for Age key file and readability
    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        log_error "Age private key file not found at: $AGE_KEY_FILE"
        ((errors++))
    elif [[ ! -r "$AGE_KEY_FILE" ]]; then
         log_error "Age private key file is not readable: $AGE_KEY_FILE"
         ((errors++))
    fi

    # Check for SOPS config file (optional? Depends on setup. Warn if missing.)
    if [[ ! -f "$SOPS_CONFIG" ]]; then
         log_warn "SOPS configuration file not found at: $SOPS_CONFIG. Relying on environment variables or defaults."
    fi

    # Check for secrets file (Warn if missing, as it might be the first run)
    if [[ ! -f "$SECRETS_FILE" ]]; then
         log_warn "Encrypted secrets file not found at: $SECRETS_FILE. (Normal for initial setup)."
    elif [[ ! -r "$SECRETS_FILE" ]]; then
         log_error "Encrypted secrets file exists but is not readable: $SECRETS_FILE"
         ((errors++))
    fi

    # If critical components are missing, return early
    if [[ $errors -gt 0 ]]; then
        log_error "SOPS/Age environment validation failed with critical errors."
        return 1
    fi

    # If secrets file exists, attempt a test decryption
    if [[ -f "$SECRETS_FILE" ]]; then
         _log_debug "Testing decryption of secrets file..."
         # Set environment variable for age key file explicitly for the test command
         # Use timeout for safety
         if ! timeout 10 env SOPS_AGE_KEY_FILE="$AGE_KEY_FILE" sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
            log_error "SOPS decryption test failed for '$SECRETS_FILE'."
            log_error "Check if the Age key '$AGE_KEY_FILE' is correct and has correct permissions (600 or 400)."
            log_error "Also check '$SOPS_CONFIG' and the integrity of '$SECRETS_FILE'."
            ((errors++))
         else
              _log_debug "SOPS decryption test successful."
         fi
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "SOPS/Age environment validation finished with errors."
        return 1 # Return 1 if any error occurred
    else
        _log_debug "SOPS/Age environment appears healthy."
        return 0 # Return 0 for success
    fi
}

# Decrypts the secrets.yaml file and loads all key-value pairs into the
# global DECRYPTED_SECRETS associative array. Uses yq if available.
# Returns 0 on success, 1 on failure.
load_secrets() {
    # If already loaded, skip redundant work
    if [[ "$SECRETS_LOADED" == "true" ]]; then
        _log_debug "Secrets already loaded in memory."
        return 0
    fi

    _log_debug "Attempting to load secrets from $SECRETS_FILE..."

    # Check if secrets file exists first
    if [[ ! -f "$SECRETS_FILE" ]]; then
        log_error "Secrets file '$SECRETS_FILE' does not exist. Cannot load secrets."
        SECRETS_LOADED=false # Ensure flag is false
        return 1
    fi

    # Validate environment before attempting decryption (important!)
    if ! validate_sops_environment; then
        log_error "SOPS environment is invalid. Cannot load secrets."
        SECRETS_LOADED=false
        return 1
    fi

    _log_debug "Loading and decrypting secrets into memory..."
    local decrypted_content rc=0
    # Decrypt using SOPS, ensuring the correct key file is specified via env var
    decrypted_content=$(env SOPS_AGE_KEY_FILE="$AGE_KEY_FILE" sops -d "$SECRETS_FILE" 2>/dev/null) || rc=$?

    if [[ $rc -ne 0 ]]; then
        log_error "SOPS decryption failed during secret loading (rc=$rc). Cannot proceed."
        SECRETS_LOADED=false
        return 1
    fi
    # Check if decrypted content is empty (e.g., empty secrets file)
    if [[ -z "$decrypted_content" ]]; then
         log_warn "Decrypted secrets content is empty. No secrets loaded."
         SECRETS_LOADED=true # Mark as loaded, but empty
         DECRYPTED_SECRETS=() # Ensure array is empty
         return 0 # Success, but no secrets
    fi


    # Clear the global array before loading new secrets
    DECRYPTED_SECRETS=()

    # Use yq (requires yq v4+) to parse the YAML and populate the associative array
    if command -v yq >/dev/null 2>&1; then
         _log_debug "Parsing secrets using yq..."
         local yq_cmd=(yq -r 'to_entries | .[] | .key + "=" + (.value | @json)') # @json handles strings/nulls better
         local key value line json_val stripped_val
         # Process line by line from yq output
         while IFS='=' read -r key json_val; do
             # Remove surrounding quotes from JSON value (basic stripping)
             stripped_val="${json_val#\"}"
             stripped_val="${stripped_val%\"}"
             # Handle potential escaped chars if needed (more complex)
             # For now, store the stripped value
             DECRYPTED_SECRETS["$key"]="$stripped_val"
             _log_debug "Loaded secret (yq): $key"
         done < <(echo "$decrypted_content" | "${yq_cmd[@]}" 2>/dev/null) # Run yq, feed to loop

         # Check if yq command succeeded by checking array size?
         if [[ ${#DECRYPTED_SECRETS[@]} -eq 0 ]]; then
             log_warn "yq parsing seemed to yield no secrets. Check secrets file format or yq version."
             # Fallback to simpler parsing? Or just accept empty? Accept empty for now.
         fi
    else
        log_warn "yq command not found. Using basic line-by-line parsing (may fail on complex values)."
        # Fallback to simpler line parsing (less robust)
        local key value line
        while IFS=: read -r key value; do
             # Trim leading/trailing whitespace and quotes carefully
             key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
             value=$(echo "$value" | sed -e 's/^[[:space:]"]*//' -e 's/[[:space:]"]*$//' -e "s/^'//" -e "s/'$//")
             # Skip empty lines or comments
             [[ -z "$key" || "$key" == "#"* ]] && continue
             DECRYPTED_SECRETS["$key"]="$value"
             _log_debug "Loaded secret (basic): $key"
        done < <(echo "$decrypted_content")
    fi


    if [[ ${#DECRYPTED_SECRETS[@]} -eq 0 ]]; then
        log_warn "No secrets were loaded from $SECRETS_FILE after parsing. Is the file structured correctly?"
        # Still mark as loaded (but empty) and return success
        SECRETS_LOADED=true
        return 0
    fi

    SECRETS_LOADED=true # Mark secrets as successfully loaded
    log_success "Loaded ${#DECRYPTED_SECRETS[@]} secrets successfully into memory."
    return 0
}

# Retrieves a specific secret value by its key from the in-memory store.
# Usage: local my_secret=$(get_secret "secret_key" [default_value])
# Returns 1 and prints nothing (or default) if secret not found or not loaded.
get_secret() {
    local secret_name="$1"
    local default_value="${2:-}" # Optional default value

    # Attempt to load secrets if they haven't been loaded yet
    if [[ "$SECRETS_LOADED" != "true" ]]; then
        log_warn "Secrets accessed before being explicitly loaded. Attempting to load now..."
        if ! load_secrets; then
            log_error "Failed to load secrets. Cannot retrieve secret '$secret_name'."
            # Return default value if provided on load failure
            [[ -n "$default_value" ]] && printf '%s' "$default_value"
            return 1
        fi
    fi

    # Check if the key exists in the associative array using -v
    if [[ -v DECRYPTED_SECRETS["$secret_name"] ]]; then
        # Print the secret value
        printf '%s' "${DECRYPTED_SECRETS[$secret_name]}"
        return 0 # Success
    else
        _log_debug "Secret '$secret_name' not found in loaded secrets."
        # Return default value if provided
        [[ -n "$default_value" ]] && printf '%s' "$default_value"
        return 1 # Failure (secret not found)
    fi
}

# Checks if a secret with the given key exists in the loaded secrets.
# Usage: if has_secret "secret_key"; then ...
# Returns 0 (true) if secret exists, 1 (false) otherwise.
has_secret() {
    local secret_name="$1"
    # Attempt to load secrets if not already loaded
    if [[ "$SECRETS_LOADED" != "true" ]]; then
        if ! load_secrets; then
            log_warn "Attempted to check for secret '$secret_name', but secrets failed to load."
            return 1 # Cannot check if not loaded, return false
        fi
    fi
     # Use -v to check if the key exists in the associative array
    if [[ -v DECRYPTED_SECRETS["$secret_name"] ]]; then
        return 0 # Secret exists
    else
        return 1 # Secret does not exist
    fi
}


# Export SOPS environment variables for direct sops command usage (e.g., by edit-secrets.sh)
export_sops_environment() {
    # Ensure AGE_KEY_FILE points to the correct location
    export SOPS_AGE_KEY_FILE="$AGE_KEY_FILE"
    _log_debug "SOPS environment variables exported (SOPS_AGE_KEY_FILE set)."
}

# --- Initialization ---
# Auto-export environment when this library is sourced
export_sops_environment

# Mark library as loaded (used internally)
SOPS_LIB_LOADED=true

# --- Self-Test ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/sops.sh is a library and should be sourced, not executed directly."
     _log_info "Running self-tests..."
     export DEBUG=true # Enable debug logs for test

     _log_section "SOPS Environment Validation Test"
     if validate_sops_environment; then
         log_success "SOPS environment validation passed."

         _log_section "Secret Loading Test"
         if load_secrets; then
              log_success "Secrets loaded successfully."
              echo "Loaded secrets:"
              # Print keys only for safety
              printf "  - %s\n" "${!DECRYPTED_SECRETS[@]}"

              _log_section "Get Secret Test"
              local test_secret_key="admin_token" # Choose a key likely to exist
              local test_secret_val
              if test_secret_val=$(get_secret "$test_secret_key"); then
                   log_success "Successfully retrieved secret '$test_secret_key' (value hidden)."
              else
                   log_warn "Secret '$test_secret_key' not found using get_secret."
              fi
              # Test get with default
              local default_val="default"
              local missing_val
              missing_val=$(get_secret "non_existent_secret" "$default_val")
              if [[ "$missing_val" == "$default_val" ]]; then
                    log_success "get_secret default value works."
              else
                    log_error "get_secret default value FAILED."
              fi


              _log_section "Has Secret Test"
              if has_secret "$test_secret_key"; then
                   log_success "has_secret correctly reports '$test_secret_key' exists."
              else
                   log_error "has_secret FAILED for existing key '$test_secret_key'."
              fi
              if ! has_secret "non_existent_secret"; then
                   log_success "has_secret correctly reports non-existent key."
              else
                   log_error "has_secret FAILED for non-existent key."
              fi

         else
              log_error "Secret loading test FAILED."
         fi
     else
         log_error "SOPS environment validation FAILED. Cannot run further tests."
     fi

     _log_info "Self-tests complete."
     # Exit with 0 if tests ran, potential issues logged above
     exit 0
fi
