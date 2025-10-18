#!/usr/bin/env bash
# lib/sops.sh - SOPS+Age integration library for encrypted secrets management

set -euo pipefail

# Auto-detect paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source required libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/validation.sh"

# SOPS constants
readonly SECRETS_FILE="$ROOT_DIR/secrets/secrets.yaml"
readonly AGE_KEY_FILE="$ROOT_DIR/secrets/keys/age-key.txt"
readonly SOPS_CONFIG="$ROOT_DIR/.sops.yaml"
readonly DOCKER_SECRETS_DIR="$ROOT_DIR/secrets/.docker_secrets"

# Global state
declare -g SOPS_INITIALIZED=false
declare -gA DECRYPTED_SECRETS=()

# Initialize SOPS environment
init_sops_environment() {
    _log_debug "Initializing SOPS environment..."
    if ! command -v sops >/dev/null 2>&1 || ! command -v age >/dev/null 2>&1; then
        _log_error "SOPS or Age not found. Run: ./tools/init-setup.sh"; return 1;
    fi
    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        _log_error "Age private key not found: $AGE_KEY_FILE"; return 1;
    fi
    if [[ ! -f "$SECRETS_FILE" ]]; then
        _log_error "Encrypted secrets file not found: $SECRETS_FILE"; return 1;
    fi
    if ! sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
        _log_error "Cannot decrypt secrets file - check Age key integrity"; return 1;
    fi
    SOPS_INITIALIZED=true
    _log_success "SOPS environment initialized successfully"
    return 0
}

# NEW: Validate SOPS environment integrity and configuration
validate_sops_environment() {
    _log_debug "Validating SOPS environment..."
    local errors=0
    # Check for required commands
    if ! command -v sops >/dev/null 2>&1; then
        _log_error "SOPS command not found"
        ((errors++))
    else
        _log_success "SOPS command available"
    fi
    if ! command -v age >/dev/null 2>&1; then
        _log_error "Age command not found"
        ((errors++))
    else
        _log_success "Age command available"
    fi
    # Check for SOPS configuration
    if [[ ! -f "$SOPS_CONFIG" ]]; then
        _log_error "SOPS configuration not found: $SOPS_CONFIG"
        ((errors++))
    else
        _log_success "SOPS configuration found"
        
        # Validate SOPS config syntax
        if ! yq eval '.' "$SOPS_CONFIG" >/dev/null 2>&1; then
            _log_error "SOPS configuration has invalid YAML syntax"
            ((errors++))
        else
            _log_success "SOPS configuration has valid syntax"
        fi
    fi
    # Check for Age private key
    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        _log_error "Age private key not found: $AGE_KEY_FILE"
        ((errors++))
    else
        _log_success "Age private key found"
        
        # Check key file permissions
        local key_perms
        key_perms="$(stat -c "%a" "$AGE_KEY_FILE")"
        if [[ "$key_perms" != "600" ]]; then
            _log_warning "Age key permissions should be 600 (currently: $key_perms)"
        else
            _log_success "Age key has secure permissions (600)"
        fi
    fi
    # Check for encrypted secrets file
    if [[ ! -f "$SECRETS_FILE" ]]; then
        _log_warning "Encrypted secrets file not found: $SECRETS_FILE"
        _log_info "This is normal for fresh installations"
    else
        _log_success "Encrypted secrets file found"
        
        # Test decryption capability
        if ! sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
            _log_error "Cannot decrypt secrets file - Age key may be incorrect"
            ((errors++))
        else
            _log_success "Secrets file decryption test passed"
        fi
    fi
    # Check Docker secrets directory
    if [[ ! -d "$DOCKER_SECRETS_DIR" ]]; then
        _log_info "Docker secrets directory will be created on startup"
    else
        _log_success "Docker secrets directory exists"
        
        # Check directory permissions
        local dir_perms
        dir_perms="$(stat -c "%a" "$DOCKER_SECRETS_DIR")"
        if [[ "$dir_perms" != "700" ]]; then
            _log_warning "Docker secrets directory permissions should be 700 (currently: $dir_perms)"
        else
            _log_success "Docker secrets directory has secure permissions (700)"
        fi
    fi
    # Summary
    if [[ $errors -eq 0 ]]; then
        _log_success "SOPS environment validation passed"
        return 0
    else
        _log_error "SOPS environment validation failed ($errors errors)"
        return 1
    fi
}

# Load and decrypt all secrets into memory
load_secrets() {
    if [[ "$SOPS_INITIALIZED" != "true" ]]; then
        if ! init_sops_environment; then return 1; fi
    fi
    _log_debug "Loading encrypted secrets..."
    local decrypted_content; decrypted_content=$(sops -d "$SECRETS_FILE" 2>/dev/null)
    if ! echo "$decrypted_content" | yq eval '.' >/dev/null 2>&1; then
        _log_error "Decrypted secrets contain invalid YAML"; return 1;
    fi
    DECRYPTED_SECRETS=()
    local keys; keys=$(echo "$decrypted_content" | yq eval 'keys | .[]' - 2>/dev/null)
    while IFS= read -r key; do
        if [[ -n "$key" ]]; then
            DECRYPTED_SECRETS["$key"]="$(echo "$decrypted_content" | yq eval ".$key" - 2>/dev/null)"
        fi
    done <<< "$keys"
    _log_success "Loaded ${#DECRYPTED_SECRETS[@]} secrets"
    return 0
}

# Get a specific secret value
get_secret() {
    local secret_name="$1"
    if [[ ${#DECRYPTED_SECRETS[@]} -eq 0 ]]; then
        if ! load_secrets; then return 1; fi
    fi
    if [[ -n "${DECRYPTED_SECRETS[$secret_name]:-}" ]]; then
        echo "${DECRYPTED_SECRETS[$secret_name]}"; return 0;
    else
        return 1;
    fi
}

# Check if a secret exists
has_secret() {
    get_secret "$1" >/dev/null 2>&1
}

# NEW: Clean up Docker secrets directory
cleanup_docker_secrets() {
    _log_debug "Cleaning up Docker secrets directory..."
    if [[ -d "$DOCKER_SECRETS_DIR" ]]; then
        # Remove files older than 1 hour
        find "$DOCKER_SECRETS_DIR" -type f -mmin +60 -exec rm -f {} \; 2>/dev/null || true
        # Remove empty directories
        find "$DOCKER_SECRETS_DIR" -type d -empty -delete 2>/dev/null || true
        _log_success "Docker secrets cleanup completed"
    fi
}

# NEW: Export SOPS environment variables
export_sops_environment() {
    export SOPS_AGE_KEY_FILE="$AGE_KEY_FILE"
    export SOPS_CONFIG_FILE="$SOPS_CONFIG"
    _log_debug "SOPS environment variables exported"
}

# Source guard and initialization
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "lib/sops.sh loaded successfully"
    # Auto-export environment on source
    export_sops_environment
else
    _log_warning "lib/sops.sh should be sourced, not executed directly"
    # Test the validation function
    validate_sops_environment
fi
