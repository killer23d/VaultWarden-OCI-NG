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