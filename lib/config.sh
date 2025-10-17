#!/usr/bin/env bash
# lib/config.sh - Enhanced Configuration management with SOPS+Age and .env file support

set -euo pipefail

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

PROJECT_NAME="$(basename "$ROOT_DIR" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
SERVICE_NAME="${PROJECT_NAME}.service"
PROJECT_STATE_DIR="/var/lib/${PROJECT_NAME}"
CONFIG_BACKUP_DIR="${PROJECT_STATE_DIR}/config-backups"
SYSTEMD_ENV_FILE="/etc/systemd/system/${PROJECT_NAME}.env"

_get_project_url() {
    if [[ -d "$ROOT_DIR/.git" ]] && command -v git >/dev/null 2>&1; then
        local remote_url
        remote_url=$(git -C "$ROOT_DIR" config --get remote.origin.url 2>/dev/null || echo "")
        if [[ -n "$remote_url" ]]; then
            echo "${remote_url%.git}"
            return 0
        fi
    fi
    echo "https://github.com/your-username/your-forked-repo"
}
PROJECT_URL="$(_get_project_url)"

# Source required libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/validation.sh"

# Conditionally load SOPS library if available
SOPS_INTEGRATION_AVAILABLE=false
if [[ -f "$ROOT_DIR/lib/sops.sh" ]]; then
    source "$ROOT_DIR/lib/sops.sh"
    SOPS_INTEGRATION_AVAILABLE=true
fi

# Configuration constants
readonly CONFIG_FILE="$ROOT_DIR/settings.env"

# Global configuration variables (populated by load functions)
declare -gA CONFIG_VALUES=()
declare -g CONFIG_LOADED=false
declare -g CONFIG_SOURCE=""
declare -g SECRETS_LOADED=false

# Initialize configuration system
_init_config_system() {
    if [[ ! -d "$CONFIG_BACKUP_DIR" ]]; then
        mkdir -p "$CONFIG_BACKUP_DIR"
        chmod 700 "$CONFIG_BACKUP_DIR"
    fi
}

# Load configuration from settings.env file
_load_from_local_file() {
    _log_info "Loading configuration from settings.env..."

    if [[ ! -f "$CONFIG_FILE" ]]; then
        _log_error "Configuration file not found: $CONFIG_FILE"
        _log_info "Run ./tools/init-setup.sh to create initial configuration"
        return 1
    fi

    # Read .env file line by line
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        # Skip comments and empty lines
        [[ "$key" =~ ^\s*# ]] && continue
        [[ -z "$key" ]] && continue

        # Remove potential quotes
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"

        # Assign to associative array
        CONFIG_VALUES["$key"]="$value"
        _log_debug "Loaded config key: $key"
    done < "$CONFIG_FILE"

    CONFIG_SOURCE="local_file"
    CONFIG_LOADED=true

    _log_success "Configuration loaded from local file"
    return 0
}

# NEW: Load configuration from SOPS encrypted secrets
_load_from_sops_secrets() {
    if [[ "$SOPS_INTEGRATION_AVAILABLE" != "true" ]]; then
        _log_debug "SOPS integration not available"
        return 1
    fi

    _log_info "Loading secrets from SOPS+Age encryption..."

    if ! init_sops_environment; then
        _log_warning "SOPS environment initialization failed"
        return 1
    fi

    if ! load_secrets; then
        _log_warning "Failed to load encrypted secrets"
        return 1
    fi

    # Override with encrypted secrets
    _merge_secrets_into_config

    CONFIG_SOURCE="sops_secrets"
    SECRETS_LOADED=true

    _log_success "Configuration loaded from SOPS encrypted secrets"
    return 0
}

# NEW: Merge encrypted secrets into configuration
_merge_secrets_into_config() {
    _log_debug "Merging encrypted secrets into configuration..."

    # Map secret names to configuration keys
    local secret_mappings=(
        "admin_token:ADMIN_TOKEN"
        "smtp_password:SMTP_PASSWORD"
        "backup_passphrase:BACKUP_PASSPHRASE"
        "push_installation_key:PUSH_INSTALLATION_KEY"
        "cloudflare_api_token:CLOUDFLARE_API_KEY"
    )

    local secrets_merged=0
    for mapping in "${secret_mappings[@]}"; do
        local secret_name="${mapping%:*}"
        local config_key="${mapping#*:}"

        if has_secret "$secret_name"; then
            local secret_value
            secret_value=$(get_secret "$secret_name")
            CONFIG_VALUES["$config_key"]="$secret_value"
            ((secrets_merged++))
            _log_debug "Merged secret $secret_name -> $config_key"
        fi
    done

    _log_debug "Merged $secrets_merged secrets into configuration"
}

# Export configuration as environment variables for docker-compose
_export_configuration() {
    if [[ "$CONFIG_LOADED" != "true" ]]; then
        _log_error "Configuration not loaded. Call load_config first."
        return 1
    fi

    _log_debug "Exporting configuration as environment variables..."

    for key in "${!CONFIG_VALUES[@]}"; do
        export "$key=${CONFIG_VALUES[$key]}"
        _log_debug "Exported: $key"
    done

    export CONFIG_SOURCE
    export CONFIG_LOADED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    export PROJECT_NAME
    export PROJECT_STATE_DIR
    export PROJECT_URL
    export SOPS_INTEGRATION_AVAILABLE
    export SECRETS_LOADED

    # Export Docker secrets directory if SOPS is available
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; then
        export DOCKER_SECRETS_DIR="$ROOT_DIR/secrets/.docker_secrets"
    fi

    _log_debug "Configuration exported successfully"
}


# Get configuration value by key
get_config_value() {
    local key="$1"

    if [[ "$CONFIG_LOADED" != "true" ]]; then
        return 1
    fi

    if [[ -n "${CONFIG_VALUES[$key]:-}" ]]; then
        echo "${CONFIG_VALUES[$key]}"
        return 0
    else
        return 1
    fi
}

# ENHANCED: Main configuration loading function with SOPS priority
load_config() {
    _log_debug "Initializing enhanced configuration system..."
    _init_config_system

    # Priority 1: Local settings.env file
    _log_debug "Attempting to load from local .env file..."
    if _load_from_local_file; then
        _log_debug "Successfully loaded from local file."
    else
        _log_warning "Could not load from local file. This might be okay if using only environment variables."
    fi

    # Priority 2: SOPS encrypted secrets (if available) - overrides .env
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]]; DOCKER-SECRETS-INTEGRATION.md
        if _load_from_sops_secrets; then
            _log_debug "SOPS secrets loaded and merged."
        else
            _log_info "SOPS secrets loading failed, continuing with existing config..."
        fi
    fi

    # Priority 3: System Environment Variables - overrides everything
    _log_debug "Checking for overrides from system environment variables..."
    for key in "${!CONFIG_VALUES[@]}"; do
        if [[ -n "${!key-}" ]]; then # Check if environment variable is set
            CONFIG_VALUES["$key"]="${!key}"
            _log_info "Overriding '$key' with value from environment."
        fi
    done

    if [[ "$CONFIG_LOADED" == "true" ]]; then
        _export_configuration
        return 0
    else
        _log_error "Failed to load configuration from any source"
        return 1
    fi
}


# ENHANCED: Validate configuration completeness with secrets awareness
validate_configuration() {
    if [[ "$CONFIG_LOADED" != "true" ]]; then
        _log_error "Configuration must be loaded before validation"
        return 1
    fi

    local errors=0

    if [[ -z "${CONFIG_VALUES[DOMAIN]:-}" ]]; then
        _log_error "Required configuration key missing: DOMAIN"
        ((errors++))
    elif [[ ! "${CONFIG_VALUES[DOMAIN]}" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        _log_error "Invalid DOMAIN format: ${CONFIG_VALUES[DOMAIN]}"
        ((errors++))
    fi

    # Check admin token - either in config or secrets
    if [[ -z "${CONFIG_VALUES[ADMIN_TOKEN]:-}" ]]; then
        if [[ "$SECRETS_LOADED" == "true" ]] && has_secret "admin_token"; then
            _log_success "ADMIN_TOKEN loaded from encrypted secrets"
        else
            _log_error "Required configuration key missing: ADMIN_TOKEN (not in config or secrets)"
            ((errors++))
        fi
    fi

    if [[ -n "${CONFIG_VALUES[ADMIN_EMAIL]:-}" ]]; then
        if [[ ! "${CONFIG_VALUES[ADMIN_EMAIL]}" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
            _log_error "Invalid ADMIN_EMAIL format: ${CONFIG_VALUES[ADMIN_EMAIL]}"
            ((errors++))
        fi
    fi

    # Validate memory limit formats
    local mem_vars=("VAULTWARDEN_MEMORY_LIMIT" "VAULTWARDEN_MEMORY_RESERVATION" "CADDY_MEMORY_LIMIT" "FAIL2BAN_MEMORY_LIMIT")
    for mem_var in "${mem_vars[@]}"; do
        if [[ -n "${CONFIG_VALUES[$mem_var]:-}" ]]; then
            local mem_limit="${CONFIG_VALUES[$mem_var]}"
            if [[ ! "$mem_limit" =~ ^[0-9]+[gGmMkK]?$ ]]; then
                _log_error "Invalid memory format for $mem_var: $mem_limit (e.g., 512M, 1G)"
                ((errors++))
            fi
        fi
    done

    # Validate SOPS integration if available
    if [[ "$SOPS_INTEGRATION_AVAILABLE" == "true" ]] && [[ "$SECRETS_LOADED" == "true" ]]; then
        _log_info "SOPS integration active - validating encrypted secrets..."
        if ! validate_sops_environment; then
            _log_warning "SOPS environment has issues (see above)"
        else
            _log_success "SOPS environment validation passed"
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        _log_success "Configuration validation passed"
        _log_info "Configuration source: $CONFIG_SOURCE"
        if [[ "$SECRETS_LOADED" == "true" ]]; then
            _log_info "Encrypted secrets: Loaded"
        fi
        return 0
    else
        _log_error "Configuration validation failed with $errors errors"
        return 1
    fi
}


if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "lib/config.sh (enhanced) loaded successfully"
else
    _log_warning "lib/config.sh should be sourced, not executed directly"
    echo "Testing enhanced configuration loading..."
    load_config
    validate_configuration
fi