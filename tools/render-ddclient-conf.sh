#!/usr/bin/env bash
# tools/render-ddclient-conf.sh — Enhanced DDNS config renderer with Docker secrets and SOPS integration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib"

TEMPLATE="${1:-}"
OUT="${2:-/etc/ddclient.conf}"

source "$LIB_DIR/logging.sh"
_set_log_prefix "ddns-render"

# Load enhanced config with SOPS support
source "$LIB_DIR/config.sh"

# Load SOPS integration if available
SOPS_AVAILABLE=false
if [[ -f "$LIB_DIR/sops.sh" ]]; then
    source "$LIB_DIR/sops.sh"
    SOPS_AVAILABLE=true
fi

[[ -z "$TEMPLATE" ]] && TEMPLATE="$PROJECT_ROOT/templates/ddclient.conf.tmpl" && _log_debug "Using default template: $TEMPLATE"

_validate_template() {
    [[ -f "$TEMPLATE" ]] || { _log_error "Template file not found: $TEMPLATE"; exit 1; }
    [[ -r "$TEMPLATE" ]] || { _log_error "Template file not readable: $TEMPLATE"; exit 1; }
    _log_debug "Template validation passed: $TEMPLATE"
}

# Enhanced variable loading with Docker secrets and SOPS support
_load_ddclient_variables() {
    _log_info "Loading DDNS configuration variables"

    # Load base configuration
    if ! load_config; then
        _log_error "Failed to load configuration"
        exit 1
    fi

    # Base configuration variables
    DDCLIENT_PROTOCOL=$(get_config_value "DDCLIENT_PROTOCOL" || echo "")
    DDCLIENT_LOGIN=$(get_config_value "DDCLIENT_LOGIN" || echo "")
    DDCLIENT_ZONE=$(get_config_value "DDCLIENT_ZONE" || echo "")
    DDCLIENT_HOST=$(get_config_value "DDCLIENT_HOST" || echo "")

    # Password/token - try multiple sources in order of preference
    local ddclient_password=""

    # 1. Docker secrets directory (highest priority)
    if [[ -n "${DOCKER_SECRETS_DIR:-}" ]] && [[ -f "${DOCKER_SECRETS_DIR}/cloudflare_api_token" ]]; then
        ddclient_password=$(cat "${DOCKER_SECRETS_DIR}/cloudflare_api_token" 2>/dev/null)
        if [[ -n "$ddclient_password" ]]; then
            _log_success "Using CloudFlare API token from Docker secrets"
        fi
    fi

    # 2. SOPS encrypted secrets (second priority)
    if [[ -z "$ddclient_password" ]] && [[ "$SOPS_AVAILABLE" == "true" ]] && [[ "$SECRETS_LOADED" == "true" ]]; then
        if ddclient_password=$(get_secret "cloudflare_api_token" 2>/dev/null); then
            if [[ -n "$ddclient_password" ]]; then
                _log_success "Using CloudFlare API token from SOPS encrypted secrets"
            fi
        fi
    fi

    # 3. Environment variable (final fallback)
    if [[ -z "$ddclient_password" ]]; then
        ddclient_password="${DDCLIENT_PASSWORD:-}"
        if [[ -n "$ddclient_password" ]]; then
            _log_info "Using DDCLIENT_PASSWORD from environment"
        fi
    fi

    export DDCLIENT_PASSWORD="$ddclient_password"

    _log_debug "DDNS configuration sources checked:"
    _log_debug "  Docker secrets: $([[ -n "${DOCKER_SECRETS_DIR:-}" ]] && echo "Available" || echo "Not available")"
    _log_debug "  SOPS secrets: $([[ "$SOPS_AVAILABLE" == "true" ]] && echo "Available" || echo "Not available")"
    _log_debug "  Configuration: $([[ -f "$PROJECT_ROOT/settings.env" ]] && echo "Available" || echo "Not available")"
}


_validate_required_vars() {
    _log_info "Validating required DDNS variables"

    local missing=()
    local required=("DDCLIENT_PROTOCOL" "DDCLIENT_LOGIN" "DDCLIENT_PASSWORD" "DDCLIENT_ZONE" "DDCLIENT_HOST")

    for v in "${required[@]}"; do
        if [[ -z "${!v:-}" ]]; then
            missing+=("$v")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        _log_error "Missing required DDCLIENT variables: ${missing[*]}"
        _log_error "Available sources (in priority order):"
        _log_error "  1. Docker secrets directory: ${DOCKER_SECRETS_DIR:-not set}"
        _log_error "  2. SOPS encrypted secrets: $([[ "$SOPS_AVAILABLE" == "true" ]] && echo "available" || echo "not available")"
        _log_error "  3. Environment variables"
        exit 1
    fi

    _log_success "All required DDCLIENT variables are set"
    _log_debug "Protocol: $DDCLIENT_PROTOCOL, Host: $DDCLIENT_HOST, Zone: $DDCLIENT_ZONE"

    # Validate CloudFlare token format if using CloudFlare
    if [[ "$DDCLIENT_PROTOCOL" == "cloudflare" ]]; then
        if [[ ${#DDCLIENT_PASSWORD} -lt 40 ]]; then
            _log_warning "CloudFlare API token appears to be too short (expected ~40 chars, got ${#DDCLIENT_PASSWORD})"
        elif [[ ! "$DDCLIENT_PASSWORD" =~ ^[A-Za-z0-9_-]+$ ]]; then
            _log_warning "CloudFlare API token contains unexpected characters"
        else
            _log_debug "CloudFlare API token format validation passed"
        fi
    fi
}

_create_output_dir() {
    local out_dir
    out_dir="$(dirname "$OUT")"
    [[ -d "$out_dir" ]] || {
        mkdir -p "$out_dir" || {
            _log_error "Failed to create output directory: $out_dir";
            exit 1;
        }
        _log_debug "Created output directory: $out_dir"
    }
}

_render_template() {
    _log_info "Rendering DDNS configuration template with enhanced variable sources"

    # Create environment for substitution
    export DDCLIENT_PROTOCOL DDCLIENT_LOGIN DDCLIENT_PASSWORD DDCLIENT_ZONE DDCLIENT_HOST

    if command -v envsubst >/dev/null 2>&1; then
        _log_debug "Using envsubst for template rendering"
        envsubst < "$TEMPLATE" > "$OUT" || {
            _log_error "envsubst rendering failed";
            exit 1;
        }
    else
        _log_warning "envsubst not available, using manual substitution"
        local content
        content="$(<"$TEMPLATE")"
        content="${content//\$\{DDCLIENT_PROTOCOL\}/$DDCLIENT_PROTOCOL}"
        content="${content//\$\{DDCLIENT_LOGIN\}/$DDCLIENT_LOGIN}"
        content="${content//\$\{DDCLIENT_PASSWORD\}/$DDCLIENT_PASSWORD}"
        content="${content//\$\{DDCLIENT_ZONE\}/$DDCLIENT_ZONE}"
        content="${content//\$\{DDCLIENT_HOST\}/$DDCLIENT_HOST}"
        printf '%s\n' "$content" > "$OUT" || {
            _log_error "Manual substitution rendering failed";
            exit 1;
        }
    fi

    # Clear sensitive variables from environment
    unset DDCLIENT_PASSWORD

    _log_debug "Template rendering completed successfully"
}

_secure_config_file() {
    chmod 600 "$OUT" || _log_warning "Failed to set restrictive permissions on $OUT"
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        chown root:root "$OUT" 2>/dev/null || _log_warning "Failed to set root ownership on $OUT"
    fi
    _log_debug "Applied security settings to configuration file"
}

_validate_output() {
    [[ -f "$OUT" ]] || { _log_error "Output file was not created: $OUT"; exit 1; }
    [[ -s "$OUT" ]] || { _log_error "Output file is empty: $OUT"; exit 1; }

    local required_keys=("protocol" "login" "password" "zone" "host")
    local missing_keys=()
    for key in "${required_keys[@]}"; do
        if ! grep -q "^$key=" "$OUT"; then
            missing_keys+=("$key")
        fi
    done

    if [[ ${#missing_keys[@]} -gt 0 ]]; then
        _log_warning "Generated config may be incomplete. Missing keys: ${missing_keys[*]}"
    else
        _log_debug "Output validation passed - all required keys present"
    fi

    # Validate that password field is not empty
    local password_line
    password_line=$(grep "^password=" "$OUT" || echo "")
    if [[ "$password_line" == "password=" ]]; then
        _log_error "Password field is empty in generated configuration"
        exit 1
    fi

    _log_debug "Password field validation passed"
}

# NEW: Display configuration sources for troubleshooting
_display_config_sources() {
    _log_info "Configuration sources used:"
    _log_info "  Base config: ${CONFIG_SOURCE:-unknown}"

    local password_source="unknown"
    if [[ -n "${DOCKER_SECRETS_DIR:-}" ]] && [[ -f "${DOCKER_SECRETS_DIR}/cloudflare_api_token" ]]; then
        password_source="Docker secrets"
    elif [[ "$SOPS_AVAILABLE" == "true" ]] && [[ "$SECRETS_LOADED" == "true" ]]; then
        if get_secret "cloudflare_api_token" >/dev/null 2>&1; then
            password_source="SOPS encrypted secrets"
        fi
    elif [[ -n "${DDCLIENT_PASSWORD:-}" ]]; then
        password_source="Environment variable"
    fi

    _log_info "  Password/token: $password_source"
}

main() {
    _log_info "Enhanced DDNS Configuration Renderer Starting"
    _log_debug "Template: $TEMPLATE"
    _log_debug "Output: $OUT"
    _log_debug "SOPS integration: $([[ "$SOPS_AVAILABLE" == "true" ]] && echo "Available" || echo "Not available")"

    _validate_template
    _load_ddclient_variables
    _validate_required_vars
    _create_output_dir
    _render_template
    _secure_config_file
    _validate_output

    _log_success "Successfully rendered ddclient configuration: $OUT"
    _log_info "Protocol: $DDCLIENT_PROTOCOL"
    _log_info "Host: $DDCLIENT_HOST"
    _log_info "Zone: $DDCLIENT_ZONE"
    _display_config_sources

    local config_size
    config_size=$(wc -c < "$OUT")
    _log_debug "Configuration file size: $config_size bytes"
}

# Argument handling
case "${1:-help}" in
    --help|-h|help)
        cat <<EOF
${BOLD}Enhanced DDNS Configuration Renderer with Docker Secrets & SOPS${NC}

${CYAN}USAGE:${NC}
  $0 [TEMPLATE] [OUTPUT]
  $0 --help

${CYAN}ARGUMENTS:${NC}
  TEMPLATE       Path to ddclient.conf template (default: templates/ddclient.conf.tmpl)
  OUTPUT         Output configuration file path (default: /etc/ddclient.conf)

${CYAN}FEATURES:${NC}
  • Multi-source variable loading (Docker secrets, SOPS, config, environment)
  • Enhanced security with encrypted secret storage
  • CloudFlare API token format validation
  • Comprehensive error handling and validation
  • Integration status logging

${CYAN}VARIABLE SOURCES (priority order):${NC}
  1. Docker secrets directory (\${DOCKER_SECRETS_DIR}/cloudflare_api_token)
  2. SOPS encrypted secrets (cloudflare_api_token)
  3. Environment variables (DDCLIENT_PASSWORD)

${CYAN}EXAMPLES:${NC}
  $0                                    # Use defaults
  $0 custom.tmpl /tmp/ddclient.conf     # Custom paths
  $0 --help                             # Show this help

EOF
        exit 0
        ;;
    *)
        # Standard execution path
        main "$@"
        ;;
esac