#!/usr/bin/env bash
# startup.sh - Enhanced Dynamic startup script with SOPS+Age integration  
#
# This script provides comprehensive startup management including:
# - Dynamic project detection and path configuration
# - SOPS+Age encrypted secrets loading
# - Configuration loading from multiple sources
# - Runtime environment preparation and validation
# - Service orchestration with health checks
# - Integration with existing library ecosystem
#

set -euo pipefail

# Auto-detect script location and project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"

# Source existing libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/validation.sh" 
source "$ROOT_DIR/lib/system.sh"

# Set logging prefix for this script
_set_log_prefix "startup"

# Script constants
readonly COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
readonly SECRETS_FILE="$ROOT_DIR/secrets/secrets.yaml"
readonly AGE_KEY_FILE="$ROOT_DIR/secrets/keys/age-key.txt"

# Define required directories dynamically
REQUIRED_DIRS=(
    "$PROJECT_STATE_DIR"
    "$PROJECT_STATE_DIR/data"
    "$PROJECT_STATE_DIR/logs"
    "$PROJECT_STATE_DIR/logs/caddy"
    "$PROJECT_STATE_DIR/logs/vaultwarden"
    "$PROJECT_STATE_DIR/logs/fail2ban"
    "$PROJECT_STATE_DIR/logs/watchtower"
    "$ROOT_DIR/secrets/.docker_secrets"
)

# Enhanced startup workflow with SOPS+Age
_startup_workflow() {
    _log_header "$PROJECT_NAME - Enhanced Startup with SOPS+Age"

    # Step 1: System validation
    _validate_startup_prerequisites

    # Step 2: SOPS+Age secrets loading
    _load_encrypted_secrets

    # Step 3: Configuration loading  
    _log_info "Loading configuration..."
    if ! load_config; then
        _log_error "Failed to load configuration"
        return 1
    fi

    # Step 4: Environment preparation
    _prepare_runtime_environment

    # Step 5: Pre-startup tasks
    _execute_pre_startup_tasks

    # Step 6: Start services
    _start_services

    # Step 7: Post-startup validation
    _validate_service_health

    _log_success "$PROJECT_NAME stack started successfully"
    _display_service_info
}

# NEW: Load and prepare encrypted secrets
_load_encrypted_secrets() {
    _log_section "Loading Encrypted Secrets"

    # Validate SOPS environment
    if ! command -v sops >/dev/null 2>&1; then
        _log_error "SOPS not found - run ./tools/init-setup.sh"
        return 1
    fi

    if [[ ! -f "$AGE_KEY_FILE" ]]; then
        _log_error "Age private key not found: $AGE_KEY_FILE"
        _log_info "Run: ./tools/init-setup.sh"
        return 1
    fi

    if [[ ! -f "$SECRETS_FILE" ]]; then
        _log_error "Encrypted secrets file not found: $SECRETS_FILE"
        _log_info "Create with: ./tools/edit-secrets.sh"
        return 1
    fi

    # Test decryption capability
    if ! sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
        _log_error "Cannot decrypt secrets file - check Age key"
        return 1
    fi

    _log_success "Encrypted secrets accessible"

    # Create Docker secrets directory
    local docker_secrets_dir="$ROOT_DIR/secrets/.docker_secrets"
    _create_directory_secure "$docker_secrets_dir" "700"

    # Extract secrets to individual files for Docker secrets
    _extract_docker_secrets

    _log_success "Docker secrets prepared"
}

# NEW: Extract individual secrets for Docker Compose secrets
_extract_docker_secrets() {
    local docker_secrets_dir="$ROOT_DIR/secrets/.docker_secrets"
    local decrypted_secrets

    # Get decrypted secrets
    decrypted_secrets=$(sops -d "$SECRETS_FILE" 2>/dev/null)

    # Extract each secret to individual file
    local secrets=("admin_token" "smtp_password" "backup_passphrase" "push_installation_key" "cloudflare_api_token")

    for secret in "${secrets[@]}"; do
        local secret_value
        secret_value=$(echo "$decrypted_secrets" | yq eval ".$secret // \"\""  - 2>/dev/null)

        if [[ -n "$secret_value" ]] && [[ "$secret_value" != "null" ]]; then
            echo -n "$secret_value" > "$docker_secrets_dir/$secret"
            chmod 600 "$docker_secrets_dir/$secret"
            _log_debug "Extracted secret: $secret"
        else
            # Create empty file for undefined secrets
            echo -n "" > "$docker_secrets_dir/$secret"
            chmod 600 "$docker_secrets_dir/$secret"
            _log_debug "Created empty secret file: $secret"
        fi
    done
}

# ENHANCED: Validate startup prerequisites including SOPS
_validate_startup_prerequisites() {
    _log_info "Validating startup prerequisites..."

    _validate_docker_daemon
    _validate_compose_file "$COMPOSE_FILE"
    _validate_network_connectivity

    # Check for configuration existence
    local has_config=false
    local has_secrets=false

    if [[ -f "$ROOT_DIR/settings.json" ]] || [[ -f "$ROOT_DIR/settings.env" ]]; then
        has_config=true
    fi

    if [[ -f "$SECRETS_FILE" ]] && [[ -f "$AGE_KEY_FILE" ]]; then
        has_secrets=true
    fi

    # Check for OCI Vault fallback
    if [[ -z "${OCI_SECRET_OCID:-}" ]]; then
        local oci_fallback=false
    else
        local oci_fallback=true
    fi

    if [[ "$has_config" == "false" ]] && [[ "$has_secrets" == "false" ]] && [[ "$oci_fallback" == "false" ]]; then
        _log_error "No configuration found."
        _log_info "This appears to be a fresh installation."
        _log_info "Please run: sudo ./tools/init-setup.sh"
        return 1
    fi

    if [[ "$has_secrets" == "true" ]]; then
        _log_success "SOPS+Age configuration detected"
    elif [[ "$has_config" == "true" ]]; then
        _log_info "Legacy configuration detected (consider migrating to SOPS+Age)"
    elif [[ "$oci_fallback" == "true" ]]; then
        _log_info "OCI Vault configuration detected"
    fi
}

# ENHANCED: Prepare runtime environment with secrets
_prepare_runtime_environment() {
    _log_info "Preparing runtime environment..."

    for dir in "${REQUIRED_DIRS[@]}"; do
        _create_directory_secure "$dir" "755"
    done

    # Enhanced: Set correct permissions for secrets directory and clean up old secrets
    if [[ -d "$ROOT_DIR/secrets/.docker_secrets" ]]; then
        chmod 700 "$ROOT_DIR/secrets/.docker_secrets"

        # Clean up old secrets (older than 30 minutes for tighter security)
        find "$ROOT_DIR/secrets/.docker_secrets" -type f -mmin +30 -exec rm -f {} \; 2>/dev/null || true

        # Set secure permissions on all current secrets
        find "$ROOT_DIR/secrets/.docker_secrets" -type f -exec chmod 600 {} \; 2>/dev/null || true
        find "$ROOT_DIR/secrets/.docker_secrets" -type d -exec chmod 700 {} \; 2>/dev/null || true

        _log_debug "Docker secrets directory secured and cleaned"
    fi

    local caddy_placeholder="$ROOT_DIR/caddy/cloudflare-ips.caddy"
    if [[ ! -f "$caddy_placeholder" ]]; then
        local parent_dir
        parent_dir="$(dirname "$caddy_placeholder")"
        [[ -d "$parent_dir" ]] || mkdir -p "$parent_dir"
        _create_file_secure "$caddy_placeholder" "644" "# Placeholder - will be populated by update scripts"
        _log_debug "Created Caddy placeholder: $caddy_placeholder"
    fi

    local ddns_config_dir="$ROOT_DIR/ddclient"
    _create_directory_secure "$ddns_config_dir" "755"

    local ddns_config_file="$ddns_config_dir/ddclient.conf"
    if [[ ! -f "$ddns_config_file" ]]; then
        _create_file_secure "$ddns_config_file" "600" "# Placeholder - will be populated dynamically"
        _log_debug "Created DDNS config placeholder: $ddns_config_file"
    fi

    if [[ -f "$ROOT_DIR/settings.json" ]]; then
        chmod 600 "$ROOT_DIR/settings.json"
    fi

    if [[ -f "$ROOT_DIR/settings.env" ]]; then
        chmod 600 "$ROOT_DIR/settings.env"
    fi

    # Export dynamic paths for docker-compose
    export PROJECT_STATE_DIR
    export COMPOSE_PROJECT_NAME="$PROJECT_NAME"

    # Simplified: Use static subnet for better reliability
    export DOCKER_SUBNET="172.20.0.0/24"
    _log_info "Using Docker subnet: $DOCKER_SUBNET"

    # Export secrets directory for Docker Compose
    export DOCKER_SECRETS_DIR="$ROOT_DIR/secrets/.docker_secrets"
}

# ENHANCED: Execute pre-startup tasks with secrets support and improved cleanup
_execute_pre_startup_tasks() {
    _log_info "Executing pre-startup tasks..."

    local cf_script="$ROOT_DIR/tools/update-cloudflare-ips.sh"
    if [[ -x "$cf_script" ]]; then
        _log_debug "Updating Cloudflare IP ranges..."
        if ! timeout "${CLOUDFLARE_UPDATE_TIMEOUT:-30}" "$cf_script" --quiet 2>/dev/null; then
            _log_warning "Failed to update Cloudflare IPs, continuing with existing config"
        else
            _log_success "Cloudflare IPs updated successfully"
        fi
    fi

    if [[ "${DDCLIENT_ENABLED:-false}" == "true" ]]; then
        local ddns_script="$ROOT_DIR/tools/render-ddclient-conf.sh"
        if [[ -x "$ddns_script" ]]; then
            _log_debug "Rendering DDNS configuration..."
            # Pass secrets directory to render script for secret access
            DOCKER_SECRETS_DIR="$ROOT_DIR/secrets/.docker_secrets" \
            timeout "${OCI_VAULT_TIMEOUT:-15}" "$ddns_script" \
                "$ROOT_DIR/templates/ddclient.conf.tmpl" \
                "$ROOT_DIR/ddclient/ddclient.conf" 2>/dev/null || {
                _log_warning "Failed to render DDNS config, container will use environment variables"
            }
        fi
    fi

    _cleanup_orphaned_containers

    # Enhanced: Clean up any stale secret files and secure log permissions
    if [[ -d "$ROOT_DIR/secrets/.docker_secrets" ]]; then
        find "$ROOT_DIR/secrets/.docker_secrets" -type f -mmin +30 -exec rm -f {} \; 2>/dev/null || true
    fi

    # Set secure permissions on log directories
    if [[ -d "$PROJECT_STATE_DIR/logs" ]]; then
        find "$PROJECT_STATE_DIR/logs" -type d -exec chmod 750 {} \; 2>/dev/null || true
        find "$PROJECT_STATE_DIR/logs" -type f -exec chmod 640 {} \; 2>/dev/null || true
    fi
}

# Continue with existing functions...
_start_services() {
    _log_info "Starting $PROJECT_NAME services..."
    cd "$ROOT_DIR"
    if docker compose -f "$COMPOSE_FILE" up -d --remove-orphans; then
        _log_success "Services started successfully"
    else
        _log_error "Failed to start services"
        _log_info "Check logs with: docker compose logs"
        return 1
    fi
}

_validate_service_health() {
    _log_info "Validating service health..."
    local max_retries=30
    local retry_delay=2
    local vaultwarden_service_name
    vaultwarden_service_name=$(get_config_value "CONTAINER_NAME_VAULTWARDEN" || echo "${COMPOSE_PROJECT_NAME}_vaultwarden")

    _log_debug "Waiting for $vaultwarden_service_name to be healthy..."
    for ((i=1; i<=max_retries; i++)); do
        if docker compose ps --format json 2>/dev/null | jq -r ".[] | select(.Service==\"vaultwarden\") | .Health" 2>/dev/null | grep -q "healthy"; then
            _log_success "VaultWarden is healthy"
            break
        fi

        if [[ $i -eq $max_retries ]]; then
            _log_error "VaultWarden failed to become healthy on the first attempt."
            _log_info "Attempting a one-time automatic restart of the 'vaultwarden' service..."

            if docker compose restart vaultwarden &>/dev/null; then
                _log_info "Restart command sent. Waiting for service to become healthy again..."
                sleep 20 
                if docker compose ps --format json 2>/dev/null | jq -r ".[] | select(.Service==\"vaultwarden\") | .Health" 2>/dev/null | grep -q "healthy"; then
                     _log_success "VaultWarden is now healthy after a restart."
                     break
                else
                     _log_error "Service is still not healthy after restart."
                     _show_troubleshooting_info
                     return 1
                fi
            else
                _log_error "Failed to issue restart command."
                _show_troubleshooting_info
                return 1
            fi
        fi
        sleep $retry_delay
    done

    local critical_services=("caddy" "fail2ban")
    for service in "${critical_services[@]}"; do
        if _compose_service_running "$service"; then
            _log_success "$service is running"
        else
            _log_warning "$service is not running properly"
        fi
    done
}

_show_troubleshooting_info() {
    _log_error "Stack failed to start correctly. Please check the logs."
    _log_info "Troubleshooting Information:"
    _log_info "  View container status: docker compose ps"
    _log_info "  View all logs: docker compose logs"
    _log_info "  View VaultWarden logs: docker compose logs vaultwarden"
    _log_info "  Check system resources: free -h && df -h"
    _log_info "  Check secrets health: ./tools/check-health.sh --sops-only"
    _log_info "  Validate configuration: ./startup.sh --validate"
    _log_info "  Force a full restart: docker compose down && ./startup.sh"
}

# ENHANCED: Display service info with secrets information
_display_service_info() {
    _log_header "Service Information"
    local domain
    domain=$(get_config_value "DOMAIN")

    _log_info "VaultWarden Web Interface:"
    _print_key_value "URL" "$domain"
    _print_key_value "Admin" "$domain/admin"
    echo
    _log_info "Service Management:"
    _print_key_value "Status" "docker compose ps"
    _print_key_value "Logs" "docker compose logs -f"
    _print_key_value "Stop" "docker compose down"
    echo
    _log_info "SOPS+Age Management:"
    _print_key_value "Edit Secrets" "./tools/edit-secrets.sh"
    _print_key_value "Health Check" "./tools/check-health.sh"
    _print_key_value "View Secrets" "./tools/edit-secrets.sh --view"
    echo
    _log_info "Project Paths:"
    _print_key_value "Data" "$PROJECT_STATE_DIR"
    _print_key_value "Config" "$ROOT_DIR/settings.env"
    _print_key_value "Secrets" "$SECRETS_FILE"
    _print_key_value "Logs" "$PROJECT_STATE_DIR/logs"
}

_cleanup_orphaned_containers() {
    _log_debug "Cleaning up orphaned containers..."
    docker container prune -f >/dev/null 2>&1 || true
    docker network prune -f >/dev/null 2>&1 || true
}

# Enhanced argument handling
case "${1:-}" in
    --help|-h)
        cat <<EOM
${BOLD}$PROJECT_NAME - Enhanced Startup Script with SOPS+Age${NC}

${CYAN}USAGE:${NC}
  $0 [OPTIONS]

${CYAN}OPTIONS:${NC}
  --help, -h     Show this help message
  --validate     Validate configuration and prerequisites only
  --secrets-info Show encrypted secrets information

${CYAN}FEATURES:${NC}
  • SOPS + Age encrypted secrets management
  • Automatic Docker secrets preparation
  • Enhanced security with encrypted storage
  • Backward compatibility with legacy configurations
  • Comprehensive health monitoring

${CYAN}DYNAMIC CONFIGURATION:${NC}
  Project paths are automatically detected based on the repository name:
  • Project: $PROJECT_NAME
  • Data: $PROJECT_STATE_DIR
  • Secrets: $ROOT_DIR/secrets/

EOM
        exit 0
        ;;
    --validate)
        _log_header "$PROJECT_NAME Configuration Validation"
        _validate_startup_prerequisites
        if [[ -f "$SECRETS_FILE" ]]; then
            _load_encrypted_secrets
        fi
        load_config
        validate_configuration
        _log_success "Validation completed successfully"
        exit 0
        ;;
    --secrets-info)
        _log_header "Encrypted Secrets Information"
        _print_key_value "Secrets File" "$SECRETS_FILE"
        _print_key_value "Private Key" "$AGE_KEY_FILE"
        _print_key_value "Docker Secrets Dir" "$ROOT_DIR/secrets/.docker_secrets"
        echo
        if [[ -f "$SECRETS_FILE" ]]; then
            _log_info "Available secrets:"
            sops -d "$SECRETS_FILE" 2>/dev/null | yq eval 'keys | .[]' - 2>/dev/null | sed 's/^/  • /' || {
                _log_error "Cannot decrypt secrets file"
                exit 1
            }
        else
            _log_warning "Secrets file not found"
        fi
        echo
        _log_info "Management commands:"
        _log_info "  Edit secrets: ./tools/edit-secrets.sh"
        _log_info "  Health check: ./tools/check-health.sh"
        _log_info "  View secrets: ./tools/edit-secrets.sh --view"
        exit 0
        ;;
    "")
        _startup_workflow
        ;;
    *)
        _log_error "Unknown argument: $1"
        _log_info "Use --help for usage information"
        exit 1
        ;;
esac
