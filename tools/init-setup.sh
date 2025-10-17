#!/usr/bin/env bash
# tools/init-setup.sh - Orchestrates initial system setup with SOPS+Age integration.

set -euo pipefail

# Auto-detect script location and project paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source core libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/validation.sh"
source "$ROOT_DIR/lib/system.sh"

# Source new modular libraries
source "$ROOT_DIR/lib/install.sh"
source "$ROOT_DIR/lib/security.sh"
source "$ROOT_DIR/lib/cron.sh"

_set_log_prefix "init"

# Constants
readonly AGE_KEY_FILE="$ROOT_DIR/secrets/keys/age-key.txt"
readonly SOPS_CONFIG_FILE="$ROOT_DIR/.sops.yaml"
readonly SECRETS_FILE="$ROOT_DIR/secrets/secrets.yaml"
readonly CONFIG_FILE="$ROOT_DIR/settings.env"

# Automatically fix script permissions
_auto_fix_script_permissions() {
    _log_section "Checking and Fixing Script Permissions"
    find "$ROOT_DIR" -name "*.sh" -type f ! -path "*/.*" -exec chmod +x {} \;
    _log_success "All script permissions automatically corrected."
}

# Parse command line arguments first
AUTO_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --auto)
            AUTO_MODE=true
            shift
            ;;
        --help|-h)
            cat <<EOF
${BOLD}$PROJECT_NAME - Initial Setup Orchestrator with SOPS+Age${NC}

${CYAN}USAGE:${NC}
  $0 [OPTIONS]

${CYAN}OPTIONS:${NC}
  --auto         Run in automated mode with minimal prompts
  --help, -h     Show this help message
EOF
            exit 0
            ;;
        *)
            _log_error "Unknown argument: $1"; exit 1;;
    esac
done

# Main initialization workflow
_init_setup_workflow() {
    _log_header "$PROJECT_NAME - Enhanced Setup with SOPS+Age"
    _log_info "Mode: $([[ "$AUTO_MODE" == "true" ]] && echo "Automated" || echo "Interactive")"

    _auto_fix_script_permissions
    _validate_system_requirements
    
    # Calls to modular libraries
    install_system_packages "$AUTO_MODE"
    install_sops_age_tools
    
    _setup_age_encryption
    _setup_docker_environment
    
    # Calls to modular libraries
    configure_system_security "$AUTO_MODE"
    
    _generate_initial_configuration
    _create_initial_secrets_file
    _create_system_structure
    
    # Calls to modular libraries
    configure_cloudflare_fail2ban
    setup_cron_jobs "$AUTO_MODE"
    
    _validate_setup_completion

    _log_success "Enhanced setup with SOPS+Age completed successfully!"
    touch "$PROJECT_STATE_DIR/.setup-complete"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PROJECT_STATE_DIR/.setup-complete"
    _display_next_steps
}

# Validate system requirements with SOPS+Age additions
_validate_system_requirements() {
    _log_section "System Requirements Validation"
    _validate_running_as_root
    _validate_os_compatibility
    _validate_systemd_availability
    _validate_system_resources
    _validate_network_connectivity
    if [[ -f "$AGE_KEY_FILE" ]] && [[ -f "$SECRETS_FILE" ]] && [[ "$AUTO_MODE" != "true" ]]; then
        _log_info "SOPS+Age setup already exists"
        _log_confirm "Reinitialize SOPS+Age setup?" "N"
        read -r response
        response=${response:-N}
        if [[ ! "$response" =~ ^[yY][eE][sS]?$ ]]; then
            _log_info "Skipping SOPS+Age reinitialization"
        fi
    fi
}

# Setup Age encryption keys and SOPS configuration
_setup_age_encryption() {
    _log_section "Setting Up Age Encryption"
    local secrets_dir="$ROOT_DIR/secrets"; local keys_dir="$secrets_dir/keys"
    _create_directory_secure "$secrets_dir" "755"; _create_directory_secure "$keys_dir" "700"

    if [[ -f "$AGE_KEY_FILE" ]]; then
        _log_info "Age key already exists."
    else
        _log_info "Generating new Age key pair..."
        age-keygen -o "$AGE_KEY_FILE" || { _log_error "Failed to generate Age key"; return 1; }
        chmod 600 "$AGE_KEY_FILE"
        _log_success "Age key generated successfully"
        local pubkey; pubkey=$(age-keygen -y "$AGE_KEY_FILE")
        _log_info "Updating SOPS configuration..."
        if [[ -f "$SOPS_CONFIG_FILE" ]]; then
            sed -i "s|age1.*|$pubkey|" "$SOPS_CONFIG_FILE"
            _log_success "SOPS configuration updated with new public key"
        fi
        cat > "$keys_dir/backup-info.txt" <<EOF
# Age Key Backup Information
PUBLIC_KEY=$pubkey
CREATED_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BACKUP_STATUS=REQUIRED
EOF
    fi
    if [[ "$AUTO_MODE" != "true" ]]; then _display_critical_backup_warning; fi
    _log_success "Age encryption setup completed"
}

# Display critical backup warning
_display_critical_backup_warning() {
    echo; _log_error "🚨 CRITICAL: AGE PRIVATE KEY BACKUP REQUIRED 🚨"
    _log_info "Your Age private key is at: $AGE_KEY_FILE"
    _log_info "⚠️  WITHOUT THIS KEY, YOUR ENCRYPTED SECRETS WILL BE PERMANENTLY LOST!"
    _log_prompt "Type 'I UNDERSTAND' to acknowledge backup responsibility"; read -r response
    if [[ "$response" != "I UNDERSTAND" ]]; then _log_error "Backup acknowledgment required. Setup cancelled."; exit 1; fi
    _log_success "Backup responsibility acknowledged"
}

_setup_docker_environment() {
    _log_section "Docker Environment Setup"
    _enable_service "docker"; _start_service "docker"
    _validate_docker_daemon; _validate_docker_compose
    local current_sudo_user="${SUDO_USER:-}";
    if [[ -n "$current_sudo_user" ]] && [[ "$current_sudo_user" != "root" ]]; then
        usermod -aG docker "$current_sudo_user";
        _log_info "User $current_sudo_user added to docker group. Log out and back in for changes to take effect."
    fi
}

_generate_initial_configuration() {
    _log_section "Configuration Generation"
    local domain admin_email
    if [[ "$AUTO_MODE" == "true" ]]; then
        domain="https://localhost"; admin_email="admin@localhost"
    else
        _log_prompt "Enter your domain name (e.g., https://vault.example.com)"; read -r domain
        _log_prompt "Enter admin email address"; read -r admin_email
    fi
    _create_configuration_file "$domain" "$admin_email"
    _log_success "Initial configuration generated (secrets will be stored encrypted)"
}

_create_configuration_file() {
    local domain="$1" admin_email="$2"
    cat > "$CONFIG_FILE" <<EOF
# settings.env - Non-sensitive VaultWarden configuration
DOMAIN=${domain}
ADMIN_EMAIL=${admin_email}
DATABASE_URL=sqlite:///data/db.sqlite3
WEBSOCKET_ENABLED=true
SIGNUPS_ALLOWED=false
SMTP_HOST=
SMTP_FROM=
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=
TZ=UTC
EOF
    chmod 600 "$CONFIG_FILE"; chown root:root "$CONFIG_FILE"
    _log_success "Configuration file created: $CONFIG_FILE"
}

_create_initial_secrets_file() {
    _log_info "Creating initial encrypted secrets template..."
    local admin_token; admin_token=$(openssl rand -base64 32)
    local backup_pass; backup_pass=$(openssl rand -base64 32)
    cat > "/tmp/secrets.yaml" <<EOF
admin_token: "$admin_token"
smtp_password: ""
backup_passphrase: "$backup_pass"
cloudflare_api_token: ""
push_installation_key: ""
EOF
    if sops -e "/tmp/secrets.yaml" > "$SECRETS_FILE"; then
        shred -u "/tmp/secrets.yaml" 2>/dev/null || rm -f "/tmp/secrets.yaml"
        _log_success "Initial encrypted secrets file created."
    else
        _log_error "Failed to create encrypted secrets file."; return 1;
    fi
}

_create_system_structure() {
    _log_section "System Structure Creation"
    local directories=("$PROJECT_STATE_DIR" "$PROJECT_STATE_DIR/data/bwdata" "$PROJECT_STATE_DIR/logs" "$PROJECT_STATE_DIR/backups/db" "$PROJECT_STATE_DIR/backups/full" "$ROOT_DIR/caddy" "$ROOT_DIR/ddclient")
    for dir in "${directories[@]}"; do _create_directory_secure "$dir" "755"; done
    _create_file_secure "$ROOT_DIR/caddy/cloudflare-ips.caddy" "644" "# Placeholder"
    _create_file_secure "$ROOT_DIR/ddclient/ddclient.conf" "600" "# Placeholder"
    _log_success "System structure created successfully"
}

_validate_setup_completion() {
    _log_section "Setup Validation"
    if [[ ! -f "$CONFIG_FILE" ]] || [[ ! -f "$AGE_KEY_FILE" ]] || [[ ! -f "$SECRETS_FILE" ]]; then
        _log_error "Configuration or secrets file validation failed"; return 1;
    fi
    if ! sops -d "$SECRETS_FILE" >/dev/null 2>&1; then
        _log_error "SOPS decryption test failed"; return 1;
    fi
    _validate_docker_daemon; _validate_docker_compose
    _log_success "Setup validation completed successfully"
}

_display_next_steps() {
    echo; _log_header "Setup Complete - Next Steps"
    _log_numbered_item 1 "🔐 IMMEDIATELY backup your Age private key: cp $AGE_KEY_FILE /secure/backup/location/"
    _log_numbered_item 2 "📝 Edit encrypted secrets: ./tools/edit-secrets.sh"
    _log_numbered_item 3 "⚙️  Review configuration: nano $CONFIG_FILE"
    _log_numbered_item 4 "🚀 Start services: ./startup.sh"
    _log_numbered_item 5 "🔍 Validate system health: ./tools/check-health.sh"
    local domain; domain=$(grep "DOMAIN=" "$CONFIG_FILE" | cut -d'=' -f2)
    _log_numbered_item 6 "🌐 Access VaultWarden: $domain"
    echo; _log_error "🚨 REMINDER: Backup your Age private key NOW!"
}

# Execute the workflow
_init_setup_workflow