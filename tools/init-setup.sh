#!/usr/bin/env bash
# tools/init-setup.sh - Initialize VaultWarden-OCI-NG system with comprehensive setup

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    exit 1
fi
source "lib/logging.sh"

# Additional required libraries
for lib in config validation system sops security install; do
    lib_file="lib/${lib}.sh"
    if [[ -f "$lib_file" ]]; then
        # shellcheck source=/dev/null
        source "$lib_file"
    else
        log_error "CRITICAL: Required library not found: $lib_file"
        exit 1
    fi
done

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# P1 FIX: Add standardized error handling
trap 'log_error "Script failed at line $LINENO in $(basename "${BASH_SOURCE[0]}")"; exit 1' ERR

# --- P2 FIX: Progress indication functions ---
show_progress() {
    local step=$1 total=$2 description="$3"
    local show_percent="${4:-false}"

    echo "[$step/$total] $description..."
    if [[ "$show_percent" == "true" ]]; then
        local percent=$(( step * 100 / total ))
        echo "Progress: ${percent}%"
    fi
}

show_setup_phase() {
    local phase="$1"
    local step="$2"
    local total="$3"

    log_header "Phase $step/$total: $phase"
}

# --- Configuration Variables ---
DOMAIN=""
ADMIN_EMAIL=""
RESTORE_MODE=false
SKIP_FIREWALL=false
AUTO_MODE=false

# --- Help Text ---
show_help() {
    cat << EOF
VaultWarden-OCI-NG System Initialization Script

USAGE:
    sudo $0 --domain DOMAIN --email EMAIL [OPTIONS]

DESCRIPTION:
    Initializes the VaultWarden-OCI-NG system with secure defaults, including:
    - System dependencies verification
    - Age encryption key generation
    - SOPS configuration setup
    - Firewall configuration (UFW + fail2ban)
    - Directory structure creation
    - Cron job installation
    - Initial secrets template

REQUIRED ARGUMENTS:
    --domain DOMAIN     Domain name for VaultWarden (e.g., vault.example.com)
    --email EMAIL       Admin email address for certificates and notifications

OPTIONS:
    --help             Show this help message
    --restore-mode     Skip key/config generation if files already exist
    --skip-firewall    Skip firewall configuration (not recommended)
    --auto             Run in non-interactive mode with minimal prompts

EXAMPLES:
    # Fresh installation
    sudo $0 --domain vault.example.com --email admin@example.com

    # Restore from backup
    sudo $0 --domain vault.example.com --email admin@example.com --restore-mode

NOTES:
    - This script requires root privileges for system configuration
    - Existing configurations are preserved when using --restore-mode
    - Generated Age keys are stored securely in secrets/keys/
EOF
}

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --email)
                ADMIN_EMAIL="$2"
                shift 2
                ;;
            --restore-mode)
                RESTORE_MODE=true
                shift
                ;;
            --skip-firewall)
                SKIP_FIREWALL=true
                shift
                ;;
            --auto)
                AUTO_MODE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$DOMAIN" ]]; then
        log_error "Domain is required. Use --domain to specify."
        show_help
        exit 1
    fi

    if [[ -z "$ADMIN_EMAIL" ]]; then
        log_error "Admin email is required. Use --email to specify."
        show_help
        exit 1
    fi
}

# --- Validation Functions ---
validate_inputs() {
    show_setup_phase "Input Validation" 1 9

    _log_section "Validating Input Parameters"
    local errors=0

    show_progress 1 3 "Validating domain format"
    # Validate domain format
    if ! validate_domain_format "$DOMAIN"; then
        log_error "Invalid domain format: $DOMAIN"
        ((errors++))
    fi

    show_progress 2 3 "Validating email format"
    # Validate email format
    if ! validate_email_format "$ADMIN_EMAIL"; then
        log_error "Invalid email format: $ADMIN_EMAIL"
        ((errors++))
    fi

    show_progress 3 3 "Checking root privileges"
    # Check root privileges
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges. Please run with sudo."
        ((errors++))
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Input validation failed with $errors error(s)."
        return 1
    fi

    log_success "Input validation passed."
    return 0
}

# --- System Setup Functions ---
setup_directories() {
    show_setup_phase "Directory Structure" 2 9

    _log_section "Setting Up Directory Structure"

    local directories=(
        "secrets/keys"
        "secrets/.docker_secrets"
        "templates"
        "caddy"
        "fail2ban"
        "ddclient"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/caddy"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/fail2ban"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/system"
        "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/backups"
    )

    show_progress 1 3 "Creating directory structure"

    local created_count=0
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_info "Creating directory: $dir"
            if mkdir -p "$dir"; then
                ((created_count++))
            else
                log_error "Failed to create directory: $dir"
                return 1
            fi
        else
            _log_debug "Directory already exists: $dir"
        fi
    done

    show_progress 2 3 "Setting directory permissions"

    # Set appropriate permissions
    chmod 700 secrets/keys secrets/.docker_secrets
    chmod 755 "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    chmod 750 "${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data"

    show_progress 3 3 "Verifying directory structure"

    log_success "Directory structure created successfully ($created_count new directories)."
}

generate_age_keys() {
    show_setup_phase "Encryption Keys" 3 9

    _log_section "Generating Age Encryption Keys"

    local age_key_file="secrets/keys/age-key.txt"
    local age_pub_file="secrets/keys/age-public-key.txt"

    show_progress 1 3 "Checking existing keys"

    if [[ "$RESTORE_MODE" == "true" && -f "$age_key_file" ]]; then
        log_info "Restore mode: Age key already exists, skipping generation."
        return 0
    fi

    if [[ -f "$age_key_file" && "$RESTORE_MODE" == "false" ]]; then
        log_warn "Age key already exists. Use --restore-mode to skip regeneration."
        if [[ "$AUTO_MODE" != "true" ]]; then
            read -p "Regenerate Age key? This will invalidate existing encrypted data (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Keeping existing Age key."
                return 0
            fi
        else
            log_info "Auto mode: Keeping existing Age key."
            return 0
        fi
    fi

    show_progress 2 3 "Generating Age private key"

    log_info "Generating new Age encryption key..."
    if ! age-keygen -o "$age_key_file" 2>/dev/null; then
        log_error "Failed to generate Age private key."
        return 1
    fi

    show_progress 3 3 "Generating Age public key"

    # Generate public key
    if ! age-keygen -y "$age_key_file" > "$age_pub_file"; then
        log_error "Failed to generate Age public key."
        return 1
    fi

    # Set secure permissions
    chmod 600 "$age_key_file"
    chmod 644 "$age_pub_file"

    log_success "Age encryption keys generated successfully."
    log_info "Private key: $age_key_file"
    log_info "Public key: $age_pub_file"
}

create_sops_config() {
    show_setup_phase "SOPS Configuration" 4 9

    _log_section "Creating SOPS Configuration"

    local sops_config=".sops.yaml"
    local age_pub_file="secrets/keys/age-public-key.txt"

    show_progress 1 2 "Checking existing SOPS config"

    if [[ "$RESTORE_MODE" == "true" && -f "$sops_config" ]]; then
        log_info "Restore mode: SOPS config already exists, skipping creation."
        return 0
    fi

    if [[ ! -f "$age_pub_file" ]]; then
        log_error "Age public key not found: $age_pub_file"
        return 1
    fi

    show_progress 2 2 "Creating SOPS configuration file"

    local age_public_key
    age_public_key=$(cat "$age_pub_file")

    log_info "Creating SOPS configuration..."
    cat > "$sops_config" << EOF
creation_rules:
  - path_regex: secrets/.*\.yaml$
    age: >-
      $age_public_key
    encrypted_regex: ^(data|stringData|password|token|key|secret)$
EOF

    chmod 644 "$sops_config"
    log_success "SOPS configuration created: $sops_config"
}

create_env_file() {
    show_setup_phase "Environment Configuration" 5 9

    _log_section "Creating Environment Configuration"

    local env_file=".env"

    show_progress 1 2 "Checking existing environment file"

    if [[ "$RESTORE_MODE" == "true" && -f "$env_file" ]]; then
        log_info "Restore mode: Environment file already exists, skipping creation."
        return 0
    fi

    show_progress 2 2 "Generating environment configuration"

    log_info "Creating environment configuration file..."

    # Use CLEAN_DOMAIN if set by validation, otherwise derive it
    local clean_domain="${CLEAN_DOMAIN:-$DOMAIN}"
    clean_domain="${clean_domain#http://}"
    clean_domain="${clean_domain#https://}"
    clean_domain="${clean_domain%/}"

    cat > "$env_file" << EOF
# VaultWarden-OCI-NG Environment Configuration
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')

# Domain Configuration
DOMAIN=$clean_domain
ADMIN_EMAIL=$ADMIN_EMAIL

# Project Configuration
PROJECT_STATE_DIR=${PROJECT_STATE_DIR:-/var/lib/vaultwarden}
TZ=${TZ:-UTC}

# VaultWarden Configuration
SIGNUPS_ALLOWED=false
INVITATIONS_ALLOWED=true
WEBSOCKET_ENABLED=true
LOG_LEVEL=warn
EXTENDED_LOGGING=true

# SMTP Configuration (configure via tools/edit-secrets.sh)
SMTP_HOST=
SMTP_FROM=$ADMIN_EMAIL
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=

# Push Notifications (configure via tools/edit-secrets.sh)
PUSH_ENABLED=false
PUSH_INSTALLATION_ID=
PUSH_RELAY_URI=https://api.bitwarden.com

# DDClient Configuration (optional)
DDCLIENT_ENABLED=false
DDCLIENT_PROTOCOL=cloudflare
DDCLIENT_ZONE=

# Resource Limits
VAULTWARDEN_MEMORY_LIMIT=1.5G
VAULTWARDEN_MEMORY_RESERVATION=256M
CADDY_MEMORY_LIMIT=384M
CADDY_MEMORY_RESERVATION=64M
FAIL2BAN_MEMORY_LIMIT=192M
FAIL2BAN_MEMORY_RESERVATION=64M
WATCHTOWER_MEMORY_LIMIT=128M
WATCHTOWER_MEMORY_RESERVATION=32M
DDCLIENT_MEMORY_LIMIT=64M
DDCLIENT_MEMORY_RESERVATION=16M
EOF

    chmod 640 "$env_file"
    log_success "Environment configuration created: $env_file"
}

create_initial_secrets() {
    show_setup_phase "Initial Secrets" 6 9

    _log_section "Creating Initial Secrets Template"

    local secrets_file="secrets/secrets.yaml"

    show_progress 1 4 "Checking existing secrets file"

    if [[ "$RESTORE_MODE" == "true" && -f "$secrets_file" ]]; then
        log_info "Restore mode: Secrets file already exists, skipping creation."
        return 0
    fi

    show_progress 2 4 "Generating secure tokens"

    log_info "Creating initial secrets template..."

    # Generate secure tokens
    local admin_token smtp_password backup_passphrase push_key
    admin_token=$(generate_secure_token 64)
    smtp_password="your_smtp_password_here"
    backup_passphrase=$(generate_secure_token 32)
    push_key="your_push_installation_key_here"

    show_progress 3 4 "Creating admin authentication hash"

    # Generate admin basic auth hash
    local admin_basic_auth_hash
    admin_basic_auth_hash=$(printf "admin:%s" "$(generate_secure_token 16)" | base64)

    cat > "$secrets_file" << EOF
# VaultWarden-OCI-NG Secrets Configuration
# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# Edit with: ./tools/edit-secrets.sh

# Admin Panel Access
admin_token: "$admin_token"
admin_basic_auth_hash: "$admin_basic_auth_hash"

# SMTP Configuration
smtp_password: "$smtp_password"

# Backup Configuration
backup_passphrase: "$backup_passphrase"

# Push Notifications
push_installation_key: "$push_key"

# Cloudflare Integration (optional)
cloudflare_api_token: "your_cloudflare_token_here"
EOF

    show_progress 4 4 "Encrypting secrets with SOPS"

    # Encrypt with SOPS
    if ! sops --encrypt --in-place "$secrets_file"; then
        log_error "Failed to encrypt secrets file with SOPS."
        return 1
    fi

    chmod 640 "$secrets_file"
    log_success "Initial secrets template created and encrypted: $secrets_file"
    log_warn "Configure actual secrets using: ./tools/edit-secrets.sh"
}

configure_firewall() {
    show_setup_phase "Firewall Setup" 7 9

    if [[ "$SKIP_FIREWALL" == "true" ]]; then
        log_info "Skipping firewall configuration as requested."
        return 0
    fi

    _log_section "Configuring System Firewall"

    show_progress 1 1 "Applying firewall configuration"

    if ! configure_system_security "$AUTO_MODE"; then
        log_error "Failed to configure system security."
        return 1
    fi

    log_success "Firewall configuration completed."
}

install_cron_jobs() {
    show_setup_phase "Automation Setup" 8 9

    _log_section "Installing Cron Jobs"

    show_progress 1 2 "Loading cron configuration library"

    # Source cron library if available
    if [[ -f "lib/cron.sh" ]]; then
        source "lib/cron.sh"
        if declare -f install_cron_jobs_for_user >/dev/null; then
            show_progress 2 2 "Installing automated maintenance jobs"
            install_cron_jobs_for_user "root"
        else
            log_warn "Cron installation function not found in lib/cron.sh"
        fi
    else
        log_warn "Cron library not found: lib/cron.sh"
    fi

    log_success "Cron jobs installation completed."
}

secure_permissions() {
    show_setup_phase "Security Hardening" 9 9

    _log_section "Securing File Permissions"

    show_progress 1 2 "Applying security permissions"

    if ! secure_project_permissions; then
        log_warn "Some permission changes failed, but continuing."
    fi

    show_progress 2 2 "Verifying critical file permissions"

    # Verify critical files have correct permissions
    local critical_files=(
        "secrets/keys/age-key.txt:600"
        ".env:640"
        "secrets/secrets.yaml:640"
    )

    for file_perm in "${critical_files[@]}"; do
        local file="${file_perm%:*}"
        local expected_perm="${file_perm#*:}"

        if [[ -f "$file" ]]; then
            local actual_perm
            actual_perm=$(stat -c "%a" "$file")
            if [[ "$actual_perm" != "$expected_perm" ]]; then
                log_warn "File $file has permissions $actual_perm (expected $expected_perm)"
            else
                _log_debug "File $file has correct permissions: $actual_perm"
            fi
        fi
    done

    log_success "File permissions secured."
}

# --- Main Execution ---
main() {
    log_header "VaultWarden-OCI-NG System Initialization"

    parse_arguments "$@"

    # Run setup steps with progress tracking
    validate_inputs || exit 1

    log_info "Running full system validation..."
    validate_full_system || exit 1

    # Execute all setup phases
    setup_directories || exit 1
    generate_age_keys || exit 1
    create_sops_config || exit 1
    create_env_file || exit 1
    create_initial_secrets || exit 1
    configure_firewall || exit 1
    install_cron_jobs || exit 1
    secure_permissions || exit 1

    # Final message with next steps
    log_success "VaultWarden-OCI-NG initialization completed successfully!"
    echo
    log_header "Next Steps"
    echo
    log_info "1. Configure secrets: ./tools/edit-secrets.sh"
    log_info "2. Start services: ./startup.sh"
    log_info "3. Verify deployment: ./tools/check-health.sh --comprehensive"
    echo
    log_warn "IMPORTANT: Backup your Age key securely!"
    log_warn "Private key location: secrets/keys/age-key.txt"
    echo
    log_info "Access your VaultWarden instance at: https://${CLEAN_DOMAIN:-$DOMAIN}"
}

# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
