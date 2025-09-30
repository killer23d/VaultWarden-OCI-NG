#!/usr/bin/env bash
# lib/config.sh - Configuration management functions

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/common.sh"

# ================================
# CONFIGURATION CONSTANTS
# ================================

# Required environment variables
declare -ra REQUIRED_VARS=(
    "DOMAIN_NAME"
    "APP_DOMAIN"
    "ADMIN_TOKEN"
    "MARIADB_ROOT_PASSWORD"
    "MARIADB_PASSWORD"
    "REDIS_PASSWORD"
)

# Optional but recommended variables
declare -ra RECOMMENDED_VARS=(
    "SMTP_HOST"
    "BACKUP_PASSPHRASE"
    "PUSH_INSTALLATION_ID"
)

# Configuration file paths
declare -r FAIL2BAN_TEMPLATE="./fail2ban/jail.d/jail.local.template"
declare -r FAIL2BAN_CONFIG="./fail2ban/jail.d/jail.local"
declare -r CLOUDFLARE_IP_SCRIPT="./caddy/update_cloudflare_ips.sh"

# ================================
# ENVIRONMENT MANAGEMENT
# ================================

# Create secure environment file from OCI Vault or local settings
create_secure_env_file() {
    local output_file="$1"
    local source_type="${2:-auto}" # auto, local, oci
    
    log_info "Creating secure environment file..."
    
    case "$source_type" in
        "oci"|"auto")
            if is_oci_vault_configured && [[ -n "${OCI_SECRET_OCID:-}" ]]; then
                fetch_oci_config "$OCI_SECRET_OCID" "$output_file"
                return 0
            elif [[ "$source_type" == "oci" ]]; then
                log_error "OCI Vault not configured but explicitly requested"
            fi
            ;;&  # Fall through to local if auto mode
        "local"|"auto")
            if [[ -f "$SETTINGS_FILE" ]]; then
                log_info "Using local settings file"
                cp "$SETTINGS_FILE" "$output_file"
                chmod 600 "$output_file"
                log_success "Local configuration loaded"
                return 0
            fi
            ;;
        *)
            log_error "Unknown configuration source type: $source_type"
            ;;
    esac
    
    log_error "No configuration source available"
}

# Validate configuration variables
validate_configuration() {
    local env_file="$1"
    
    log_info "Validating configuration..."
    
    # Load environment
    set -a
    source "$env_file"
    set +a
    
    local errors=0
    local warnings=0
    
    # Check required variables
    for var in "${REQUIRED_VARS[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable not set: $var"
            ((errors++))
        else
            # Check password strength for password fields
            if [[ "$var" == *"PASSWORD"* ]] || [[ "$var" == *"TOKEN"* ]]; then
                if [[ ${#!var} -lt 16 ]]; then
                    log_warning "$var is shorter than 16 characters"
                    ((warnings++))
                fi
            fi
        fi
    done
    
    # Check recommended variables
    for var in "${RECOMMENDED_VARS[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_warning "Recommended variable not set: $var"
            ((warnings++))
        fi
    done
    
    # Validate domain format
    if [[ -n "${DOMAIN_NAME:-}" ]]; then
        if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
            log_success "Domain name format is valid"
        else
            log_warning "Domain name format may be invalid: $DOMAIN_NAME"
            ((warnings++))
        fi
    fi
    
    # Validate database URL consistency
    if [[ -n "${MARIADB_PASSWORD:-}" ]]; then
        local expected_db_url="mysql://${MARIADB_USER:-vaultwarden}:${MARIADB_PASSWORD}@bw_mariadb:3306/${MARIADB_DATABASE:-vaultwarden}"
        if [[ "${DATABASE_URL:-}" != "$expected_db_url" ]]; then
            log_warning "DATABASE_URL may be inconsistent with MariaDB settings"
            log_debug "Expected: $expected_db_url"
            log_debug "Actual: ${DATABASE_URL:-}"
            ((warnings++))
        fi
    fi
    
    # Summary
    if [[ $errors -gt 0 ]]; then
        log_error "Configuration validation failed with $errors errors"
        return 1
    elif [[ $warnings -gt 0 ]]; then
        log_warning "Configuration validation completed with $warnings warnings"
        return 0
    else
        log_success "Configuration validation passed with no issues"
        return 0
    fi
}

# ================================
# TEMPLATE PROCESSING
# ================================

# Process configuration template
process_template() {
    local template_file="$1"
    local output_file="$2"
    local env_file="${3:-}"
    
    log_info "Processing template: $template_file"
    
    if [[ ! -f "$template_file" ]]; then
        log_error "Template file not found: $template_file"
    fi
    
    # Load environment if provided
    if [[ -n "$env_file" ]]; then
        set -a
        source "$env_file"
        set +a
    fi
    
    # Process template with envsubst
    if envsubst < "$template_file" > "$output_file"; then
        log_success "Template processed: $output_file"
    else
        log_error "Failed to process template: $template_file"
    fi
}

# Generate Fail2ban configuration
generate_fail2ban_config() {
    local env_file="$1"
    
    log_info "Generating Fail2ban configuration..."
    
    if [[ ! -f "$FAIL2BAN_TEMPLATE" ]]; then
        log_error "Fail2ban template not found: $FAIL2BAN_TEMPLATE"
    fi
    
    process_template "$FAIL2BAN_TEMPLATE" "$FAIL2BAN_CONFIG" "$env_file"
}

# ================================
# CLOUDFLARE IP MANAGEMENT
# ================================

# Check if Cloudflare IPs need updating
need_cloudflare_ip_update() {
    local max_age_days="${1:-7}"
    local ip_files=("./caddy/cloudflare_ips.caddy" "./caddy/cloudflare_ips.txt")
    
    for file in "${ip_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_debug "Cloudflare IP file missing: $file"
            return 0  # Need update
        elif [[ $(find "$file" -mtime +$max_age_days 2>/dev/null) ]]; then
            log_debug "Cloudflare IP file older than $max_age_days days: $file"
            return 0  # Need update
        fi
    done
    
    return 1  # No update needed
}

# Update Cloudflare IPs
update_cloudflare_ips() {
    local force="${1:-false}"
    
    log_info "Checking Cloudflare IP configuration..."
    
    if [[ ! -f "$CLOUDFLARE_IP_SCRIPT" ]]; then
        log_warning "Cloudflare IP update script not found, skipping"
        return 0
    fi
    
    chmod +x "$CLOUDFLARE_IP_SCRIPT"
    
    if [[ "$force" == "true" ]] || need_cloudflare_ip_update; then
        log_info "Updating Cloudflare IP ranges..."
        if "$CLOUDFLARE_IP_SCRIPT"; then
            log_success "Cloudflare IP ranges updated"
            return 0
        else
            log_error "Failed to update Cloudflare IP ranges"
            return 1
        fi
    else
        log_info "Cloudflare IP files are current"
        return 0
    fi
}

# ================================
# CONFIGURATION MIGRATION
# ================================

# Migrate old configuration format to new format
migrate_configuration() {
    local old_config="$1"
    local new_config="$2"
    
    log_info "Migrating configuration format..."
    
    if [[ ! -f "$old_config" ]]; then
        log_error "Old configuration file not found: $old_config"
    fi
    
    # Create backup
    cp "$old_config" "${old_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Load old config
    set -a
    source "$old_config"
    set +a
    
    # Migrate variables (example migrations)
    {
        echo "# Migrated configuration - $(date)"
        echo
        
        # Domain configuration
        echo "# === DOMAIN & SECURITY CONFIGURATION ==="
        echo "DOMAIN_NAME=${DOMAIN_NAME:-}"
        echo "APP_DOMAIN=\${DOMAIN_NAME:+vault.\$DOMAIN_NAME}"
        echo "DOMAIN=\${APP_DOMAIN:+https://\$APP_DOMAIN}"
        echo
        
        # Add other migration rules as needed
        # This is a template - customize based on actual migration needs
        
    } > "$new_config"
    
    chmod 600 "$new_config"
    log_success "Configuration migrated to: $new_config"
}

# ================================
# PASSWORD MANAGEMENT
# ================================

# Generate secure passwords for configuration
generate_secure_config() {
    local output_file="$1"
    local template_file="${2:-$SETTINGS_EXAMPLE}"
    
    log_info "Generating secure configuration..."
    
    if [[ ! -f "$template_file" ]]; then
        log_error "Template file not found: $template_file"
    fi
    
    # Generate passwords for placeholder values
    local admin_token mariadb_root_password mariadb_password redis_password backup_passphrase
    admin_token=$(generate_password 32)
    mariadb_root_password=$(generate_password 32)
    mariadb_password=$(generate_password 32)
    redis_password=$(generate_password 32)
    backup_passphrase=$(generate_password 32)
    
    # Process template and replace placeholders
    sed \
        -e "s/generate-with-openssl-rand-base64-32/${admin_token}/g" \
        -e "s/your-very-strong-admin-token-here/${admin_token}/g" \
        -e "s/your-very-strong-root-password/${mariadb_root_password}/g" \
        -e "s/your-strong-db-password/${mariadb_password}/g" \
        -e "s/your-strong-redis-password/${redis_password}/g" \
        -e "s/your-very-strong-backup-passphrase/${backup_passphrase}/g" \
        "$template_file" > "$output_file"
    
    chmod 600 "$output_file"
    log_success "Secure configuration generated: $output_file"
    log_warning "Remember to customize domain and email settings in: $output_file"
}

# ================================
# CONFIGURATION VALIDATION HELPERS
# ================================

# Test SMTP configuration
test_smtp_config() {
    local env_file="$1"
    
    # Load environment
    set -a
    source "$env_file"
    set +a
    
    log_info "Testing SMTP configuration..."
    
    # Check required SMTP variables
    local required_smtp_vars=("SMTP_HOST" "SMTP_PORT" "SMTP_USERNAME" "SMTP_PASSWORD" "SMTP_FROM")
    for var in "${required_smtp_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_warning "SMTP variable not set: $var"
            return 1
        fi
    done
    
    # Test SMTP connectivity (basic check)
    if command_exists nc; then
        if nc -z "${SMTP_HOST}" "${SMTP_PORT}" 2>/dev/null; then
            log_success "SMTP server is reachable"
        else
            log_warning "SMTP server is not reachable"
        fi
    else
        log_debug "nc command not available, skipping SMTP connectivity test"
    fi
    
    return 0
}

# Test database connectivity
test_database_config() {
    local env_file="$1"
    
    # Load environment
    set -a
    source "$env_file"
    set +a
    
    log_info "Testing database configuration..."
    
    # Check if MariaDB container is running
    if is_service_running "bw_mariadb"; then
        local db_id
        db_id=$(get_container_id "bw_mariadb")
        
        if docker exec "$db_id" mysql -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" -e "SELECT 1;" "${MARIADB_DATABASE}" >/dev/null 2>&1; then
            log_success "Database connection successful"
            return 0
        else
            log_warning "Database connection failed"
            return 1
        fi
    else
        log_warning "MariaDB container is not running"
        return 1
    fi
}
