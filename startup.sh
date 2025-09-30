#!/usr/bin/env bash
# startup.sh -- Enhanced startup script with profile management and best practices
# VaultWarden-OCI-NG - Production deployment script

# Set up environment
set -euo pipefail
export DEBUG="${DEBUG:-false}"
export LOG_FILE="/tmp/vaultwarden_startup_$(date +%Y%m%d_%H%M%S).log"

# Source library modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/docker.sh" 
source "$SCRIPT_DIR/lib/config.sh"

# ================================
# PROFILE MANAGEMENT FUNCTIONS
# ================================

# Determine which profiles to activate based on configuration
determine_active_profiles() {
    local -a profiles=()
    
    log_info "Determining active service profiles..."
    
    # Backup profile
    if [[ "${ENABLE_BACKUP:-false}" == "true" ]]; then
        profiles+=(--profile backup)
        log_success "✅ Backup profile enabled"
        
        # Prepare backup configuration directory
        prepare_backup_config
    else
        log_info "ℹ️  Backup profile disabled"
    fi
    
    # Security profile (fail2ban)
    if [[ "${ENABLE_SECURITY:-true}" == "true" ]]; then
        profiles+=(--profile security)
        log_success "✅ Security profile enabled (fail2ban)"
    else
        log_info "ℹ️  Security profile disabled"
    fi
    
    # DNS profile (ddclient)
    if [[ "${ENABLE_DNS:-false}" == "true" ]]; then
        profiles+=(--profile dns)
        log_success "✅ DNS profile enabled (ddclient)"
    else
        log_info "ℹ️  DNS profile disabled"
    fi
    
    # Maintenance profile (watchtower, logrotate)
    if [[ "${ENABLE_MAINTENANCE:-true}" == "true" ]]; then
        profiles+=(--profile maintenance)
        log_success "✅ Maintenance profile enabled (watchtower, logrotate)"
    else
        log_info "ℹ️  Maintenance profile disabled"
    fi
    
    # Development profile (future)
    if [[ "${ENABLE_DEVELOPMENT:-false}" == "true" ]]; then
        profiles+=(--profile development)
        log_warning "⚠️  Development profile enabled"
    fi
    
    # Export for use in other functions
    export ACTIVE_PROFILES=("${profiles[@]}")
    
    if [[ ${#profiles[@]} -eq 0 ]]; then
        log_info "Using core services only (no optional profiles)"
    else
        log_info "Active profiles: ${profiles[*]}"
    fi
}

# Prepare backup configuration directory
prepare_backup_config() {
    local config_dir="${RCLONE_CONFIG_DIR:-./backup/config}"
    local config_file="$config_dir/rclone.conf"
    local template_file="./backup/templates/rclone.conf.example"
    
    log_info "Preparing backup configuration..."
    
    # Create config directory with proper permissions
    mkdir -p "$config_dir"
    chmod 700 "$config_dir"
    
    # Create rclone.conf if it doesn't exist
    if [[ ! -f "$config_file" ]]; then
        if [[ -f "$template_file" ]]; then
            log_info "Creating rclone.conf from template"
            cp "$template_file" "$config_file"
        else
            log_info "Creating empty rclone.conf"
            cat > "$config_file" << 'EOF'
# rclone configuration file
# Add your remote configurations here
# 
# Example for Backblaze B2:
# [b2-backup]
# type = b2
# account = your-account-id
# key = your-application-key
# 
# Run 'docker compose exec bw_backup rclone config' to configure interactively
EOF
        fi
        chmod 600 "$config_file"
        log_warning "⚠️  Empty rclone.conf created. Configure your backup remote before enabling backups."
    else
        log_success "✅ rclone.conf exists"
    fi
    
    # Validate rclone configuration if backup remote is specified
    if [[ -n "${BACKUP_REMOTE:-}" ]]; then
        log_info "Validating backup remote configuration..."
        # Note: Full validation happens inside the container
        log_info "Backup remote configured: ${BACKUP_REMOTE}"
    fi
}

# ================================
# ENHANCED MAIN FUNCTIONS
# ================================

# Initialize environment with profile support
initialize() {
    log_info "Initializing VaultWarden-OCI startup..."
    
    # Validate system requirements
    validate_system_requirements
    
    # Validate project structure
    validate_project_structure
    
    # Load and validate configuration
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        source "$SETTINGS_FILE"
        set +a
        log_success "Configuration loaded from $SETTINGS_FILE"
    else
        log_error "Configuration file not found: $SETTINGS_FILE"
    fi
    
    # Determine active profiles based on configuration
    determine_active_profiles
    
    log_success "Initialization complete"
}

# Setup configuration with enhanced validation
setup_configuration() {
    log_info "Setting up configuration..."
    
    # Create secure temporary directory for environment file
    local tmpdir
    tmpdir=$(create_secure_tmpdir "startup")
    local env_file="$tmpdir/settings.env"
    
    # Create secure environment file
    create_secure_env_file "$env_file" "auto"
    
    # Validate configuration
    validate_configuration "$env_file"
    
    # Update Cloudflare IPs if needed
    update_cloudflare_ips "${FORCE_IP_UPDATE:-false}"
    
    # Generate Fail2ban configuration (if security profile enabled)
    if [[ "${ENABLE_SECURITY:-true}" == "true" ]]; then
        generate_fail2ban_config "$env_file"
    fi
    
    # Export env file path for Docker Compose
    export COMPOSE_ENV_FILE="$env_file"
    
    log_success "Configuration setup complete"
}

# Deploy stack with profile support
deploy_stack() {
    log_info "Deploying container stack with profiles..."
    
    # Build Docker Compose command with profiles
    local compose_cmd=(docker compose --env-file "$COMPOSE_ENV_FILE")
    
    # Add profile arguments
    for profile in "${ACTIVE_PROFILES[@]}"; do
        compose_cmd+=("$profile")
    done
    
    # Add the up command
    compose_cmd+=(up -d --remove-orphans)
    
    log_info "Running: ${compose_cmd[*]}"
    
    # Start the stack
    if "${compose_cmd[@]}"; then
        log_success "Stack started successfully"
    else
        log_error "Failed to start stack"
    fi
    
    # Wait for critical services to be healthy
    local critical_services=("vaultwarden" "bw_mariadb" "bw_redis")
    
    for service in "${critical_services[@]}"; do
        if wait_for_service "$service" 120 10; then
            log_success "✅ Service $service is ready"
        else
            log_warning "⚠️  Service $service may not be fully ready"
        fi
    done
    
    # Wait for profile services if enabled
    wait_for_profile_services
    
    # Perform comprehensive health check
    if perform_health_check; then
        log_success "✅ All services are healthy"
    else
        log_warning "⚠️  Some services may have issues"
    fi
    
    log_success "Stack deployment complete"
}

# Wait for profile-specific services
wait_for_profile_services() {
    log_info "Checking profile service status..."
    
    # Check backup service
    if [[ "${ENABLE_BACKUP:-false}" == "true" ]]; then
        if wait_for_service "bw_backup" 60 5; then
            log_success "✅ Backup service is ready"
        else
            log_warning "⚠️  Backup service may not be fully ready"
        fi
    fi
    
    # Check security service
    if [[ "${ENABLE_SECURITY:-true}" == "true" ]]; then
        if wait_for_service "bw_fail2ban" 90 5; then
            log_success "✅ Security service (fail2ban) is ready"
        else
            log_warning "⚠️  Security service may not be fully ready"
        fi
    fi
    
    # Check DNS service
    if [[ "${ENABLE_DNS:-false}" == "true" ]]; then
        if wait_for_service "bw_ddclient" 60 5; then
            log_success "✅ DNS service (ddclient) is ready"
        else
            log_warning "⚠️  DNS service may not be fully ready"
        fi
    fi
    
    # Check maintenance services
    if [[ "${ENABLE_MAINTENANCE:-true}" == "true" ]]; then
        if wait_for_service "bw_watchtower" 30 5; then
            log_success "✅ Watchtower service is ready"
        else
            log_info "ℹ️  Watchtower service status unknown (normal)"
        fi
    fi
}

# Enhanced status display
show_status() {
    log_info "VaultWarden-OCI Status:"
    echo "========================================"
    
    # Load config for domain info
    if [[ -f "$COMPOSE_ENV_FILE" ]]; then
        set -a
        source "$COMPOSE_ENV_FILE"
        set +a
        
        echo "🌐 Domain: ${APP_DOMAIN:-'Not configured'}"
        echo "🔗 URL: ${DOMAIN:-'Not configured'}"
        echo "⚙️  Profiles: ${ACTIVE_PROFILES[*]:-'core only'}"
    fi
    
    echo ""
    echo "📊 Service Status:"
    
    # Build status command with same profiles
    local status_cmd=(docker compose --env-file "$COMPOSE_ENV_FILE")
    for profile in "${ACTIVE_PROFILES[@]}"; do
        status_cmd+=("$profile")
    done
    status_cmd+=(ps)
    
    "${status_cmd[@]}"
    
    echo "========================================"
    log_info "💡 Management Commands:"
    echo "  ./monitor.sh       - Real-time monitoring dashboard"
    echo "  ./diagnose.sh      - Comprehensive health diagnostics"
    echo "  ./perf-monitor.sh  - Performance monitoring"
    echo "  ./alerts.sh        - Alert management"
    echo ""
    echo "  Profile Management:"
    echo "  docker compose --profile backup ps     - Backup service status"
    echo "  docker compose --profile security ps   - Security service status"
}

# ================================
# ENHANCED MAIN EXECUTION
# ================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force-ip-update)
                export FORCE_IP_UPDATE="true"
                shift
                ;;
            --debug)
                export DEBUG="true"
                shift
                ;;
            --profile)
                # Override profile selection
                export FORCE_PROFILES="$2"
                shift 2
                ;;
            --help|-h)
                cat <<EOF
VaultWarden-OCI Enhanced Startup Script

Usage: $0 [OPTIONS]

Options:
    --force-ip-update    Force update of Cloudflare IP ranges
    --debug             Enable debug logging
    --profile PROFILES  Force specific profiles (comma-separated)
    --help, -h          Show this help message

Environment Variables:
    OCI_SECRET_OCID     Use OCI Vault for configuration
    DEBUG               Enable debug logging
    LOG_FILE            Custom log file path
    
    Profile Control (settings.env):
    ENABLE_BACKUP       Enable backup services
    ENABLE_SECURITY     Enable security services (fail2ban)
    ENABLE_DNS          Enable DNS services (ddclient) 
    ENABLE_MAINTENANCE  Enable maintenance services (watchtower)

Examples:
    $0                                    # Start with auto-detected profiles
    $0 --force-ip-update                  # Force IP update during startup
    ENABLE_BACKUP=false $0                # Start without backup services
    OCI_SECRET_OCID=ocid1... $0           # Use OCI Vault configuration
    DEBUG=true $0                         # Debug mode startup

Profile Information:
    core        - Essential services (always enabled)
    backup      - Database backup and restore
    security    - fail2ban intrusion protection
    dns         - ddclient dynamic DNS updates
    maintenance - watchtower updates and log rotation

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Main execution flow
    log_info "🚀 Starting VaultWarden-OCI enhanced deployment..."
    
    # Override profiles if forced
    if [[ -n "${FORCE_PROFILES:-}" ]]; then
        log_info "🔧 Using forced profiles: $FORCE_PROFILES"
        # Convert comma-separated profiles to array
        IFS=',' read -ra FORCED_PROFILE_ARRAY <<< "$FORCE_PROFILES"
        ACTIVE_PROFILES=()
        for profile in "${FORCED_PROFILE_ARRAY[@]}"; do
            ACTIVE_PROFILES+=(--profile "$profile")
        done
    fi
    
    initialize
    setup_configuration
    deploy_stack
    show_status
    
    log_success "🎉 VaultWarden-OCI startup completed successfully!"
    log_info "📋 Log file: $LOG_FILE"
    
    # Show next steps
    echo ""
    echo "🎯 Next Steps:"
    echo "1. Configure your domain DNS to point to this server"
    echo "2. Set up SMTP credentials in settings.env for email notifications"
    if [[ "${ENABLE_BACKUP:-false}" == "true" ]] && [[ -n "${BACKUP_REMOTE:-}" ]]; then
        echo "3. Configure rclone remote for backups: docker compose exec bw_backup rclone config"
    fi
    echo "4. Access your vault at: ${DOMAIN:-https://vault.yourdomain.com}"
}

# Execute main function
main "$@"
