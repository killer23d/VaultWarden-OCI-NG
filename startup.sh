#!/usr/bin/env bash
# startup.sh -- Modular startup script for VaultWarden-OCI

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
# MAIN FUNCTIONS
# ================================

# Initialize environment
initialize() {
    log_info "Initializing VaultWarden-OCI startup..."
    
    # Validate system requirements
    validate_system_requirements
    
    # Validate project structure
    validate_project_structure
    
    log_success "Initialization complete"
}

# Setup configuration
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
    
    # Generate Fail2ban configuration
    generate_fail2ban_config "$env_file"
    
    # Export env file path for Docker Compose
    export COMPOSE_ENV_FILE="$env_file"
    
    log_success "Configuration setup complete"
}

# Deploy stack
deploy_stack() {
    log_info "Deploying container stack..."
    
    # Start the stack
    start_stack "$COMPOSE_ENV_FILE"
    
    # Wait for critical services to be healthy
    local critical_services=("vaultwarden" "bw_mariadb" "bw_redis")
    
    for service in "${critical_services[@]}"; do
        if wait_for_service "$service" 120 10; then
            log_success "Service $service is ready"
        else
            log_warning "Service $service may not be fully ready"
        fi
    done
    
    # Perform health check
    if perform_health_check; then
        log_success "All services are healthy"
    else
        log_warning "Some services may have issues"
    fi
    
    log_success "Stack deployment complete"
}

# Display status
show_status() {
    log_info "VaultWarden-OCI Status:"
    echo "========================================"
    
    # Load config for domain info
    if [[ -f "$COMPOSE_ENV_FILE" ]]; then
        set -a
        source "$COMPOSE_ENV_FILE"
        set +a
        
        echo "Domain: ${APP_DOMAIN:-'Not configured'}"
        echo "URL: ${DOMAIN:-'Not configured'}"
    fi
    
    echo "Services:"
    docker compose ps
    
    echo "========================================"
    log_info "Run './monitor.sh' for detailed monitoring"
    log_info "Run './diagnose.sh' if you encounter issues"
}

# ================================
# MAIN EXECUTION
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
            --help|-h)
                cat <<EOF
VaultWarden-OCI Startup Script

Usage: $0 [OPTIONS]

Options:
    --force-ip-update    Force update of Cloudflare IP ranges
    --debug             Enable debug logging
    --help, -h          Show this help message

Environment Variables:
    OCI_SECRET_OCID     Use OCI Vault for configuration
    DEBUG               Enable debug logging
    LOG_FILE            Custom log file path

Examples:
    $0                           # Normal startup
    $0 --force-ip-update         # Startup with IP update
    OCI_SECRET_OCID=ocid1... $0  # Use OCI Vault
    DEBUG=true $0                # Debug mode

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Main execution flow
    log_info "Starting VaultWarden-OCI deployment process..."
    
    initialize
    setup_configuration
    deploy_stack
    show_status
    
    log_success "VaultWarden-OCI startup completed successfully!"
    log_info "Log file: $LOG_FILE"
}

# Execute main function
main "$@"
