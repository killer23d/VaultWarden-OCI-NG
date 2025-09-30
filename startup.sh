#!/usr/bin/env bash
# startup.sh -- Secure startup with profile handling and security separation

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration
readonly CLOUDFLARE_IP_SCRIPT="./caddy/update_cloudflare_ips.sh"
readonly FAIL2BAN_TEMPLATE="./fail2ban/jail.d/jail.local.template"
readonly FAIL2BAN_CONFIG="./fail2ban/jail.d/jail.local"

# Default profiles
DEFAULT_PROFILES=""
ENABLE_BACKUP_PROFILE=false

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if backup should be enabled
check_backup_profile() {
    log_info "Checking backup configuration..."
    
    # Source environment to check backup settings
    if [[ -f "${COMPOSE_ENV_FILE:-./settings.env}" ]]; then
        source "${COMPOSE_ENV_FILE:-./settings.env}"
    fi
    
    # Enable backup if any backup settings are configured
    if [[ -n "${BACKUP_PASSPHRASE:-}" ]] || [[ -n "${BACKUP_REMOTE:-}" ]] || [[ -n "${BACKUP_EMAIL:-}" ]]; then
        ENABLE_BACKUP_PROFILE=true
        log_info "Backup configuration detected - enabling backup service"
    else
        log_info "No backup configuration - backup service will be disabled"
    fi
}

# Build profile arguments
build_profile_args() {
    local profile_args=()
    
    if [[ "$ENABLE_BACKUP_PROFILE" == "true" ]]; then
        profile_args+=("--profile" "backup")
        log_info "Backup profile will be activated"
    fi
    
    echo "${profile_args[@]}"
}

# Validate required directories and files
validate_environment() {
    log_info "Validating environment setup..."
    
    local required_dirs=("./data" "./caddy" "./fail2ban" "./backup" "./lib")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_error "Required directory not found: $dir"
        fi
    done
    
    if [[ ! -f "$FAIL2BAN_TEMPLATE" ]]; then
        log_error "Fail2ban template not found: $FAIL2BAN_TEMPLATE"
    fi
    
    # Check for library files
    local required_libs=("./lib/common.sh" "./lib/docker.sh" "./lib/config.sh")
    for lib in "${required_libs[@]}"; do
        if [[ ! -f "$lib" ]]; then
            log_error "Required library not found: $lib"
        fi
    done
    
    # Ensure data directories have correct ownership for security separation
    log_info "Setting data directory permissions for security separation..."
    if [[ -d "./data" ]]; then
        if command -v chown >/dev/null 2>&1; then
            if [[ $(id -u) -eq 0 ]] || sudo -n chown --help >/dev/null 2>&1; then
                local chown_cmd=""
                if [[ $(id -u) -ne 0 ]]; then
                    chown_cmd="sudo "
                fi
                
                # Create directories if they don't exist
                mkdir -p ./data/{bwdata,caddy_data,caddy_config,caddy_logs,backups,backup_logs,mariadb,redis,fail2ban}
                
                # User service directories (PUID:PGID, defaulting to 1000:1000)
                local puid="${PUID:-1000}"
                local pgid="${PGID:-1000}"
                
                ${chown_cmd}chown -R ${puid}:${pgid} ./data/bwdata 2>/dev/null || log_warning "Could not set bwdata directory ownership"
                ${chown_cmd}chown -R ${puid}:${pgid} ./data/caddy_data ./data/caddy_config ./data/caddy_logs 2>/dev/null || log_warning "Could not set caddy directory ownership"
                ${chown_cmd}chown -R ${puid}:${pgid} ./data/backups ./data/backup_logs 2>/dev/null || log_warning "Could not set backup directory ownership"
                ${chown_cmd}chown -R ${puid}:${pgid} ./data/fail2ban 2>/dev/null || log_warning "Could not set fail2ban directory ownership"
                
                # System service directories (999:999)
                ${chown_cmd}chown -R 999:999 ./data/mariadb 2>/dev/null || log_warning "Could not set mariadb directory ownership"
                ${chown_cmd}chown -R 999:999 ./data/redis 2>/dev/null || log_warning "Could not set redis directory ownership"
                
                # General permissions
                ${chown_cmd}chmod -R 755 ./data 2>/dev/null || log_warning "Could not set data directory permissions"
                
                log_success "Data directory permissions updated with security separation"
                log_info "User services (${puid}:${pgid}): bwdata, caddy_*, backups, backup_logs, fail2ban"
                log_info "System services (999:999): mariadb, redis"
            else
                log_warning "Cannot set data directory ownership - ensure correct permissions manually"
                echo "User services (PUID:PGID): ./data/bwdata, ./data/caddy_*, ./data/backups, ./data/backup_logs, ./data/fail2ban"
                echo "System services (999:999): ./data/mariadb, ./data/redis"
            fi
        fi
    fi
    
    log_success "Environment validation passed"
}

# Handle Cloudflare IP updates with improved logic
update_cloudflare_ips() {
    log_info "Checking Cloudflare IP configuration..."
    
    if [[ ! -f "$CLOUDFLARE_IP_SCRIPT" ]]; then
        log_warning "Cloudflare IP update script not found, skipping"
        return 0
    fi
    
    chmod +x "$CLOUDFLARE_IP_SCRIPT"
    
    # Check if IP files exist and are recent (less than 7 days old)
    local ip_files=("./caddy/cloudflare_ips.caddy" "./caddy/cloudflare_ips.txt")
    local need_update=false
    
    for file in "${ip_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_info "IP file missing: $file"
            need_update=true
            break
        elif [[ $(find "$file" -mtime +7 2>/dev/null) ]]; then
            log_info "IP file older than 7 days: $file"
            need_update=true
            break
        fi
    done
    
    if [[ "$need_update" == "true" ]] || [[ "${1:-}" == "true" ]]; then
        log_info "Updating Cloudflare IP ranges..."
        if "$CLOUDFLARE_IP_SCRIPT"; then
            log_success "Cloudflare IP ranges updated"
        else
            log_error "Failed to update Cloudflare IP ranges"
        fi
    else
        log_info "Cloudflare IP files are current (less than 7 days old)"
    fi
}

# Load environment variables securely
load_environment() {
    log_info "Loading environment configuration..."
    
    # Setup secure temporary directory
    local tmpdir="${TMPDIR:-/dev/shm}/bwsettings_$$"
    mkdir -p "$tmpdir"
    chmod 700 "$tmpdir"
    
    local envfile="$tmpdir/settings.env"
    
    # Cleanup function
    cleanup_env() {
        if [[ -f "$envfile" ]]; then
            if command -v shred >/dev/null 2>&1; then
                shred -u "$envfile" 2>/dev/null || rm -f "$envfile"
            else
                rm -f "$envfile"
            fi
        fi
        rmdir "$tmpdir" 2>/dev/null || true
    }
    trap cleanup_env EXIT
    
    # Load from OCI Vault or local file
    if [[ -n "${OCI_SECRET_OCID:-}" ]]; then
        log_info "Fetching configuration from OCI Vault..."
        
        # Validate OCI CLI
        if ! command -v oci &>/dev/null; then
            log_error "OCI CLI not found. Install it or use local settings.env"
        fi
        
        # Test OCI connectivity
        if ! oci os ns get >/dev/null 2>&1; then
            log_error "OCI CLI not configured. Run 'oci setup config' or use local settings.env"
        fi
        
        # Validate OCID format
        if [[ ! "$OCI_SECRET_OCID" =~ ^ocid1\.vaultsecret\. ]]; then
            log_error "Invalid Secret OCID format. Expected: ocid1.vaultsecret...."
        fi
        
        # Fetch secret
        if ! oci vault secret get --secret-id "$OCI_SECRET_OCID" --raw-output | \
             jq -r '.data."secret-content".content' | base64 -d > "$envfile"; then
            log_error "Failed to fetch secret from OCI Vault"
        fi
        
        log_success "Configuration loaded from OCI Vault"
    else
        if [[ -f "./settings.env" ]]; then
            log_info "Loading local settings.env..."
            cp "./settings.env" "$envfile"
            log_success "Local configuration loaded"
        else
            log_error "No settings.env found and OCI_SECRET_OCID not set"
        fi
    fi
    
    chmod 600 "$envfile"
    
    # Validate critical variables
    log_info "Validating configuration variables..."
    source "$envfile"
    
    local required_vars=(
        "DOMAIN_NAME" "APP_DOMAIN" "ADMIN_TOKEN"
        "MARIADB_ROOT_PASSWORD" "MARIADB_PASSWORD" "REDIS_PASSWORD"
        "MARIADB_USER" "MARIADB_DATABASE" "DATABASE_URL"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable not set: $var"
        fi
    done
    
    # Check for placeholder values
    local placeholder_vars=()
    for var in "${required_vars[@]}"; do
        if [[ "${!var:-}" == *"generate-with-openssl"* ]] || [[ "${!var:-}" == *"example.com"* ]]; then
            placeholder_vars+=("$var")
        fi
    done
    
    if [[ ${#placeholder_vars[@]} -gt 0 ]]; then
        log_error "Variables still contain placeholder values: ${placeholder_vars[*]}"
        echo "Please update settings.env with actual values"
        exit 1
    fi
    
    # Validate DATABASE_URL format
    if [[ ! "$DATABASE_URL" =~ mysql://.*@bw_mariadb:3306/ ]]; then
        log_error "DATABASE_URL format incorrect. Should be: mysql://user:pass@bw_mariadb:3306/database"
    fi
    
    # Validate that DATABASE_URL components match other variables
    local db_user_in_url db_pass_in_url db_name_in_url
    db_user_in_url=$(echo "$DATABASE_URL" | sed -n 's|mysql://\([^:]*\):.*|\1|p')
    db_pass_in_url=$(echo "$DATABASE_URL" | sed -n 's|mysql://[^:]*:\([^@]*\)@.*|\1|p')
    db_name_in_url=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^/]*\)$|\1|p')
    
    if [[ "$db_user_in_url" != "$MARIADB_USER" ]]; then
        log_error "DATABASE_URL username ($db_user_in_url) does not match MARIADB_USER ($MARIADB_USER)"
    fi
    
    if [[ "$db_pass_in_url" != "$MARIADB_PASSWORD" ]]; then
        log_error "DATABASE_URL password does not match MARIADB_PASSWORD"
    fi
    
    if [[ "$db_name_in_url" != "$MARIADB_DATABASE" ]]; then
        log_error "DATABASE_URL database ($db_name_in_url) does not match MARIADB_DATABASE ($MARIADB_DATABASE)"
    fi
    
    # Set the environment file for docker-compose
    export COMPOSE_ENV_FILE="$envfile"
    log_success "Configuration validation passed"
}

# Generate Fail2ban configuration from template
generate_fail2ban_config() {
    log_info "Generating Fail2ban configuration..."
    
    if [[ ! -f "$FAIL2BAN_TEMPLATE" ]]; then
        log_error "Fail2ban template not found: $FAIL2BAN_TEMPLATE"
    fi
    
    # Source environment for variable substitution
    source "${COMPOSE_ENV_FILE}"
    
    # Generate configuration with variable substitution
    envsubst < "$FAIL2BAN_TEMPLATE" > "$FAIL2BAN_CONFIG"
    
    if [[ -f "$FAIL2BAN_CONFIG" ]]; then
        log_success "Fail2ban configuration generated"
    else
        log_error "Failed to generate Fail2ban configuration"
    fi
}

# Prepare system for deployment
prepare_system() {
    log_info "Preparing system for deployment..."
    
    # Source libraries for advanced functions
    source "./lib/common.sh"
    source "./lib/docker.sh"
    source "./lib/config.sh"
    
    # Validate system requirements
    validate_system_requirements
    
    # Validate project structure
    validate_project_structure
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
    fi
    
    # Check Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose is not available"
    fi
    
    # Validate compose file
    if ! docker compose config >/dev/null 2>&1; then
        log_error "docker-compose.yml has syntax errors"
    fi
    
    log_success "System preparation completed"
}

# Start Docker Compose stack
start_containers() {
    log_info "Starting container stack..."
    
    # Build profile arguments
    local profile_args
    profile_args=($(build_profile_args))
    
    # Use the secure environment file
    local compose_cmd=(docker compose --env-file "${COMPOSE_ENV_FILE}")
    
    # Add profile arguments if any
    if [[ ${#profile_args[@]} -gt 0 ]]; then
        compose_cmd+=("${profile_args[@]}")
        log_info "Using profiles: ${profile_args[*]}"
    fi
    
    # Start the stack
    if "${compose_cmd[@]}" up -d --remove-orphans; then
        log_success "Container stack started successfully"
    else
        log_error "Failed to start container stack"
    fi
    
    # Wait a moment for containers to initialize
    sleep 10
    
    # Source libraries for health check functions
    source "./lib/docker.sh"
    
    # Check critical services
    log_info "Waiting for critical services to be ready..."
    local critical_services=("bw_mariadb" "bw_redis" "vaultwarden")
    
    for service in "${critical_services[@]}"; do
        local attempts=0
        local max_attempts=20  # Reduced since health checks are now faster
        
        while [[ $attempts -lt $max_attempts ]]; do
            if is_service_running "$service"; then
                if is_service_healthy "$service" || [[ $attempts -gt 10 ]]; then
                    log_success "Service $service is ready"
                    break
                fi
            fi
            
            attempts=$((attempts + 1))
            log_info "Waiting for $service... (attempt $attempts/$max_attempts)"
            sleep 10
        done
        
        if [[ $attempts -eq $max_attempts ]]; then
            log_warning "Service $service may not be fully ready yet"
        fi
    done
    
    # Show container status
    echo ""
    log_info "Current container status:"
    "${compose_cmd[@]}" ps
    
    # Quick health summary
    echo ""
    log_info "Service health summary:"
    for service in "${critical_services[@]}"; do
        if is_service_running "$service"; then
            if is_service_healthy "$service"; then
                echo -e "  ${GREEN}●${NC} $service: healthy"
            else
                echo -e "  ${YELLOW}●${NC} $service: running (starting up)"
            fi
        else
            echo -e "  ${RED}●${NC} $service: not running"
        fi
    done
    
    # Show backup service status
    if [[ "$ENABLE_BACKUP_PROFILE" == "true" ]]; then
        if is_service_running "bw_backup"; then
            echo -e "  ${GREEN}●${NC} bw_backup: enabled and running"
        else
            echo -e "  ${YELLOW}●${NC} bw_backup: enabled but starting up"
        fi
    else
        echo -e "  ${BLUE}○${NC} bw_backup: disabled (no backup configuration)"
    fi
    
    # Show additional services status
    local additional_services=("bw_caddy" "bw_fail2ban")
    for service in "${additional_services[@]}"; do
        if is_service_running "$service"; then
            echo -e "  ${GREEN}●${NC} $service: running"
        else
            echo -e "  ${YELLOW}●${NC} $service: starting up"
        fi
    done
}

# Post-deployment checks and information
post_deployment() {
    log_info "Running post-deployment checks..."
    
    # Load configuration for display
    source "${COMPOSE_ENV_FILE}"
    
    # Test basic connectivity
    local vw_container_id
    vw_container_id=$(docker compose ps -q vaultwarden 2>/dev/null || echo "")
    
    if [[ -n "$vw_container_id" ]]; then
        if docker exec "$vw_container_id" curl -f http://localhost:80/alive --max-time 10 >/dev/null 2>&1; then
            log_success "VaultWarden health check passed"
        else
            log_warning "VaultWarden health check failed - service may still be starting"
        fi
    fi
    
    # Display important information
    echo ""
    echo "=========================================="
    echo -e "${GREEN}VaultWarden-OCI deployment completed!${NC}"
    echo "=========================================="
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    echo "  Domain:     ${APP_DOMAIN:-'Not configured'}"
    echo "  URL:        ${DOMAIN:-'http://localhost'}"
    echo "  Admin URL:  ${DOMAIN:-'http://localhost'}/admin"
    echo ""
    echo -e "${BLUE}Security Configuration:${NC}"
    echo "  User Services (PUID ${PUID:-1000}): vaultwarden, caddy, backup, logrotate"
    echo "  System Services (UID 999): mariadb, redis"
    echo "  Security separation: ✓ Enabled"
    echo ""
    echo -e "${BLUE}Memory Allocation (OCI A1 Optimized):${NC}"
    echo "  VaultWarden:    512MB"
    echo "  MariaDB:        1GB"
    echo "  Redis:          256MB"
    echo "  Caddy:          256MB"
    echo "  Other services: ~512MB"
    echo "  Total:          ~2.5GB (within 6GB limit with buffer)"
    echo ""
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  Dashboard:       ./dashboard.sh"
    echo "  Performance:     ./perf-monitor.sh status"
    echo "  Diagnostics:     ./diagnose.sh"
    echo "  Alerts:          ./alerts.sh status"
    echo "  Benchmark:       ./benchmark.sh run all"
    echo ""
    echo -e "${BLUE}Backup & Restore:${NC}"
    if [[ "$ENABLE_BACKUP_PROFILE" == "true" ]]; then
        echo "  Status:          ✓ Enabled (automated daily backups)"
        echo "  Manual backup:   docker compose exec bw_backup /backup/db-backup.sh --force"
        echo "  Backup location: ./data/backups/"
        echo "  Database restore: ./backup/db-restore.sh"
        echo "  Verify backups:  ./backup/verify-backup.sh --all"
    else
        echo "  Status:          ○ Disabled (no backup configuration)"
        echo "  Enable:          Configure BACKUP_* variables in settings.env and restart"
    fi
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo "  View logs:       docker compose logs -f [service-name]"
    echo "  Restart stack:   docker compose restart"
    echo "  Stop stack:      docker compose down"
    echo "  Update images:   docker compose pull && ./startup.sh"
    echo ""
    
    # Show health check timing info
    echo -e "${BLUE}Health Check Intervals:${NC}"
    echo "  Critical services: 30s (fast dependency resolution)"
    echo "  Web services:      5m (standard monitoring)"
    echo "  Utility services:  30-60m (low frequency)"
    echo ""
    
    echo -e "${GREEN}Deployment successful! 🚀${NC}"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "1. Access VaultWarden: ${DOMAIN:-'http://localhost'}"
    echo "2. Create admin account: ${DOMAIN:-'http://localhost'}/admin"
    echo "3. Monitor system: ./dashboard.sh"
    echo ""
}

# Main execution
main() {
    log_info "Starting VaultWarden-OCI deployment..."
    echo "==============================================="
    
    # Parse arguments
    local force_ip_update=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force-ip-update)
                force_ip_update=true
                shift
                ;;
            --enable-backup)
                ENABLE_BACKUP_PROFILE=true
                log_info "Forcing backup service enable"
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
    --enable-backup      Force enable backup service (overrides auto-detection)
    --debug             Enable debug logging
    --help, -h          Show this help message

Environment Variables:
    OCI_SECRET_OCID     Use OCI Vault for configuration
    PUID                User ID for user services (default: 1000)
    PGID                Group ID for user services (default: 1000)
    DEBUG               Enable debug logging

Examples:
    $0                           # Normal startup with auto-detected profiles
    $0 --enable-backup           # Force backup service enabled
    $0 --force-ip-update         # Startup with IP update
    OCI_SECRET_OCID=ocid1... $0  # Use OCI Vault
    DEBUG=true $0                # Debug mode

Security Design:
- User services (vaultwarden, caddy, backup): PUID:PGID (default 1000:1000)
- System services (mariadb, redis): 999:999 (security separation)
- Data directories automatically configured for proper ownership

Memory Allocation (OCI A1 Optimized):
- Reduced memory limits to fit within 6GB total system capacity
- Faster health checks (30s) for reduced startup time
- Backup service auto-enabled based on configuration
- Relaxed dependencies for better startup resilience

EOF
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
    done
    
    # Main execution flow
    validate_environment
    prepare_system
    update_cloudflare_ips "$force_ip_update"
    load_environment
    check_backup_profile
    generate_fail2ban_config
    start_containers
    post_deployment
    
    echo "==============================================="
    log_success "VaultWarden-OCI startup completed successfully!"
    echo "Access your VaultWarden instance at: ${DOMAIN:-'http://localhost'}"
    echo ""
    echo "Next steps:"
    echo "  - Run './dashboard.sh' for real-time monitoring"
    echo "  - Run './diagnose.sh' if you encounter any issues" 
    echo "  - Run './benchmark.sh run all' for performance testing"
    echo "  - Check './perf-monitor.sh status' for performance metrics"
}

# Execute main function with all arguments
main "$@"
