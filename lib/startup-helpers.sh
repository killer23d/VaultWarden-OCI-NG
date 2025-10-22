#!/usr/bin/env bash
# lib/startup-helpers.sh - Modular startup functions for maintainability

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[startup-helpers.sh][INFO] $*"; }
    log_warn() { echo "[startup-helpers.sh][WARN] $*"; }
    log_error() { echo "[startup-helpers.sh][ERROR] $*" >&2; }
    log_success() { echo "[startup-helpers.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    log_header() { echo "=== $* ==="; }
fi

# Source additional required libraries
for lib in constants system; do
    if [[ -f "$LIB_DIR/${lib}.sh" ]]; then
        # shellcheck source=/dev/null
        source "$LIB_DIR/${lib}.sh"
    else
        log_warn "Optional library not found: lib/${lib}.sh"
    fi
done

# Set library-specific log prefix
_set_log_prefix "startup-helpers"

# --- P2 FIX: Progress indication functions ---

# Show progress with optional percentage
show_progress() {
    local step=$1 total=$2 description="$3"
    local show_percent="${4:-false}"

    echo "[$step/$total] $description..."
    if [[ "$show_percent" == "true" ]]; then
        local percent=$(( step * 100 / total ))
        echo "Progress: ${percent}%"
    fi
}

# Show startup phase with progress
show_startup_phase() {
    local phase="$1"
    local step="$2"
    local total="$3"

    log_header "Phase $step/$total: $phase"
}

# --- Existing startup helper functions with progress indicators ---

# Basic validation of system prerequisites
basic_validation() {
    show_startup_phase "System Validation" 1 7

    _log_section "Validating System Prerequisites"
    local errors=0

    show_progress 1 4 "Checking Docker availability"
    # Check Docker daemon
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker command not found."
        ((errors++))
    elif ! timeout 10 docker info >/dev/null 2>&1; then
        log_error "Docker daemon not running or not accessible."
        ((errors++))
    else
        log_success "Docker daemon available and running."
    fi

    show_progress 2 4 "Checking Docker Compose plugin"
    # Check Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose plugin not available."
        ((errors++))
    else
        log_success "Docker Compose plugin available."
    fi

    show_progress 3 4 "Verifying essential files"
    # Check essential files
    local essential_files=("$COMPOSE_FILE" ".env")
    for file in "${essential_files[@]}"; do
        if [[ ! -f "$PROJECT_ROOT/$file" ]]; then
            log_error "Essential file not found: $file"
            ((errors++))
        fi
    done

    show_progress 4 4 "Checking SOPS environment"
    # Check SOPS availability
    if ! command -v sops >/dev/null 2>&1; then
        log_error "SOPS command not found. Cannot decrypt secrets."
        ((errors++))
    elif ! command -v age >/dev/null 2>&1; then
        log_error "Age command not found. Cannot decrypt secrets."
        ((errors++))
    else
        _log_debug "SOPS and Age available for secret decryption."
    fi

    if [[ $errors -eq 0 ]]; then
        log_success "Basic validation completed successfully."
        return 0
    else
        log_error "Basic validation failed with $errors error(s)."
        return 1
    fi
}

# Ensure log directories exist with proper permissions
ensure_log_directories() {
    show_startup_phase "Log Directory Setup" 2 7

    _log_section "Ensuring Log Directories"

    # Get PROJECT_STATE_DIR from config (should be loaded by now)
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}"
    local log_dirs=(
        "$state_dir/logs/caddy"
        "$state_dir/logs/fail2ban" 
        "$state_dir/logs/system"
    )

    show_progress 1 2 "Creating log directories"

    local errors=0
    for log_dir in "${log_dirs[@]}"; do
        if [[ ! -d "$log_dir" ]]; then
            log_info "Creating log directory: $log_dir"
            if ! mkdir -p "$log_dir"; then
                log_error "Failed to create log directory: $log_dir"
                ((errors++))
            fi
        else
            _log_debug "Log directory exists: $log_dir"
        fi
    done

    show_progress 2 2 "Setting directory permissions"

    # Set appropriate permissions
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            chmod 755 "$log_dir" || {
                log_warn "Failed to set permissions on: $log_dir"
            }
        fi
    done

    if [[ $errors -eq 0 ]]; then
        log_success "Log directories ensured successfully."
        return 0
    else
        log_error "Failed to ensure some log directories."
        return 1
    fi
}

# Prepare Docker secrets from SOPS-encrypted sources
prepare_docker_secrets() {
    show_startup_phase "Secret Preparation" 3 7

    _log_section "Preparing Docker Secrets"

    local secrets_dir="$PROJECT_ROOT/$DOCKER_SECRETS_DIR"
    local sops_secrets_file="$PROJECT_ROOT/$SECRETS_FILE"

    show_progress 1 4 "Setting up secrets directory"

    # Clean and create secrets directory
    if [[ -d "$secrets_dir" ]]; then
        log_info "Cleaning existing Docker secrets directory..."
        rm -rf "$secrets_dir" || {
            log_error "Failed to clean secrets directory: $secrets_dir"
            return 1
        }
    fi

    mkdir -p "$secrets_dir" || {
        log_error "Failed to create secrets directory: $secrets_dir"
        return 1
    }
    chmod 700 "$secrets_dir"

    show_progress 2 4 "Verifying SOPS secrets file"

    # Check if secrets file exists
    if [[ ! -f "$sops_secrets_file" ]]; then
        log_error "SOPS secrets file not found: $sops_secrets_file"
        log_info "Run './tools/edit-secrets.sh' to create and configure secrets."
        return 1
    fi

    show_progress 3 4 "Decrypting secrets"

    # Decrypt and extract individual secrets
    log_info "Decrypting secrets using SOPS..."

    local secret_names=("admin_token" "smtp_password" "backup_passphrase" "push_installation_key" "cloudflare_api_token")
    local extracted_count=0

    for secret_name in "${secret_names[@]}"; do
        local secret_file="$secrets_dir/$secret_name"

        # Extract secret value using sops
        if sops -d --extract ".["$secret_name"]" "$sops_secrets_file" > "$secret_file" 2>/dev/null; then
            chmod 600 "$secret_file"
            _log_debug "Extracted secret: $secret_name"
            ((extracted_count++))
        else
            log_warn "Failed to extract secret: $secret_name (may not be configured)"
            # Create empty file to prevent Docker errors
            touch "$secret_file"
            chmod 600 "$secret_file"
        fi
    done

    show_progress 4 4 "Validating extracted secrets"

    log_success "Prepared Docker secrets ($extracted_count/$((${#secret_names[@]})) secrets extracted)."

    # Warn about critical missing secrets
    if [[ ! -s "$secrets_dir/admin_token" ]]; then
        log_warn "Admin token appears to be empty. Admin panel access may not work."
    fi

    return 0
}

# Start Docker Compose services
start_services() {
    show_startup_phase "Service Startup" 4 7

    _log_section "Starting Docker Compose Services"

    local compose_file="$PROJECT_ROOT/$COMPOSE_FILE"

    show_progress 1 3 "Validating compose configuration"

    # Validate compose file syntax
    if ! docker compose -f "$compose_file" config --quiet >/dev/null 2>&1; then
        log_error "Docker Compose configuration is invalid."
        log_info "Run 'docker compose -f "$compose_file" config' to see errors."
        return 1
    fi

    show_progress 2 3 "Starting services with docker compose up"

    log_info "Starting services using Docker Compose..."
    log_info "Compose file: $compose_file"

    # Start services in detached mode
    if (cd "$PROJECT_ROOT" && docker compose -f "$compose_file" up -d); then
        log_success "Docker Compose services started successfully."
    else
        log_error "Failed to start Docker Compose services."
        return 1
    fi

    show_progress 3 3 "Waiting for services to initialize"

    # Brief wait for services to initialize
    log_info "Waiting for services to initialize..."
    sleep 5

    # Check if core services are running
    local core_services=("vaultwarden" "caddy")
    local running_services=0

    for service in "${core_services[@]}"; do
        if docker compose -f "$compose_file" ps --services --filter "status=running" | grep -q "^${service}$"; then
            _log_debug "Service running: $service"
            ((running_services++))
        else
            log_warn "Service not running: $service"
        fi
    done

    if [[ $running_services -eq ${#core_services[@]} ]]; then
        log_success "All core services are running."
    else
        log_warn "$running_services/${#core_services[@]} core services running. Check service logs if needed."
    fi

    return 0
}

# Post-startup health check
post_startup_health_check() {
    show_startup_phase "Health Validation" 5 7

    _log_section "Post-Startup Health Check"

    if [[ "$SKIP_HEALTH" == "true" ]]; then
        log_info "Skipping health check as requested."
        return 0
    fi

    show_progress 1 3 "Checking if health check tool is available"

    local health_script="$PROJECT_ROOT/tools/check-health.sh"

    if [[ ! -x "$health_script" ]]; then
        log_warn "Health check script not found or not executable: $health_script"
        log_info "Performing basic service status check instead..."

        # Basic check using docker compose
        if docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps | grep -q "Up"; then
            log_success "Basic health check: Services appear to be running."
        else
            log_error "Basic health check: No services appear to be running."
            return 1
        fi
        return 0
    fi

    show_progress 2 3 "Running comprehensive health check"

    # Run health check with timeout
    log_info "Running comprehensive health check..."
    if timeout 60 "$health_script" --quick >/dev/null 2>&1; then
        log_success "Health check passed."
        return 0
    else
        log_warn "Health check failed or timed out."
        log_info "Services may still be initializing. Check logs if issues persist."

        show_progress 3 3 "Displaying service status for troubleshooting"

        # Show service status for troubleshooting
        log_info "Current service status:"
        docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps || true

        return 1
    fi
}

# Additional helper function for service management
restart_service() {
    local service_name="$1"
    local compose_file="$PROJECT_ROOT/$COMPOSE_FILE"

    log_info "Restarting service: $service_name"

    if docker compose -f "$compose_file" restart "$service_name"; then
        log_success "Service restarted: $service_name"
        return 0
    else
        log_error "Failed to restart service: $service_name"
        return 1
    fi
}

# Check if a service is running
is_service_running() {
    local service_name="$1"
    local compose_file="$PROJECT_ROOT/$COMPOSE_FILE"

    docker compose -f "$compose_file" ps --services --filter "status=running" | grep -q "^${service_name}$"
}

# Display startup summary
show_startup_summary() {
    show_startup_phase "Startup Summary" 7 7

    _log_section "VaultWarden Stack Status"

    local compose_file="$PROJECT_ROOT/$COMPOSE_FILE"

    show_progress 1 1 "Generating status report"

    # Get domain from config for access URL
    local domain="${DOMAIN:-localhost}"
    local clean_domain="${domain#http://}"
    clean_domain="${clean_domain#https://}"
    clean_domain="${clean_domain%/}"

    log_info "Service Status:"
    docker compose -f "$compose_file" ps 2>/dev/null || log_warn "Could not retrieve service status."

    echo
    log_info "Access Information:"
    log_info "  Web Interface: https://$clean_domain"
    log_info "  Admin Panel: https://$clean_domain/admin"

    echo
    log_info "Useful Commands:"
    log_info "  Check logs: docker compose logs -f [service_name]"
    log_info "  Health check: ./tools/check-health.sh"
    log_info "  Stop services: ./startup.sh --down"
}

# --- Script Execution ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     log_warn "lib/startup-helpers.sh is a library and should be sourced, not executed directly."
     log_info "Available functions:"
     log_info "  - basic_validation"
     log_info "  - ensure_log_directories" 
     log_info "  - prepare_docker_secrets"
     log_info "  - start_services"
     log_info "  - post_startup_health_check"
     log_info "  - show_startup_summary"
     log_info "  - restart_service <service_name>"
     log_info "  - is_service_running <service_name>"
else
      _log_debug "lib/startup-helpers.sh loaded successfully as a library."
fi
