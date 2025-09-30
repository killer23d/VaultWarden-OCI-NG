#!/usr/bin/env bash
# lib/common.sh - Shared functions and constants for VaultWarden-OCI scripts

# Prevent multiple sourcing
[[ "${_COMMON_SH_LOADED:-}" == "true" ]] && return 0
declare -r _COMMON_SH_LOADED=true

# ================================
# CONSTANTS AND CONFIGURATION
# ================================

# Color constants
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r BOLD='\033[1m'
declare -r NC='\033[0m'

# Project constants
declare -r PROJECT_NAME="VaultWarden-OCI"
declare -r COMPOSE_FILE="docker-compose.yml"
declare -r SETTINGS_FILE="settings.env"
declare -r SETTINGS_EXAMPLE="settings.env.example"

# Container services array
declare -ra SERVICES=(
    "vaultwarden"
    "bw_mariadb" 
    "bw_redis"
    "bw_caddy"
    "bw_fail2ban"
    "bw_ddclient"
    "bw_backup"
    "bw_watchtower"
)

# Required directories
declare -ra REQUIRED_DIRS=(
    "./data"
    "./caddy"
    "./fail2ban" 
    "./backup"
)

# Critical files
declare -ra CRITICAL_FILES=(
    "./docker-compose.yml"
    "./caddy/Caddyfile"
    "./fail2ban/jail.d/jail.local.template"
)

# ================================
# LOGGING FUNCTIONS
# ================================

# Log with timestamp
log_with_timestamp() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}"
}

# Info logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
    log_with_timestamp "INFO" "$1" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
}

# Success logging
log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
    log_with_timestamp "SUCCESS" "$1" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
}

# Warning logging
log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
    log_with_timestamp "WARNING" "$1" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
}

# Error logging and exit
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log_with_timestamp "ERROR" "$1" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
    exit "${2:-1}"
}

# Debug logging (only if DEBUG is set)
log_debug() {
    [[ "${DEBUG:-}" == "true" ]] || return 0
    echo -e "${CYAN}[DEBUG]${NC} $1" >&2
    log_with_timestamp "DEBUG" "$1" >> "${LOG_FILE:-/dev/null}" 2>/dev/null || true
}

# ================================
# UTILITY FUNCTIONS
# ================================

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root
is_root() {
    [[ $EUID -eq 0 ]]
}

# Check if directory is writable
is_writable() {
    [[ -w "$1" ]]
}

# Get script directory
get_script_dir() {
    cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd
}

# Get project root directory
get_project_root() {
    local script_dir
    script_dir="$(get_script_dir)"
    if [[ -f "$script_dir/../$COMPOSE_FILE" ]]; then
        echo "$(cd "$script_dir/.." && pwd)"
    elif [[ -f "$script_dir/$COMPOSE_FILE" ]]; then
        echo "$script_dir"
    else
        log_error "Cannot find project root directory"
    fi
}

# Cleanup function for trap
cleanup_on_exit() {
    local exit_code=$?
    [[ "${CLEANUP_FUNCTIONS:-}" ]] || return $exit_code
    
    log_debug "Running cleanup functions..."
    for cleanup_func in "${CLEANUP_FUNCTIONS[@]}"; do
        if declare -f "$cleanup_func" >/dev/null; then
            $cleanup_func || log_warning "Cleanup function '$cleanup_func' failed"
        fi
    done
    
    exit $exit_code
}

# Add cleanup function to be run on exit
add_cleanup_function() {
    CLEANUP_FUNCTIONS+=("$1")
    trap cleanup_on_exit EXIT INT TERM
}

# ================================
# VALIDATION FUNCTIONS
# ================================

# Validate system requirements
validate_system_requirements() {
    log_info "Validating system requirements..."
    
    local errors=0
    
    # Check Docker
    if ! command_exists docker; then
        log_error "Docker is not installed"
        ((errors++))
    fi
    
    # Check Docker Compose
    if ! command_exists "docker compose"; then
        log_error "Docker Compose is not installed"
        ((errors++))
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        ((errors++))
    fi
    
    # Check disk space (minimum 2GB)
    local available_space
    available_space=$(df --output=avail . | tail -1)
    if [[ $available_space -lt 2097152 ]]; then
        log_error "Insufficient disk space (need at least 2GB)"
        ((errors++))
    fi
    
    # Check memory (minimum 1GB free)
    local free_memory
    free_memory=$(free -m | awk '/^Mem:/{print $7}')
    if [[ $free_memory -lt 1024 ]]; then
        log_warning "Low memory (less than 1GB free)"
    fi
    
    if [[ $errors -gt 0 ]]; then
        log_error "System validation failed with $errors errors"
    fi
    
    log_success "System requirements validated"
}

# Validate project structure
validate_project_structure() {
    log_info "Validating project structure..."
    
    local errors=0
    
    # Check required directories
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_error "Required directory missing: $dir"
            ((errors++))
        elif [[ ! -w "$dir" ]]; then
            log_warning "Directory not writable: $dir"
        fi
    done
    
    # Check critical files
    for file in "${CRITICAL_FILES[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Critical file missing: $file"
            ((errors++))
        fi
    done
    
    if [[ $errors -gt 0 ]]; then
        log_error "Project structure validation failed with $errors errors"
    fi
    
    log_success "Project structure validated"
}

# ================================
# DOCKER FUNCTIONS
# ================================

# Get container ID by service name
get_container_id() {
    local service_name="$1"
    docker compose ps -q "$service_name" 2>/dev/null || echo ""
}

# Get container status
get_container_status() {
    local container_id="$1"
    docker inspect --format='{{.State.Status}}' "$container_id" 2>/dev/null || echo "unknown"
}

# Get container health status
get_container_health() {
    local container_id="$1"
    docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-health-check{{end}}' "$container_id" 2>/dev/null || echo "unknown"
}

# Check if service is running
is_service_running() {
    local service_name="$1"
    local container_id
    container_id=$(get_container_id "$service_name")
    [[ -n "$container_id" ]] && [[ "$(get_container_status "$container_id")" == "running" ]]
}

# Check if service is healthy
is_service_healthy() {
    local service_name="$1"
    local container_id
    container_id=$(get_container_id "$service_name")
    [[ -n "$container_id" ]] && [[ "$(get_container_health "$container_id")" == "healthy" ]]
}

# Get service logs
get_service_logs() {
    local service_name="$1"
    local lines="${2:-50}"
    docker compose logs --tail "$lines" "$service_name" 2>/dev/null || echo "No logs available for $service_name"
}

# ================================
# ENVIRONMENT FUNCTIONS
# ================================

# Load environment variables from file
load_env_file() {
    local env_file="${1:-$SETTINGS_FILE}"
    
    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file not found: $env_file"
    fi
    
    log_debug "Loading environment from: $env_file"
    
    # Source the file in a subshell to avoid polluting current environment
    set -a
    source "$env_file"
    set +a
    
    log_debug "Environment loaded successfully"
}

# Validate required environment variables
validate_required_vars() {
    local required_vars=("$@")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
    fi
    
    log_success "All required environment variables are set"
}

# ================================
# SECURITY FUNCTIONS
# ================================

# Create secure temporary directory
create_secure_tmpdir() {
    local prefix="${1:-bw}"
    local tmpdir="${TMPDIR:-/dev/shm}/${prefix}_$$"
    
    mkdir -p "$tmpdir"
    chmod 700 "$tmpdir"
    
    # Add cleanup
    add_cleanup_function "rm -rf '$tmpdir'"
    
    echo "$tmpdir"
}

# Secure file removal
secure_remove() {
    local file="$1"
    
    if [[ -f "$file" ]]; then
        if command_exists shred; then
            shred -u "$file" 2>/dev/null || rm -f "$file"
        else
            rm -f "$file"
        fi
    fi
}

# Generate random password
generate_password() {
    local length="${1:-32}"
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# ================================
# CONFIGURATION FUNCTIONS
# ================================

# Check if OCI Vault is configured
is_oci_vault_configured() {
    [[ -n "${OCI_SECRET_OCID:-}" ]] && command_exists oci
}

# Fetch configuration from OCI Vault
fetch_oci_config() {
    local secret_ocid="$1"
    local output_file="$2"
    
    log_info "Fetching configuration from OCI Vault..."
    
    # Validate OCID format
    if [[ ! "$secret_ocid" =~ ^ocid1\.vaultsecret\. ]]; then
        log_error "Invalid Secret OCID format"
    fi
    
    # Test OCI CLI
    if ! oci os ns get >/dev/null 2>&1; then
        log_error "OCI CLI not configured properly"
    fi
    
    # Fetch secret
    if ! oci vault secret get --secret-id "$secret_ocid" --raw-output | \
         jq -r '.data."secret-content".content' | base64 -d > "$output_file"; then
        log_error "Failed to fetch secret from OCI Vault"
    fi
    
    chmod 600 "$output_file"
    log_success "Configuration fetched from OCI Vault"
}

# ================================
# INITIALIZATION
# ================================

# Initialize common environment
init_common() {
    # Set strict error handling
    set -euo pipefail
    
    # Initialize cleanup functions array
    CLEANUP_FUNCTIONS=()
    
    # Set up logging
    if [[ -z "${LOG_FILE:-}" ]]; then
        LOG_FILE="/tmp/${PROJECT_NAME,,}_$(date +%Y%m%d_%H%M%S).log"
    fi
    
    # Change to project directory
    local project_root
    project_root=$(get_project_root)
    cd "$project_root"
    
    log_debug "Common library initialized"
    log_debug "Project root: $project_root"
    log_debug "Log file: $LOG_FILE"
}

# Auto-initialize when sourced (unless SKIP_INIT is set)
if [[ "${SKIP_INIT:-}" != "true" ]]; then
    init_common
fi
