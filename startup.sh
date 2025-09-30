#!/usr/bin/env bash
# startup.sh -- Secure startup with standardized environment variable handling
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

# Validate required directories and files
validate_environment() {
    log_info "Validating environment setup..."
    
    local required_dirs=("./data" "./caddy" "./fail2ban" "./backup")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_error "Required directory not found: $dir"
        fi
    done
    
    if [[ ! -f "$FAIL2BAN_TEMPLATE" ]]; then
        log_error "Fail2ban template not found: $FAIL2BAN_TEMPLATE"
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
    
    if [[ "$need_update" == "true" ]] || [[ "${1:-}" == "--force-ip-update" ]]; then
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
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable not set: $var"
        fi
    done
    
    # Set the environment file for docker-compose
    export COMPOSE_ENV_FILE="$envfile"
    log_success "Configuration validation passed"
}

# Generate Fail2ban configuration from template
generate_fail2ban_config() {
    log_info "Generating Fail2ban configuration..."
    
    if
