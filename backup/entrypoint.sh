#!/bin/bash
# entrypoint.sh - Secure initialization for backup container
# Implements best practices for rclone configuration management

set -euo pipefail

# Configuration
RCLONE_CONFIG_DIR="/home/backup/.config/rclone"
RCLONE_CONFIG_FILE="$RCLONE_CONFIG_DIR/rclone.conf"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
LOG_DIR="${LOG_DIR:-/var/log/backup}"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $*" >&2
}

# Initialize rclone configuration with security best practices
initialize_rclone_config() {
    log_info "Initializing rclone configuration..."
    
    # Ensure config directory exists with proper permissions
    if [[ ! -d "$RCLONE_CONFIG_DIR" ]]; then
        mkdir -p "$RCLONE_CONFIG_DIR"
        chmod 700 "$RCLONE_CONFIG_DIR"
        log_info "Created rclone config directory"
    fi
    
    # Create default config file if none exists
    if [[ ! -f "$RCLONE_CONFIG_FILE" ]]; then
        log_info "Creating default rclone configuration..."
        
        cat > "$RCLONE_CONFIG_FILE" << 'EOF'
# rclone configuration file
# This file is automatically created by the backup container
# 
# To configure your backup remotes, run:
#   docker compose exec bw_backup rclone config
#
# Example configurations:
#
# [b2-backup]
# type = b2
# account = your-account-id
# key = your-application-key
#
# [s3-backup] 
# type = s3
# provider = AWS
# access_key_id = your-access-key
# secret_access_key = your-secret-key
# region = us-east-1
#
# [google-drive]
# type = drive
# client_id = your-client-id
# client_secret = your-client-secret
# token = {"access_token":"..."}

EOF
        
        chmod 600 "$RCLONE_CONFIG_FILE"
        log_success "Created default rclone.conf"
    else
        log_success "rclone.conf already exists"
    fi
    
    # Validate file permissions
    local perms
    perms=$(stat -c "%a" "$RCLONE_CONFIG_FILE")
    if [[ "$perms" != "600" ]]; then
        log_info "Fixing rclone.conf permissions..."
        chmod 600 "$RCLONE_CONFIG_FILE"
    fi
    
    # Export rclone config location
    export RCLONE_CONFIG="$RCLONE_CONFIG_FILE"
}

# Validate rclone configuration
validate_rclone_config() {
    log_info "Validating rclone configuration..."
    
    # Check if we can read the config
    if ! rclone listremotes >/dev/null 2>&1; then
        log_error "Cannot read rclone configuration"
        return 1
    fi
    
    # List available remotes
    local remotes
    remotes=$(rclone listremotes 2>/dev/null || echo "")
    
    if [[ -z "$remotes" ]]; then
        log_info "No rclone remotes configured"
        log_info "To add remotes, run: docker compose exec bw_backup rclone config"
    else
        log_success "Available rclone remotes:"
        echo "$remotes" | sed 's/^/  - /'
        
        # Validate backup remote if specified
        if [[ -n "${BACKUP_REMOTE:-}" ]]; then
            if echo "$remotes" | grep -q "^${BACKUP_REMOTE}:$"; then
                log_success "Backup remote '$BACKUP_REMOTE' is configured"
                
                # Test remote connectivity
                if rclone lsd "${BACKUP_REMOTE}:" >/dev/null 2>&1; then
                    log_success "Backup remote '$BACKUP_REMOTE' is accessible"
                else
                    log_error "Backup remote '$BACKUP_REMOTE' is not accessible"
                fi
            else
                log_error "Backup remote '$BACKUP_REMOTE' is not configured"
                log_info "Available remotes: $(echo "$remotes" | tr '\n' ' ')"
            fi
        fi
    fi
}

# Initialize backup environment
initialize_backup_environment() {
    log_info "Initializing backup environment..."
    
    # Create required directories
    mkdir -p "$BACKUP_DIR" "$LOG_DIR"
    
    # Validate write permissions
    if [[ ! -w "$BACKUP_DIR" ]]; then
        log_error "Backup directory is not writable: $BACKUP_DIR"
        return 1
    fi
    
    if [[ ! -w "$LOG_DIR" ]]; then
        log_error "Log directory is not writable: $LOG_DIR"
        return 1
    fi
    
    # Test database connectivity
    if [[ -n "${MARIADB_USER:-}" ]] && [[ -n "${MARIADB_PASSWORD:-}" ]]; then
        log_info "Testing database connectivity..."
        if mysqladmin ping -h bw_mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" --silent 2>/dev/null; then
            log_success "Database connection successful"
        else
            log_error "Cannot connect to database"
            return 1
        fi
    else
        log_error "Database credentials not configured"
        return 1
    fi
    
    log_success "Backup environment initialized"
}

# Health check function
health_check() {
    local errors=0
    
    # Check if crond is running
    if ! pgrep crond >/dev/null 2>&1; then
        log_error "crond is not running"
        ((errors++))
    fi
    
    # Check backup directory
    if [[ ! -w "$BACKUP_DIR" ]]; then
        log_error "Backup directory not writable"
        ((errors++))
    fi
    
    # Check database connectivity
    if ! mysqladmin ping -h bw_mariadb -u"${MARIADB_USER:-}" -p"${MARIADB_PASSWORD:-}" --silent 2>/dev/null; then
        log_error "Database not accessible"
        ((errors++))
    fi
    
    # Check rclone config
    if [[ ! -f "$RCLONE_CONFIG_FILE" ]]; then
        log_error "rclone config file missing"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "Health check passed"
        return 0
    else
        log_error "Health check failed with $errors errors"
        return 1
    fi
}

# Main execution
main() {
    case "${1:-start}" in
        --health-check)
            health_check
            ;;
        --init-only)
            initialize_rclone_config
            initialize_backup_environment
            ;;
        --validate-config)
            initialize_rclone_config
            validate_rclone_config
            ;;
        *)
            log_info "Starting backup container..."
            
            # Initialize configuration
            initialize_rclone_config
            validate_rclone_config
            initialize_backup_environment
            
            log_success "Backup container initialization complete"
            
            # Execute the provided command
            exec "$@"
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
