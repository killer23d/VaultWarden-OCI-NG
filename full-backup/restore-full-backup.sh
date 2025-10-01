#!/usr/bin/env bash
# backup/full-backup/restore-full-backup.sh - Restore complete VaultWarden system on new VM
# This script restores everything from a full system backup created by create-full-backup.sh

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration - Updated for /backup/full-backup/ directory structure
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKUP_DIR="$(dirname "$SCRIPT_DIR")"  # /backup
readonly PROJECT_ROOT="$(dirname "$BACKUP_DIR")"  # project root (two levels up)
BACKUP_FILE="${1:-}"

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

# Show usage information
show_usage() {
    echo "Usage: $0 <backup-file.tar.gz>"
    echo ""
    echo "Available backups:"

    # Look for backups in common locations - updated paths
    local backup_locations=(
        "$PROJECT_ROOT/migration_backups"
        "$PROJECT_ROOT"
        "."
    )

    local found_backups=false
    for location in "${backup_locations[@]}"; do
        if [[ -d "$location" ]]; then
            local backups
            backups=$(find "$location" -name "vaultwarden_full_*.tar.gz" -type f 2>/dev/null | head -5)
            if [[ -n "$backups" ]]; then
                echo "  In $location:"
                echo "$backups" | while read -r backup; do
                    echo "    $(basename "$backup")"
                done
                found_backups=true
            fi
        fi
    done

    if [[ "$found_backups" != "true" ]]; then
        echo "  No backup files found"
        echo ""
        echo "Create a backup first:"
        echo "  ./backup/full-backup/create-full-backup.sh"
    fi

    echo ""
    exit 1
}

# Validate backup file
validate_backup() {
    if [[ -z "$BACKUP_FILE" ]]; then
        log_error "No backup file specified"
        show_usage
    fi

    if [[ ! -f "$BACKUP_FILE" ]]; then
        # Try to find the file in common locations - updated paths
        local backup_locations=(
            "$PROJECT_ROOT/migration_backups/$BACKUP_FILE"
            "$PROJECT_ROOT/$BACKUP_FILE"
            "./$BACKUP_FILE"
        )

        local found_file=""
        for location in "${backup_locations[@]}"; do
            if [[ -f "$location" ]]; then
                found_file="$location"
                break
            fi
        done

        if [[ -n "$found_file" ]]; then
            BACKUP_FILE="$found_file"
            log_info "Found backup file: $BACKUP_FILE"
        else
            log_error "Backup file not found: $BACKUP_FILE"
            show_usage
        fi
    fi

    # Verify it's a gzipped tar file
    if ! file "$BACKUP_FILE" | grep -q "gzip compressed"; then
        log_error "Invalid backup file format (not a gzipped tar archive)"
    fi

    log_success "Backup file validated: $(basename "$BACKUP_FILE")"
}

# Verify backup integrity
verify_integrity() {
    log_info "Verifying backup integrity..."

    local backup_dir
    backup_dir="$(dirname "$BACKUP_FILE")"
    local backup_name
    backup_name="$(basename "$BACKUP_FILE" .tar.gz)"

    # Check for checksum files
    local sha_file="$backup_dir/${backup_name}.sha256"
    local md5_file="$backup_dir/${backup_name}.md5"

    if [[ -f "$sha_file" ]]; then
        log_info "Verifying SHA256 checksum..."
        cd "$backup_dir"
        if sha256sum -c "$(basename "$sha_file")" --quiet; then
            log_success "SHA256 checksum verified"
        else
            log_error "SHA256 checksum verification failed!"
        fi
    elif [[ -f "$md5_file" ]]; then
        log_info "Verifying MD5 checksum..."
        cd "$backup_dir"
        if md5sum -c "$(basename "$md5_file")" --quiet; then
            log_success "MD5 checksum verified"
        else
            log_error "MD5 checksum verification failed!"
        fi
    else
        log_warning "No checksum files found - skipping integrity verification"
    fi
}

# Extract backup
extract_backup() {
    log_info "Extracting backup archive..."

    local temp_dir
    temp_dir=$(mktemp -d)

    # Extract the backup
    if tar -xzf "$BACKUP_FILE" -C "$temp_dir"; then
        # Find the extracted directory
        local extracted_dir
        extracted_dir=$(find "$temp_dir" -mindepth 1 -maxdepth 1 -type d | head -1)

        if [[ -n "$extracted_dir" && -d "$extracted_dir" ]]; then
            echo "$extracted_dir"
            log_success "Backup extracted successfully"
        else
            log_error "Could not find extracted backup directory"
        fi
    else
        log_error "Failed to extract backup archive"
    fi
}

# Restore data directories
restore_data() {
    local backup_dir="$1"

    log_info "Restoring data directories..."

    if [[ -f "$backup_dir/data_directories.tar.gz" ]]; then
        # Create data directory if it doesn't exist
        mkdir -p "$PROJECT_ROOT/data"

        # Extract data directories
        cd "$PROJECT_ROOT"
        if tar -xzf "$backup_dir/data_directories.tar.gz"; then
            log_success "Data directories restored"
        else
            log_error "Failed to restore data directories"
        fi
    else
        log_error "Data directories backup not found in archive"
    fi
}

# Restore configuration files
restore_configuration() {
    local backup_dir="$1"

    log_info "Restoring configuration files..."

    if [[ -f "$backup_dir/configuration.tar.gz" ]]; then
        cd "$PROJECT_ROOT"

        # Backup existing settings.env if it exists
        if [[ -f "settings.env" ]]; then
            log_warning "Existing settings.env found - backing up as settings.env.backup"
            cp "settings.env" "settings.env.backup"
        fi

        # Extract configuration files
        if tar -xzf "$backup_dir/configuration.tar.gz"; then
            log_success "Configuration files restored"
        else
            log_error "Failed to restore configuration files"
        fi
    else
        log_error "Configuration backup not found in archive"
    fi
}

# Restore SSL certificates
restore_ssl_certificates() {
    local backup_dir="$1"

    log_info "Restoring SSL certificates..."

    if [[ -f "$backup_dir/ssl_certificates.tar.gz" ]]; then
        cd "$PROJECT_ROOT"
        if tar -xzf "$backup_dir/ssl_certificates.tar.gz"; then
            log_success "SSL certificates restored"
        else
            log_warning "Failed to restore SSL certificates"
        fi
    else
        log_warning "SSL certificates backup not found - will be regenerated on first run"
    fi
}

# Set proper permissions
set_permissions() {
    log_info "Setting proper file permissions..."

    # Check if we can use sudo
    local use_sudo=""
    if [[ $(id -u) -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
        if sudo -n chown --help >/dev/null 2>&1; then
            use_sudo="sudo "
        else
            log_warning "Cannot use sudo - you may need to set permissions manually"
            return 0
        fi
    fi

    # Set data directory permissions based on service requirements
    if [[ -d "$PROJECT_ROOT/data" ]]; then
        # User services (1000:1000) - need access to these directories
        ${use_sudo}chown -R 1000:1000 \
            "$PROJECT_ROOT/data/bwdata" \
            "$PROJECT_ROOT/data/caddy_data" \
            "$PROJECT_ROOT/data/caddy_config" \
            "$PROJECT_ROOT/data/caddy_logs" \
            "$PROJECT_ROOT/data/backups" \
            "$PROJECT_ROOT/data/backup_logs" \
            "$PROJECT_ROOT/data/fail2ban" \
            2>/dev/null || log_warning "Could not set permissions for user service directories"

        # System services (999:999) - isolated services
        ${use_sudo}chown -R 999:999 \
            "$PROJECT_ROOT/data/mariadb" \
            "$PROJECT_ROOT/data/redis" \
            2>/dev/null || log_warning "Could not set permissions for system service directories"

        # General directory permissions
        ${use_sudo}chmod -R 755 "$PROJECT_ROOT/data" 2>/dev/null || true

        log_success "File permissions updated"
    fi

    # Make scripts executable
    find "$PROJECT_ROOT" -name "*.sh" -type f -exec chmod +x {} \; 2>/dev/null || true
}

# Show system information from backup
show_backup_info() {
    local backup_dir="$1"

    if [[ -f "$backup_dir/system_info.txt" ]]; then
        log_info "Original system information:"
        echo ""
        cat "$backup_dir/system_info.txt"
        echo ""
    fi
}

# Validate configuration consistency
validate_configuration() {
    log_info "Validating restored configuration..."

    if [[ -f "$PROJECT_ROOT/settings.env" ]]; then
        # Check for critical variables
        source "$PROJECT_ROOT/settings.env" 2>/dev/null || true

        local missing_vars=()
        local required_vars=(
            "DOMAIN_NAME" "APP_DOMAIN" "ADMIN_TOKEN"
            "MARIADB_ROOT_PASSWORD" "MARIADB_PASSWORD" "REDIS_PASSWORD"
        )

        for var in "${required_vars[@]}"; do
            if [[ -z "${!var:-}" ]]; then
                missing_vars+=("$var")
            fi
        done

        if [[ ${#missing_vars[@]} -gt 0 ]]; then
            log_warning "Missing configuration variables: ${missing_vars[*]}"
            log_warning "You may need to update settings.env manually"
        else
            log_success "Configuration validation passed"
        fi
    else
        log_error "settings.env not found after restoration"
    fi
}

# Show next steps
show_next_steps() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}✅ FULL SYSTEM RESTORATION COMPLETED${NC}"
    echo "=============================================="
    echo ""
    echo -e "${BLUE}📋 What was restored:${NC}"
    echo "✓ Database backup (ready for restoration)"
    echo "✓ Data directories (bwdata, caddy_*, backups, etc.)"
    echo "✓ Configuration files (settings.env, docker-compose.yml, scripts)"
    echo "✓ SSL certificates (if available)"
    echo "✓ File permissions (user separation maintained)"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT NEXT STEPS:${NC}"
    echo ""
    echo "1. 🔧 Update configuration for new VM:"
    echo "   nano settings.env"
    echo "   # Verify DOMAIN settings, SMTP config, etc."
    echo ""
    echo "2. 🌐 Update DNS records:"
    echo "   # Point vault.yourdomain.com to new VM IP"
    echo ""
    echo "3. 🚀 Start services:"
    echo "   ./startup.sh"
    echo ""
    echo "4. ✅ Verify restoration:"
    echo "   ./diagnose.sh"
    echo "   # Test web access: https://vault.yourdomain.com"
    echo ""
    echo -e "${BLUE}🔍 Troubleshooting:${NC}"
    echo "• Check logs: docker compose logs <service-name>"
    echo "• Test connectivity: ./diagnose.sh --network"
    echo "• Monitor resources: ./perf-monitor.sh monitor"
    echo ""

    # Show backup settings summary if available
    if [[ -f "$PROJECT_ROOT/settings.env" ]]; then
        echo -e "${BLUE}📊 Current Configuration Summary:${NC}"
        grep -E "^(DOMAIN|APP_DOMAIN|MARIADB_DATABASE)" "$PROJECT_ROOT/settings.env" 2>/dev/null | sed 's/^/  /' || true
        echo ""
    fi
}

# Cleanup function
cleanup() {
    local temp_dir="$1"
    if [[ -n "$temp_dir" && -d "$temp_dir" ]]; then
        rm -rf "$temp_dir"
    fi
}

# Main execution
main() {
    echo "=============================================="
    echo "🔄 VaultWarden Complete System Restoration"
    echo "=============================================="
    echo ""

    # Validate inputs
    validate_backup
    verify_integrity

    # Confirmation prompt
    echo "📋 Restoration Plan:"
    echo "  Source: $(basename "$BACKUP_FILE")"
    echo "  Target: $PROJECT_ROOT"
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: This will overwrite existing data and configuration!${NC}"
    echo ""
    read -p "Continue with full system restoration? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Restoration cancelled."
        exit 0
    fi

    # Extract and restore
    local backup_extract_dir
    backup_extract_dir=$(extract_backup)

    # Set up cleanup trap
    trap \'cleanup "$backup_extract_dir"\' EXIT

    # Show original system info
    show_backup_info "$backup_extract_dir"

    # Restore all components
    restore_data "$backup_extract_dir"
    restore_configuration "$backup_extract_dir"
    restore_ssl_certificates "$backup_extract_dir"
    set_permissions
    validate_configuration

    # Show completion summary
    show_next_steps

    log_success "VaultWarden restoration completed successfully!"
}

# Execute main function with all arguments
main "$@"
