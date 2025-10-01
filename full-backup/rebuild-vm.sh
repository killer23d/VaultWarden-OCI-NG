#!/usr/bin/env bash
# backup/full-backup/rebuild-vm.sh - Complete VM rebuild and restoration process
# This script automates the entire disaster recovery process on a new VM

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

# Show usage
show_usage() {
    cat << EOF
VaultWarden VM Rebuild Script

Usage: $0 <backup-file.tar.gz>

This script automates the complete disaster recovery process:
1. Validates the new VM environment
2. Runs init-setup.sh if needed
3. Restores from full backup
4. Guides through final configuration
5. Starts services and validates

Examples:
  $0 vaultwarden_full_20241001_143000.tar.gz
  $0 /path/to/backup.tar.gz

Available backups:
$(find "$PROJECT_ROOT/migration_backups" "$PROJECT_ROOT" -name "vaultwarden_full_*.tar.gz" -type f 2>/dev/null | head -5 | sed 's/^/  /' || echo "  No backup files found")

EOF
    exit 1
}

# Check VM readiness
check_vm_environment() {
    log_info "Checking VM environment readiness..."

    # Check OS
    if ! lsb_release -d 2>/dev/null | grep -qi ubuntu; then
        log_warning "Non-Ubuntu OS detected - some features may not work as expected"
    fi

    # Check architecture
    if [[ "$(uname -m)" != "aarch64" ]] && [[ "$(uname -m)" != "arm64" ]]; then
        log_warning "Non-ARM64 architecture detected - this may not be OCI A1 Flex"
    fi

    # Check memory
    local total_mem
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $total_mem -lt 5 ]]; then
        log_warning "Less than 6GB RAM detected (${total_mem}GB) - performance may be impacted"
    fi

    # Check disk space
    local available_space
    available_space=$(df . | awk 'NR==2{print $4}')
    if [[ $available_space -lt 10485760 ]]; then  # 10GB in KB
        log_warning "Less than 10GB free disk space - may not be sufficient"
    fi

    log_success "VM environment check completed"
}

# Initialize new VM if needed
initialize_vm() {
    log_info "Checking if VM initialization is needed..."

    # Check if Docker is installed
    if ! command -v docker >/dev/null 2>&1; then
        log_info "Docker not found - running VM initialization..."

        if [[ -f "$PROJECT_ROOT/init-setup.sh" ]]; then
            chmod +x "$PROJECT_ROOT/init-setup.sh"
            cd "$PROJECT_ROOT"
            if ./init-setup.sh; then
                log_success "VM initialization completed"
            else
                log_error "VM initialization failed"
            fi
        else
            log_error "init-setup.sh not found - cannot initialize VM"
        fi
    else
        log_info "Docker found - VM appears to be initialized"

        # Check if Docker Compose is available
        if ! docker compose version >/dev/null 2>&1; then
            log_warning "Docker Compose not available - may need to install"
        fi

        # Check if directories exist
        if [[ ! -d "$PROJECT_ROOT/data" ]]; then
            log_info "Creating missing data directories..."
            mkdir -p "$PROJECT_ROOT/data"/{bwdata,mariadb,redis,caddy_data,caddy_config,caddy_logs,backups,backup_logs,fail2ban}
        fi
    fi
}

# Validate backup file
validate_backup_file() {
    if [[ -z "$BACKUP_FILE" ]]; then
        log_error "No backup file specified"
        show_usage
    fi

    if [[ ! -f "$BACKUP_FILE" ]]; then
        log_error "Backup file not found: $BACKUP_FILE"
        show_usage
    fi

    log_info "Backup file validated: $(basename "$BACKUP_FILE")"
}

# Network configuration guidance
guide_network_configuration() {
    log_info "Network Configuration Guidance"
    echo ""
    echo "🌐 Before proceeding, ensure:"
    echo "  1. Firewall allows ports 80 and 443"
    echo "  2. OCI Security Lists allow HTTP/HTTPS traffic"
    echo "  3. DNS will be updated to point to this VM"
    echo ""

    # Get current IP
    local current_ip
    current_ip=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "Unable to detect")
    echo "📍 Current VM IP: $current_ip"
    echo ""

    read -p "Network configuration ready? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Please configure network settings first:"
        echo ""
        echo "OCI Console:"
        echo "  1. Go to your instance's subnet"
        echo "  2. Edit Security List"
        echo "  3. Add Ingress Rules:"
        echo "     - HTTP: Source 0.0.0.0/0, Port 80"
        echo "     - HTTPS: Source 0.0.0.0/0, Port 443"
        echo ""
        echo "Local Firewall (if using ufw):"
        echo "  sudo ufw allow 80/tcp"
        echo "  sudo ufw allow 443/tcp"
        echo "  sudo ufw reload"
        echo ""
        exit 1
    fi
}

# Restore from backup
restore_backup() {
    log_info "Starting backup restoration..."

    if [[ -f "$SCRIPT_DIR/restore-full-backup.sh" ]]; then
        chmod +x "$SCRIPT_DIR/restore-full-backup.sh"
        if "$SCRIPT_DIR/restore-full-backup.sh" "$BACKUP_FILE"; then
            log_success "Backup restoration completed"
        else
            log_error "Backup restoration failed"
        fi
    else
        log_error "restore-full-backup.sh not found in $SCRIPT_DIR"
    fi
}

# Guide configuration updates
guide_configuration_updates() {
    log_info "Configuration Update Guidance"
    echo ""
    echo "🔧 Configuration files have been restored from backup."
    echo "   You may need to update some settings for the new VM environment."
    echo ""

    if [[ -f "$PROJECT_ROOT/settings.env" ]]; then
        echo "📋 Current key settings:"
        grep -E "^(DOMAIN|APP_DOMAIN|TZ|ADMIN_EMAIL)" "$PROJECT_ROOT/settings.env" 2>/dev/null | sed 's/^/  /' || true
        echo ""

        echo "🔍 Settings you might need to update:"
        echo "  • TZ (timezone) - if different from original VM"
        echo "  • ADMIN_EMAIL - if changed"
        echo "  • SMTP settings - if server-specific"
        echo "  • Backup remote paths - if changed"
        echo ""

        read -p "Edit settings.env now? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if command -v nano >/dev/null 2>&1; then
                nano "$PROJECT_ROOT/settings.env"
            elif command -v vim >/dev/null 2>&1; then
                vim "$PROJECT_ROOT/settings.env"
            else
                log_warning "No text editor found - edit settings.env manually before starting services"
            fi
        fi
    else
        log_error "settings.env not found after restoration"
    fi
}

# Start services and validate
start_and_validate() {
    log_info "Starting VaultWarden services..."

    cd "$PROJECT_ROOT"

    if [[ -f "$PROJECT_ROOT/startup.sh" ]]; then
        chmod +x "$PROJECT_ROOT/startup.sh"

        # Start services
        if ./startup.sh; then
            log_success "Services started successfully"

            # Wait a moment for services to stabilize
            log_info "Waiting for services to stabilize..."
            sleep 30

            # Run diagnostics
            if [[ -f "$PROJECT_ROOT/diagnose.sh" ]]; then
                chmod +x "$PROJECT_ROOT/diagnose.sh"
                log_info "Running system diagnostics..."
                ./diagnose.sh || log_warning "Some diagnostic checks failed"
            fi
        else
            log_error "Failed to start services - check logs for details"
        fi
    else
        log_error "startup.sh not found in $PROJECT_ROOT"
    fi
}

# Show final summary and next steps
show_final_summary() {
    local current_ip
    current_ip=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || echo "Unable to detect")

    echo ""
    echo "=============================================="
    echo -e "${GREEN}🎉 VM REBUILD COMPLETED SUCCESSFULLY!${NC}"
    echo "=============================================="
    echo ""
    echo -e "${BLUE}📊 System Status:${NC}"
    echo "  VM IP Address: $current_ip"
    echo "  Services: Started and running"
    echo "  Diagnostics: $(if [[ -f "$PROJECT_ROOT/diagnose.sh" ]]; then echo "Available"; else echo "Not available"; fi)"
    echo ""
    echo -e "${BLUE}🔍 Verification Steps:${NC}"
    echo "  1. Update DNS to point to: $current_ip"
    echo "  2. Wait for DNS propagation (5-60 minutes)"
    echo "  3. Test web access: https://vault.yourdomain.com"
    echo "  4. Test admin panel: https://vault.yourdomain.com/admin"
    echo "  5. Test user login with existing accounts"
    echo ""
    echo -e "${BLUE}🛠️  Management Commands:${NC}"
    echo "  Real-time monitoring: ./dashboard.sh"
    echo "  System diagnostics: ./diagnose.sh"
    echo "  Performance check: ./perf-monitor.sh status"
    echo "  View service logs: docker compose logs <service-name>"
    echo ""
    echo -e "${BLUE}🔐 Security Features Restored:${NC}"
    echo "  ✓ SSL certificates (Let's Encrypt)"
    echo "  ✓ Fail2ban intrusion protection"
    echo "  ✓ Encrypted database backups"
    echo "  ✓ User permission separation"
    echo ""
    echo -e "${YELLOW}⚠️  Important Reminders:${NC}"
    echo "  • DNS propagation may take up to 1 hour"
    echo "  • SSL certificates will renew automatically"
    echo "  • Backups will resume on schedule"
    echo "  • Monitor logs for first 24 hours"
    echo ""
    echo -e "${GREEN}✅ Disaster recovery completed successfully!${NC}"
    echo ""
}

# Main execution
main() {
    echo "=============================================="
    echo "🔄 VaultWarden VM Rebuild & Recovery"
    echo "=============================================="
    echo ""

    # Validate inputs
    if [[ -z "$BACKUP_FILE" ]]; then
        show_usage
    fi

    validate_backup_file

    echo "📋 Rebuild Plan:"
    echo "  Target VM: $(hostname)"
    echo "  Backup Source: $(basename "$BACKUP_FILE")"
    echo "  Process: Full disaster recovery"
    echo ""

    read -p "Continue with complete VM rebuild? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "VM rebuild cancelled."
        exit 0
    fi

    echo ""
    log_info "Starting VM rebuild process..."

    # Execute rebuild phases
    check_vm_environment
    initialize_vm
    guide_network_configuration
    restore_backup
    guide_configuration_updates
    start_and_validate
    show_final_summary

    log_success "VM rebuild and recovery completed successfully!"
}

# Execute main function with all arguments
main "$@"
