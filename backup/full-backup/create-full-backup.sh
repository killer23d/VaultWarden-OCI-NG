#!/usr/bin/env bash
# backup/full-backup/create-full-backup.sh - Complete VaultWarden system backup for VM migration
# This script creates a comprehensive backup of everything needed for disaster recovery

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
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly BACKUP_NAME="vaultwarden_full_${TIMESTAMP}"
readonly OUTPUT_DIR="${PROJECT_ROOT}/migration_backups"
readonly TEMP_DIR="/tmp/${BACKUP_NAME}"

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

# Check if running from correct directory
validate_environment() {
    if [[ ! -f "$PROJECT_ROOT/docker-compose.yml" ]]; then
        log_error "Not running from VaultWarden project directory. PROJECT_ROOT: $PROJECT_ROOT"
    fi

    if [[ ! -d "$PROJECT_ROOT/data" ]]; then
        log_error "Data directory not found. Is VaultWarden initialized?"
    fi

    log_success "Environment validation passed"
}

# Create backup directories
setup_directories() {
    log_info "Setting up backup directories..."
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"
    chmod 755 "$OUTPUT_DIR"
    log_success "Directories created: $OUTPUT_DIR, $TEMP_DIR"
}

# Create database backup using existing script
backup_database() {
    log_info "Step 1/6: Creating database backup..."

    # Change to project root for docker compose commands
    cd "$PROJECT_ROOT"

    # Check if backup service is running
    if ! docker compose ps --services --filter "status=running" | grep -q "bw_backup"; then
        log_warning "Backup service not running. Starting temporarily..."
        docker compose up -d bw_backup
        sleep 15

        # Wait for service to be ready
        local attempts=0
        while [[ $attempts -lt 10 ]]; do
            if docker compose ps bw_backup | grep -q "Up"; then
                break
            fi
            sleep 5
            attempts=$((attempts + 1))
        done
    fi

    # Create database backup
    if docker compose exec -T bw_backup /backup/db-backup.sh --force; then
        # Find the latest database backup
        local latest_db_backup
        latest_db_backup=$(find "$PROJECT_ROOT/data/backups" -name "db_backup_*.sql*" -type f -exec ls -t {} + | head -1)

        if [[ -n "$latest_db_backup" && -f "$latest_db_backup" ]]; then
            cp "$latest_db_backup" "$TEMP_DIR/"
            log_success "Database backup included: $(basename "$latest_db_backup")"
        else
            log_error "Database backup not found after creation"
        fi
    else
        log_error "Database backup failed"
    fi
}

# Backup data directories
backup_data_directories() {
    log_info "Step 2/6: Backing up data directories..."

    cd "$PROJECT_ROOT"

    # Create comprehensive data backup excluding temporary files
    tar -czf "$TEMP_DIR/data_directories.tar.gz" \
        --exclude="./data/backups" \
        --exclude="./data/backup_logs" \
        --exclude="./data/*/lost+found" \
        --exclude="./data/*/*.tmp" \
        --exclude="./data/*/*.lock" \
        --exclude="./data/mariadb/ib_logfile*" \
        ./data/

    if [[ -f "$TEMP_DIR/data_directories.tar.gz" ]]; then
        local size
        size=$(du -h "$TEMP_DIR/data_directories.tar.gz" | cut -f1)
        log_success "Data directories backed up ($size)"
    else
        log_error "Failed to create data directories backup"
    fi
}

# Backup configuration files
backup_configurations() {
    log_info "Step 3/6: Backing up configuration files..."

    cd "$PROJECT_ROOT"

    # Backup all configuration files and scripts
    tar -czf "$TEMP_DIR/configuration.tar.gz" \
        --exclude="./migration_backups" \
        --exclude="./.git" \
        --exclude="./data" \
        --exclude="*.backup" \
        --exclude="*~" \
        ./settings.env \
        ./docker-compose.yml \
        ./caddy/ \
        ./fail2ban/ \
        ./config/ \
        ./lib/ \
        ./backup/ \
        ./ddclient/ \
        ./*.sh \
        2>/dev/null || true

    if [[ -f "$TEMP_DIR/configuration.tar.gz" ]]; then
        log_success "Configuration files backed up"
    else
        log_warning "Some configuration files may be missing"
        # Create minimal config backup
        tar -czf "$TEMP_DIR/configuration.tar.gz" \
            ./settings.env \
            ./docker-compose.yml \
            2>/dev/null || log_error "Critical configuration files missing"
    fi
}

# Backup SSL certificates
backup_ssl_certificates() {
    log_info "Step 4/6: Backing up SSL certificates..."

    if [[ -d "$PROJECT_ROOT/data/caddy_data" ]]; then
        tar -czf "$TEMP_DIR/ssl_certificates.tar.gz" \
            "$PROJECT_ROOT/data/caddy_data/" \
            2>/dev/null || true

        if [[ -f "$TEMP_DIR/ssl_certificates.tar.gz" ]]; then
            local size
            size=$(du -h "$TEMP_DIR/ssl_certificates.tar.gz" | cut -f1)
            log_success "SSL certificates backed up ($size)"
        else
            log_warning "No SSL certificates found or backup failed"
        fi
    else
        log_warning "Caddy data directory not found - SSL certificates not backed up"
    fi
}

# Create system information snapshot
backup_system_info() {
    log_info "Step 5/6: Creating system information snapshot..."

    # Create system info file
    cat > "$TEMP_DIR/system_info.txt" << EOF
# VaultWarden Full System Backup Information
Backup Date: $(date)
Backup Name: ${BACKUP_NAME}
Hostname: $(hostname)
OS Version: $(lsb_release -d 2>/dev/null || echo "Unknown")
Architecture: $(uname -m)
Kernel: $(uname -r)
Docker Version: $(docker --version 2>/dev/null || echo "Not available")
Docker Compose Version: $(docker compose version 2>/dev/null || echo "Not available")

# Container Status at Backup Time
$(cd "$PROJECT_ROOT" && docker compose ps 2>/dev/null || echo "Could not get container status")

# Disk Usage
$(df -h "$PROJECT_ROOT" 2>/dev/null || echo "Could not get disk usage")

# Memory Usage
$(free -h 2>/dev/null || echo "Could not get memory usage")

# VaultWarden Configuration Summary
$(grep -E "^(DOMAIN|APP_DOMAIN|MARIADB_DATABASE|BACKUP_)" "$PROJECT_ROOT/settings.env" 2>/dev/null || echo "Could not read settings")

# Backup File Sizes
Data Directories: $(du -h "$TEMP_DIR/data_directories.tar.gz" 2>/dev/null | cut -f1 || echo "N/A")
Configuration: $(du -h "$TEMP_DIR/configuration.tar.gz" 2>/dev/null | cut -f1 || echo "N/A")
SSL Certificates: $(du -h "$TEMP_DIR/ssl_certificates.tar.gz" 2>/dev/null | cut -f1 || echo "N/A")
Database: $(find "$TEMP_DIR" -name "db_backup_*.sql*" -exec du -h {} \; | cut -f1 || echo "N/A")
EOF

    log_success "System information snapshot created"
}

# Create final archive
create_final_archive() {
    log_info "Step 6/6: Creating final backup archive..."

    cd "$(dirname "$TEMP_DIR")"

    # Create compressed archive
    if tar -czf "$OUTPUT_DIR/${BACKUP_NAME}.tar.gz" "$(basename "$TEMP_DIR")"; then
        log_success "Archive created: ${BACKUP_NAME}.tar.gz"
    else
        log_error "Failed to create archive"
    fi

    if [[ -f "$OUTPUT_DIR/${BACKUP_NAME}.tar.gz" ]]; then
        # Create checksums
        cd "$OUTPUT_DIR"
        sha256sum "${BACKUP_NAME}.tar.gz" > "${BACKUP_NAME}.sha256"
        md5sum "${BACKUP_NAME}.tar.gz" > "${BACKUP_NAME}.md5"

        # Create backup manifest
        cat > "${BACKUP_NAME}_manifest.txt" << EOF
VaultWarden Full System Backup Manifest
Backup Name: ${BACKUP_NAME}
Created: $(date)
Size: $(du -h "${BACKUP_NAME}.tar.gz" | cut -f1)
Location: $(pwd)/${BACKUP_NAME}.tar.gz

Contents:
- Database backup (encrypted SQL dump)
- Data directories (bwdata, caddy_data, caddy_config, etc.)
- Configuration files (settings.env, docker-compose.yml, scripts)
- SSL certificates (Let's Encrypt)
- System information snapshot

Checksums:
SHA256: $(cut -d' ' -f1 "${BACKUP_NAME}.sha256")
MD5: $(cut -d' ' -f1 "${BACKUP_NAME}.md5")

Restoration Commands:
# Automated disaster recovery:
./backup/full-backup/rebuild-vm.sh ${BACKUP_NAME}.tar.gz

# Manual restoration:
./backup/full-backup/restore-full-backup.sh ${BACKUP_NAME}.tar.gz

# Backup validation:
./backup/full-backup/validate-backup.sh ${BACKUP_NAME}.tar.gz

Created by: create-full-backup.sh v1.0
EOF

        log_success "Backup manifest created"
    else
        log_error "Failed to create final archive"
    fi
}

# Upload to remote storage if configured
upload_to_remote() {
    log_info "Checking for remote storage configuration..."

    cd "$PROJECT_ROOT"

    # Check if rclone is configured and remote storage is available
    if [[ -f "$PROJECT_ROOT/backup/config/rclone.conf" ]]; then
        # Source environment variables
        if [[ -f "$PROJECT_ROOT/settings.env" ]]; then
            source "$PROJECT_ROOT/settings.env" 2>/dev/null || true
        fi

        if [[ -n "${BACKUP_REMOTE:-}" ]]; then
            log_info "Uploading to remote storage: $BACKUP_REMOTE"

            # Copy the backup file to the backup container's volume first
            cp "$OUTPUT_DIR/${BACKUP_NAME}.tar.gz" "$PROJECT_ROOT/data/backups/"
            cp "$OUTPUT_DIR/${BACKUP_NAME}.sha256" "$PROJECT_ROOT/data/backups/"
            cp "$OUTPUT_DIR/${BACKUP_NAME}.md5" "$PROJECT_ROOT/data/backups/"
            cp "$OUTPUT_DIR/${BACKUP_NAME}_manifest.txt" "$PROJECT_ROOT/data/backups/"

            # Upload via rclone from container
            if docker compose exec -T bw_backup rclone copy "/backups/${BACKUP_NAME}.tar.gz" "${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/" --config /home/backup/.config/rclone/rclone.conf; then
                # Also upload checksums and manifest
                docker compose exec -T bw_backup rclone copy "/backups/${BACKUP_NAME}.sha256" "${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/" --config /home/backup/.config/rclone/rclone.conf
                docker compose exec -T bw_backup rclone copy "/backups/${BACKUP_NAME}.md5" "${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/" --config /home/backup/.config/rclone/rclone.conf
                docker compose exec -T bw_backup rclone copy "/backups/${BACKUP_NAME}_manifest.txt" "${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/" --config /home/backup/.config/rclone/rclone.conf

                log_success "Backup uploaded to remote storage"
                log_info "Remote location: ${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/"
            else
                log_warning "Remote upload failed - backup saved locally only"
            fi

            # Clean up temporary copies
            rm -f "$PROJECT_ROOT/data/backups/${BACKUP_NAME}."*
        else
            log_info "No remote storage configured (BACKUP_REMOTE not set)"
        fi
    else
        log_info "rclone not configured - backup saved locally only"
    fi
}

# Cleanup temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_success "Temporary files cleaned up"
    fi
}

# Show backup summary
show_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}✅ COMPLETE BACKUP READY FOR VM MIGRATION${NC}"
    echo "=============================================="
    echo ""
    echo "📁 Backup Location: $OUTPUT_DIR/${BACKUP_NAME}.tar.gz"
    echo "📊 Backup Size: $(du -h "$OUTPUT_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)"
    echo "🔐 SHA256: $(cut -d' ' -f1 "$OUTPUT_DIR/${BACKUP_NAME}.sha256")"
    echo "📋 Manifest: $OUTPUT_DIR/${BACKUP_NAME}_manifest.txt"
    echo ""
    echo -e "${BLUE}📋 Backup Contents:${NC}"
    echo "✓ Database (all user data, organizations, ciphers)"
    echo "✓ Configuration files (settings, scripts, compose file)"  
    echo "✓ SSL certificates (Let's Encrypt)"
    echo "✓ Application data (VaultWarden data directory)"
    echo "✓ User attachments (file uploads)"
    echo "✓ System information (for troubleshooting)"
    echo ""
    echo -e "${BLUE}🔄 To Restore on New VM:${NC}"
    echo ""
    echo "Option A - Automated Recovery:"
    echo "  1. ./init-setup.sh"
    echo "  2. Copy backup file to new VM"
    echo "  3. ./backup/full-backup/rebuild-vm.sh ${BACKUP_NAME}.tar.gz"
    echo ""
    echo "Option B - Manual Recovery:"
    echo "  1. ./init-setup.sh"
    echo "  2. ./backup/full-backup/restore-full-backup.sh ${BACKUP_NAME}.tar.gz"
    echo "  3. Update settings.env for new VM"
    echo "  4. ./startup.sh"
    echo ""
    echo -e "${BLUE}🔍 Backup Validation:${NC}"
    echo "  ./backup/full-backup/validate-backup.sh --latest"
    echo "  ./backup/full-backup/validate-backup.sh --deep ${BACKUP_NAME}.tar.gz"
    echo ""
    echo -e "${YELLOW}⚠️  CRITICAL REMINDERS:${NC}"
    echo "• Store backup passphrase securely (needed for database restoration)"
    echo "• Update DNS records when switching to new VM"  
    echo "• Test backup restoration regularly (monthly recommended)"
    echo "• Keep multiple backup copies in different locations"
    echo ""

    # Show storage locations
    echo -e "${BLUE}💾 Storage Locations:${NC}"
    echo "  Local: $OUTPUT_DIR/"
    if [[ -n "${BACKUP_REMOTE:-}" ]]; then
        echo "  Remote: ${BACKUP_REMOTE}:${BACKUP_PATH:-vaultwarden-backups}/full/"
    else
        echo "  Remote: Not configured"
    fi
    echo ""
}

# Main execution
main() {
    echo "=============================================="
    echo "🔄 VaultWarden Complete System Backup"
    echo "=============================================="
    echo ""

    log_info "Starting full system backup process..."
    log_info "Script location: $SCRIPT_DIR"
    log_info "Project root: $PROJECT_ROOT"
    echo ""

    # Main backup process
    validate_environment
    setup_directories

    # Create all backup components
    backup_database
    backup_data_directories
    backup_configurations
    backup_ssl_certificates
    backup_system_info
    create_final_archive

    # Optional remote upload
    upload_to_remote

    # Cleanup and show results
    cleanup
    show_summary

    log_success "Full system backup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "• Validate backup: ./backup/full-backup/validate-backup.sh --latest"
    echo "• Test restoration: Set up test VM and run rebuild-vm.sh"
    echo "• Schedule regular backups: Add to crontab for weekly execution"
    echo ""
}

# Execute main function
main "$@"
