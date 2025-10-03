#!/usr/bin/env bash

# backup-manager.sh - Interactive backup management and monitoring
# Manage your VaultWarden automated backup system

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly BACKUP_SCRIPT="${SCRIPT_DIR}/create-full-backup.sh"
readonly SETTINGS_FILE="${PROJECT_ROOT}/settings.env"

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
}

log_header() {
    echo -e "${BOLD}${CYAN}$1${NC}"
}

# Load current settings
load_settings() {
    if [[ -f "$SETTINGS_FILE" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "$SETTINGS_FILE"
        set +a
    fi
}

# Show main menu
show_main_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                VaultWarden Backup Manager                 ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "📊 Backup System Management and Monitoring"
    echo ""
    echo "1) 📋 Show backup status and schedule"
    echo "2) 🚀 Run backup now (force backup)"
    echo "3) ☁️  Browse cloud storage contents"
    echo "4) 🔧 Modify backup settings"
    echo "5) ⏰ Manage cron schedule"
    echo "6) 🧪 Test system connectivity"
    echo "7) 📈 View backup history and logs"
    echo "8) 🔄 Restore from backup"
    echo "9) 🛠️  Troubleshooting tools"
    echo "0) ❌ Exit"
    echo ""
    echo -n "Select option [0-9]: "
}

# Show backup status
show_backup_status() {
    clear
    log_header "📋 Backup System Status"
    echo "$(printf '=%.0s' {1..50})"
    echo ""

    load_settings

    # Check backup script
    if [[ -f "$BACKUP_SCRIPT" ]] && [[ -x "$BACKUP_SCRIPT" ]]; then
        log_success "✓ Backup script available"
    else
        log_error "✗ Backup script missing or not executable"
        return 1
    fi

    # Check schedule
    local schedule_file="${PROJECT_ROOT}/.last_full_backup"
    local interval="${FULL_BACKUP_INTERVAL_DAYS:-21}"

    echo ""
    echo "⏰ Schedule Information:"
    if [[ -f "$schedule_file" ]]; then
        local last_backup
        last_backup=$(cat "$schedule_file" 2>/dev/null || echo "unknown")
        echo "   Last backup: $last_backup"

        if [[ "$last_backup" != "unknown" ]]; then
            local days_ago
            days_ago=$(( ($(date +%s) - $(date -d "$last_backup" +%s 2>/dev/null || echo 0)) / 86400 ))
            local days_until_next=$((interval - days_ago))

            echo "   Days since last: $days_ago"
            if [[ $days_until_next -le 0 ]]; then
                log_warning "   Status: Backup overdue"
            else
                echo "   Next backup in: $days_until_next days"
            fi
        fi
    else
        log_warning "   No previous backup recorded"
    fi

    echo "   Backup interval: $interval days"

    # Check cron job
    echo ""
    echo "🤖 Automation Status:"
    if crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
        log_success "   ✓ Cron job active"
        local cron_schedule
        cron_schedule=$(crontab -l 2>/dev/null | grep "$BACKUP_SCRIPT" | head -1)
        echo "   Schedule: $cron_schedule"
    else
        log_warning "   ⚠ No cron job found"
    fi

    # Check cloud configuration
    echo ""
    echo "☁️  Cloud Storage:"
    if [[ -n "${BACKUP_REMOTE:-}" ]]; then
        log_success "   ✓ Remote configured: $BACKUP_REMOTE"
        echo "   Path: ${BACKUP_PATH:-vaultwarden-backups}/full/"
    else
        log_warning "   ⚠ Remote storage not configured"
    fi

    # Check backup service
    echo ""
    echo "🐳 Backup Service:"
    if docker compose ps --services --filter "status=running" | grep -q "^bw_backup$"; then
        log_success "   ✓ Backup service running"
    else
        log_warning "   ⚠ Backup service not running"
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Force backup now
run_backup_now() {
    clear
    log_header "🚀 Manual Backup Execution"
    echo "$(printf '=%.0s' {1..50})"
    echo ""

    if [[ ! -f "$BACKUP_SCRIPT" ]]; then
        log_error "Backup script not found: $BACKUP_SCRIPT"
        echo -n "Press Enter to continue..."
        read -r
        return 1
    fi

    log_info "Running full backup now..."
    echo ""
    echo "This will:"
    echo "• Create a complete system backup"
    echo "• Upload to cloud storage"
    echo "• Delete local copy after upload"
    echo "• Update backup schedule"
    echo ""
    echo -n "Continue? [Y/n]: "
    read -r confirm

    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        log_info "Backup cancelled"
        echo -n "Press Enter to continue..."
        read -r
        return 0
    fi

    echo ""
    log_info "Starting backup..."
    echo ""

    if "$BACKUP_SCRIPT" --force; then
        echo ""
        log_success "🎉 Backup completed successfully!"
    else
        echo ""
        log_error "❌ Backup failed - check error messages above"
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Browse cloud storage
browse_cloud_storage() {
    clear
    log_header "☁️ Cloud Storage Browser"
    echo "$(printf '=%.0s' {1..50})"
    echo ""

    load_settings

    if [[ -z "${BACKUP_REMOTE:-}" ]]; then
        log_error "Cloud storage not configured"
        echo -n "Press Enter to continue..."
        read -r
        return 1
    fi

    # Ensure backup service is running
    if ! docker compose ps --services --filter "status=running" | grep -q "^bw_backup$"; then
        log_info "Starting backup service..."
        docker compose up -d bw_backup >/dev/null 2>&1
        sleep 5
    fi

    local backup_path="${BACKUP_PATH:-vaultwarden-backups}"

    echo "🗂️  Browsing: ${BACKUP_REMOTE}:${backup_path}/"
    echo ""

    # Show directory structure
    log_info "Directory structure:"
    if docker compose exec -T bw_backup rclone lsd "${BACKUP_REMOTE}:${backup_path}/" --config ~/.config/rclone/rclone.conf 2>/dev/null; then
        echo ""
    else
        log_warning "Could not list directories"
    fi

    # Show full backups
    echo ""
    log_info "Full backup files:"
    if docker compose exec -T bw_backup rclone ls "${BACKUP_REMOTE}:${backup_path}/full/" --config ~/.config/rclone/rclone.conf 2>/dev/null | head -20; then
        echo ""
    else
        log_warning "No full backup files found or could not access"
    fi

    echo ""
    echo "Options:"
    echo "1) List all files in full backup directory"
    echo "2) Check storage usage"
    echo "3) Test connectivity"
    echo "0) Back to main menu"
    echo ""
    echo -n "Select option [0-3]: "
    read -r option

    case "$option" in
        1)
            echo ""
            log_info "All files in full backup directory:"
            docker compose exec -T bw_backup rclone ls "${BACKUP_REMOTE}:${backup_path}/full/" --config ~/.config/rclone/rclone.conf 2>/dev/null || \
                log_warning "Could not list files"
            ;;
        2)
            echo ""
            log_info "Storage usage:"
            docker compose exec -T bw_backup rclone size "${BACKUP_REMOTE}:${backup_path}/" --config ~/.config/rclone/rclone.conf 2>/dev/null || \
                log_warning "Could not get storage usage"
            ;;
        3)
            echo ""
            log_info "Testing connectivity..."
            if docker compose exec -T bw_backup rclone lsd "${BACKUP_REMOTE}:" --config ~/.config/rclone/rclone.conf >/dev/null 2>&1; then
                log_success "✓ Connection successful"
            else
                log_error "✗ Connection failed"
            fi
            ;;
    esac

    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Show usage and help
show_usage() {
    echo "VaultWarden Backup Manager"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --status     Show backup status"
    echo "  --backup     Run backup now"
    echo "  --check      Check backup schedule"
    echo "  --browse     Browse cloud storage"
    echo "  --help       Show this help"
    echo ""
    echo "Interactive mode (default): $0"
}

# Handle command line arguments
handle_cli_args() {
    case "${1:-}" in
        --status)
            show_backup_status
            return 0
            ;;
        --backup)
            run_backup_now
            return 0
            ;;
        --check)
            if [[ -f "$BACKUP_SCRIPT" ]]; then
                "$BACKUP_SCRIPT" --check
            else
                log_error "Backup script not found"
                return 1
            fi
            return 0
            ;;
        --browse)
            browse_cloud_storage
            return 0
            ;;
        --help|-h)
            show_usage
            return 0
            ;;
        "")
            # No arguments - run interactive mode
            return 1
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            return 1
            ;;
    esac
}

# Main interactive loop
interactive_mode() {
    while true; do
        show_main_menu
        read -r choice

        case "$choice" in
            1)
                show_backup_status
                ;;
            2)
                run_backup_now
                ;;
            3)
                browse_cloud_storage
                ;;
            4)
                log_info "Use setup-automated-full-backup.sh to modify settings"
                echo -n "Press Enter to continue..."
                read -r
                ;;
            5)
                clear
                log_header "⏰ Cron Job Management"
                echo "$(printf '=%.0s' {1..50})"
                echo ""
                echo "Current cron jobs:"
                crontab -l 2>/dev/null | grep -v "^#" || echo "No cron jobs found"
                echo ""
                echo "To modify: crontab -e"
                echo -n "Press Enter to continue..."
                read -r
                ;;
            6)
                clear
                log_header "🧪 Connectivity Test"
                echo "$(printf '=%.0s' {1..50})"
                echo ""
                load_settings
                if [[ -n "${BACKUP_REMOTE:-}" ]]; then
                    if docker compose exec -T bw_backup rclone lsd "${BACKUP_REMOTE}:" --config ~/.config/rclone/rclone.conf >/dev/null 2>&1; then
                        log_success "✓ Cloud storage connectivity OK"
                    else
                        log_error "✗ Cannot connect to cloud storage"
                    fi
                else
                    log_warning "Cloud storage not configured"
                fi
                echo -n "Press Enter to continue..."
                read -r
                ;;
            7)
                clear
                log_header "📈 Backup History"
                echo "$(printf '=%.0s' {1..50})"
                echo ""
                echo "Recent system logs (backup-related):"
                journalctl -u cron --since "7 days ago" | grep -i backup | tail -10 || \
                    echo "No recent backup logs found"
                echo ""
                echo -n "Press Enter to continue..."
                read -r
                ;;
            8)
                log_info "Use restore-full-backup.sh for restoration"
                echo -n "Press Enter to continue..."
                read -r
                ;;
            9)
                clear
                log_header "🛠️ Troubleshooting Tools"
                echo "$(printf '=%.0s' {1..50})"
                echo ""
                echo "Common troubleshooting commands:"
                echo ""
                echo "• Check services: docker compose ps"
                echo "• View logs: docker compose logs bw_backup"
                echo "• Test rclone: docker compose exec bw_backup rclone lsd REMOTE:"
                echo "• Check cron: crontab -l"
                echo "• Check disk space: df -h"
                echo "• Manual backup: $BACKUP_SCRIPT --force"
                echo ""
                echo -n "Press Enter to continue..."
                read -r
                ;;
            0)
                echo ""
                log_info "Goodbye! 👋"
                exit 0
                ;;
            *)
                log_warning "Invalid option. Please try again."
                sleep 1
                ;;
        esac
    done
}

# Main function
main() {
    # Handle command line arguments
    if handle_cli_args "$@"; then
        return 0
    fi

    # Run interactive mode
    interactive_mode
}

# Execute main
main "$@"
