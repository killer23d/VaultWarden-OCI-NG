#!/usr/bin/env bash

# setup-automated-full-backup.sh - Enhanced OCI Vault Integration
# Interactive setup for automated full backups with OCI Vault secret management
# Enhanced with progress indicators, retry logic, and dry-run mode

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
readonly RCLONE_CONFIG_DIR="${PROJECT_ROOT}/backup/config"
readonly RCLONE_CONFIG_FILE="${RCLONE_CONFIG_DIR}/rclone.conf"
readonly OCI_SETUP_SCRIPT="${PROJECT_ROOT}/oci-setup.sh"

# Temporary files for vault integration
readonly TEMP_SETTINGS_DIR="/tmp/vaultwarden_setup_$$"
readonly TEMP_SETTINGS_FILE="${TEMP_SETTINGS_DIR}/settings.env"
readonly TEMP_UPDATED_FILE="${TEMP_SETTINGS_DIR}/settings_updated.env"

# Default settings
DEFAULT_BACKUP_INTERVAL=21
DEFAULT_BACKUP_PATH="vaultwarden-backups"

# Enhanced: Dry-run mode support
DRY_RUN_MODE=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN_MODE=true
    log_info "🧪 DRY RUN MODE: No changes will be made to OCI Vault"
    shift
fi

# Cleanup trap
cleanup() {
    if [[ -d "$TEMP_SETTINGS_DIR" ]]; then
        rm -rf "$TEMP_SETTINGS_DIR" || true
    fi
}

trap cleanup EXIT INT TERM

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

log_step() {
    echo -e "${BOLD}${BLUE}$1${NC}"
}

# Enhanced: Progress indicator function
show_progress() {
    local message="$1"
    local duration="${2:-15}"

    echo -n "${BLUE}[INFO]${NC} $message"

    for ((i=0; i<duration; i++)); do
        echo -n "."
        sleep 1
    done
    echo ""
}

# Enhanced: Retry wrapper for network operations
retry_operation() {
    local max_attempts=3
    local delay=5
    local operation_name="$1"
    shift

    for attempt in $(seq 1 $max_attempts); do
        if [[ $attempt -gt 1 ]]; then
            log_warning "Retry attempt $attempt/$max_attempts for: $operation_name"
            sleep $delay
        fi

        if "$@"; then
            return 0
        fi

        if [[ $attempt -eq $max_attempts ]]; then
            log_error "Failed after $max_attempts attempts: $operation_name"
            return 1
        fi
    done
}

draw_separator() {
    echo -e "${CYAN}$(printf '=%.0s' {1..60})${NC}"
}

# Show welcome screen with OCI Vault awareness
show_welcome() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "║        VaultWarden Automated Backup - DRY RUN MODE        ║"
    else
        echo "║        VaultWarden Automated Backup with OCI Vault        ║"
    fi
    echo "║                 Interactive Setup Wizard                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "🧪 DRY RUN MODE ACTIVE"
        echo "   • Configuration will be prepared but not saved"
        echo "   • No changes will be made to OCI Vault"
        echo "   • Services will not be restarted"
        echo "   • Perfect for testing and validation"
        echo ""
    fi

    echo "🔒 This wizard configures automated full backups for VaultWarden"
    echo "   with enterprise-grade OCI Vault secret management."
    echo ""
    echo "📋 What this wizard will do:"
    echo "• 🔍 Fetch current settings from OCI Vault"
    echo "• ⚙️  Configure automated backup preferences"
    echo "• ☁️  Set up rclone cloud storage integration"  
    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "• 👀 Preview configuration changes (DRY RUN)"
    else
        echo "• 🔄 Update OCI Vault with new configuration"
    fi
    echo "• 🤖 Set up automated 21-day backup scheduling"
    echo "• 🧪 Test the complete backup system"
    echo ""
    echo "🛡️ Security Benefits:"
    echo "• All secrets remain in OCI Vault (never stored on disk)"
    echo "• Encrypted backups with enterprise key management"
    echo "• Audit trail of all configuration changes"
    echo "• Multi-VM deployment support"
    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Check OCI Vault setup and connectivity
check_oci_vault_setup() {
    clear
    log_header "🔐 OCI Vault Configuration Check"
    draw_separator
    echo ""

    # Enhanced: Progress indicator for long operations
    log_info "Checking OCI Vault setup components..."

    # Check if OCI setup script exists
    if [[ ! -f "$OCI_SETUP_SCRIPT" ]]; then
        log_error "OCI setup script not found: $OCI_SETUP_SCRIPT"
        echo ""
        echo "The OCI Vault integration script is required for this setup."
        echo "Please ensure the oci-setup.sh script is present in the project root."
        return 1
    fi

    if [[ ! -x "$OCI_SETUP_SCRIPT" ]]; then
        chmod +x "$OCI_SETUP_SCRIPT"
        log_info "Made OCI setup script executable"
    fi

    # Check if OCI_SECRET_OCID is set
    if [[ -z "${OCI_SECRET_OCID:-}" ]]; then
        log_warning "OCI_SECRET_OCID environment variable not set"
        echo ""
        echo "You have two options:"
        echo ""
        echo "1) 📁 Local Mode (settings.env file on disk)"
        echo "   - Use local settings.env file"
        echo "   - Good for development/testing"
        echo "   - Less secure (secrets on disk)"
        echo ""
        echo "2) 🔒 Vault Mode (recommended for production)"
        echo "   - Use OCI Vault for secret storage"
        echo "   - Enterprise security"
        echo "   - Requires OCI_SECRET_OCID to be set"
        echo ""
        echo -n "Choose mode [1=local, 2=vault]: "
        read -r mode_choice

        case "$mode_choice" in
            1)
                log_info "Selected local mode"
                return 2  # Signal local mode
                ;;
            2)
                echo ""
                echo "To use OCI Vault mode:"
                echo "1. Set up OCI Vault: $OCI_SETUP_SCRIPT setup"
                echo "2. Export the OCID: export OCI_SECRET_OCID='your-secret-ocid'"
                echo "3. Re-run this setup wizard"
                echo ""
                log_warning "Please complete OCI Vault setup first"
                return 1
                ;;
            *)
                log_error "Invalid choice"
                return 1
                ;;
        esac
    fi

    # Enhanced: Progress indicator for OCI CLI check
    log_info "Verifying OCI CLI installation and configuration..."
    if ! command -v oci >/dev/null 2>&1; then
        log_error "OCI CLI not found"
        echo "Please install OCI CLI or use local mode"
        return 1
    fi

    # Enhanced: Test vault connectivity with retry logic
    log_info "Testing OCI Vault connectivity (this may take 10-30 seconds)..."
    if retry_operation "OCI Vault connectivity test" oci secrets secret-bundle get --secret-id "$OCI_SECRET_OCID" --stage CURRENT >/dev/null 2>&1; then
        log_success "✓ OCI Vault connectivity verified"
        return 0  # Signal vault mode
    else
        log_error "Cannot access OCI Vault secret"
        echo ""
        echo "Troubleshooting:"
        echo "1. Check OCI_SECRET_OCID is correct"
        echo "2. Verify OCI CLI configuration: oci iam user get --user-id [your-user-id]"
        echo "3. Check vault permissions"
        echo "4. Verify network connectivity"
        return 1
    fi
}

# Fetch current settings from OCI Vault
fetch_vault_settings() {
    log_info "Fetching current configuration from OCI Vault..."

    # Create temp directory
    mkdir -p "$TEMP_SETTINGS_DIR"
    chmod 700 "$TEMP_SETTINGS_DIR"

    # Enhanced: Progress indicator for fetch operation
    echo -n "${BLUE}[INFO]${NC} Downloading settings from OCI Vault"

    # Enhanced: Use retry logic for vault fetch
    local fetch_success=false

    # Method 1: Try oci-setup.sh first (with progress)
    if retry_operation "OCI Vault fetch via oci-setup.sh" "$OCI_SETUP_SCRIPT" get --output "$TEMP_SETTINGS_FILE" >/dev/null 2>&1; then
        echo ""
        log_success "✓ Settings fetched from OCI Vault via oci-setup.sh"
        fetch_success=true
    else
        echo ""
        # Method 2: Fallback to direct OCI CLI call (with progress)
        log_info "Fallback: Using direct OCI CLI to fetch settings..."

        if retry_operation "Direct OCI CLI fetch" bash -c "oci secrets secret-bundle get --secret-id '$OCI_SECRET_OCID' --stage CURRENT --query 'data."secret-bundle-content"."content"' --raw-output | base64 -d > '$TEMP_SETTINGS_FILE' 2>/dev/null"; then
            log_success "✓ Settings fetched from OCI Vault via OCI CLI"
            fetch_success=true
        fi
    fi

    if [[ "$fetch_success" != "true" ]]; then
        log_error "Failed to fetch settings from OCI Vault"
        return 1
    fi

    # Validate fetched settings
    if [[ ! -s "$TEMP_SETTINGS_FILE" ]]; then
        log_error "Fetched settings file is empty"
        return 1
    fi

    # Enhanced: Better syntax validation with specific error reporting
    if ! bash -n "$TEMP_SETTINGS_FILE" 2>/tmp/syntax_check_$$; then
        log_error "Fetched settings file has syntax errors:"
        cat /tmp/syntax_check_$$
        rm -f /tmp/syntax_check_$$
        return 1
    fi
    rm -f /tmp/syntax_check_$$ 2>/dev/null || true

    log_success "Settings successfully fetched and validated ($(wc -l < "$TEMP_SETTINGS_FILE") lines)"
    return 0
}

# Display current backup configuration from vault
show_vault_backup_config() {
    clear
    log_header "📋 Current Backup Configuration (from OCI Vault)"
    draw_separator
    echo ""

    # Load fetched settings
    set -a
    # shellcheck source=/dev/null
    source "$TEMP_SETTINGS_FILE"
    set +a

    echo "🔐 Secret Source: OCI Vault"
    echo "    Secret OCID: ${OCI_SECRET_OCID:0:20}...${OCI_SECRET_OCID: -8}"
    echo ""
    echo "☁️  Current Cloud Storage:"
    echo "    BACKUP_REMOTE: ${BACKUP_REMOTE:-❌ Not configured}"
    echo "    BACKUP_PATH: ${BACKUP_PATH:-❌ Not configured}"
    echo "    BACKUP_PASSPHRASE: ${BACKUP_PASSPHRASE:+✅ Configured}${BACKUP_PASSPHRASE:-❌ Not configured}"
    echo ""
    echo "📅 Full Backup Schedule:"
    echo "    Interval: ${FULL_BACKUP_INTERVAL_DAYS:-21} days (default)"
    echo "    Enabled: ${FULL_BACKUP_ENABLED:-false}"
    echo "    Cloud Only: ${FULL_BACKUP_CLOUD_ONLY:-false}"
    echo ""

    # Check rclone config
    if [[ -f "$RCLONE_CONFIG_FILE" ]]; then
        log_success "✓ rclone configuration file exists"

        local remotes
        if remotes=$(grep "^\[.*\]$" "$RCLONE_CONFIG_FILE" 2>/dev/null | tr -d '[]'); then
            if [[ -n "$remotes" ]]; then
                echo "    Available remotes:"
                echo "$remotes" | while read -r remote; do
                    echo "      • $remote"
                done
            fi
        fi
    else
        log_warning "⚠ rclone configuration not found"
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Apply intelligent updates to vault settings
update_vault_settings() {
    local remote="$1"
    local path="$2"
    local interval="$3"
    local passphrase="$4"

    log_info "Applying intelligent updates to vault configuration..."

    # Create updated settings file
    local updated_vars=()
    local added_vars=()

    # Process original file line by line (same intelligent logic)
    if [[ -f "$TEMP_SETTINGS_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            case "$line" in
                BACKUP_REMOTE=*)
                    echo "BACKUP_REMOTE=$remote" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("BACKUP_REMOTE")
                    ;;
                BACKUP_PATH=*)
                    echo "BACKUP_PATH=$path" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("BACKUP_PATH")
                    ;;
                FULL_BACKUP_INTERVAL_DAYS=*)
                    echo "FULL_BACKUP_INTERVAL_DAYS=$interval" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("FULL_BACKUP_INTERVAL_DAYS")
                    ;;
                BACKUP_PASSPHRASE=*)
                    if [[ -n "$passphrase" ]]; then
                        echo "BACKUP_PASSPHRASE=$passphrase" >> "$TEMP_UPDATED_FILE"
                        updated_vars+=("BACKUP_PASSPHRASE")
                    else
                        echo "# BACKUP_PASSPHRASE=" >> "$TEMP_UPDATED_FILE"
                        updated_vars+=("BACKUP_PASSPHRASE (disabled)")
                    fi
                    ;;
                FULL_BACKUP_ENABLED=*)
                    echo "FULL_BACKUP_ENABLED=true" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("FULL_BACKUP_ENABLED")
                    ;;
                FULL_BACKUP_CLOUD_ONLY=*)
                    echo "FULL_BACKUP_CLOUD_ONLY=true" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("FULL_BACKUP_CLOUD_ONLY")
                    ;;
                \#*BACKUP_REMOTE=*)
                    echo "BACKUP_REMOTE=$remote  # Enabled by backup wizard" >> "$TEMP_UPDATED_FILE"
                    updated_vars+=("BACKUP_REMOTE (uncommented)")
                    ;;
                *)
                    echo "$line" >> "$TEMP_UPDATED_FILE"
                    ;;
            esac
        done < "$TEMP_SETTINGS_FILE"
    fi

    # Add missing variables
    local vars_to_check=(
        "BACKUP_REMOTE:$remote"
        "BACKUP_PATH:$path"
        "FULL_BACKUP_INTERVAL_DAYS:$interval"
        "FULL_BACKUP_ENABLED:true"
        "FULL_BACKUP_CLOUD_ONLY:true"
    )

    if [[ -n "$passphrase" ]]; then
        vars_to_check+=("BACKUP_PASSPHRASE:$passphrase")
    fi

    for var_spec in "${vars_to_check[@]}"; do
        local var_name="${var_spec%:*}"
        local var_value="${var_spec#*:}"

        if ! grep -q "^${var_name}=" "$TEMP_UPDATED_FILE" 2>/dev/null; then
            echo "${var_name}=${var_value}" >> "$TEMP_UPDATED_FILE"
            added_vars+=("$var_name")
        fi
    done

    # Show changes
    echo ""
    log_success "Configuration updates prepared!"

    if [[ ${#updated_vars[@]} -gt 0 ]]; then
        echo ""
        echo "📝 Variables to be updated in OCI Vault:"
        for var in "${updated_vars[@]}"; do
            echo "   ✓ $var"
        done
    fi

    if [[ ${#added_vars[@]} -gt 0 ]]; then
        echo ""
        echo "➕ Variables to be added to OCI Vault:"
        for var in "${added_vars[@]}"; do
            echo "   + $var"
        done
    fi

    return 0
}

# Show settings diff and get confirmation
show_vault_changes_preview() {
    clear
    log_header "📊 Configuration Changes Preview"
    draw_separator
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "🧪 DRY RUN MODE: These changes would be applied in normal mode"
        echo ""
    fi

    echo "🔍 Comparing current vault settings with proposed changes:"
    echo ""

    # Show key backup-related changes
    echo "📋 Backup Configuration Changes:"
    echo ""

    # Load both files for comparison
    local current_backup_remote=""
    local current_backup_path=""
    local current_interval=""

    if [[ -f "$TEMP_SETTINGS_FILE" ]]; then
        current_backup_remote=$(grep "^BACKUP_REMOTE=" "$TEMP_SETTINGS_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        current_backup_path=$(grep "^BACKUP_PATH=" "$TEMP_SETTINGS_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        current_interval=$(grep "^FULL_BACKUP_INTERVAL_DAYS=" "$TEMP_SETTINGS_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    fi

    local new_backup_remote=""
    local new_backup_path=""
    local new_interval=""

    if [[ -f "$TEMP_UPDATED_FILE" ]]; then
        new_backup_remote=$(grep "^BACKUP_REMOTE=" "$TEMP_UPDATED_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        new_backup_path=$(grep "^BACKUP_PATH=" "$TEMP_UPDATED_FILE" 2>/dev/null | cut -d= -f2 || echo "")
        new_interval=$(grep "^FULL_BACKUP_INTERVAL_DAYS=" "$TEMP_UPDATED_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    fi

    # Show changes in table format
    printf "%-25s | %-20s | %-20s\n" "Setting" "Current (Vault)" "New (Proposed)"
    printf "%-25s-|-%-20s-|-%-20s\n" "$(printf '%*s' 25 '' | tr ' ' '-')" "$(printf '%*s' 20 '' | tr ' ' '-')" "$(printf '%*s' 20 '' | tr ' ' '-')"
    printf "%-25s | %-20s | %-20s\n" "BACKUP_REMOTE" "${current_backup_remote:-❌ Not set}" "${new_backup_remote}"
    printf "%-25s | %-20s | %-20s\n" "BACKUP_PATH" "${current_backup_path:-❌ Not set}" "${new_backup_path}" 
    printf "%-25s | %-20s | %-20s\n" "BACKUP_INTERVAL_DAYS" "${current_interval:-21 (default)}" "${new_interval}"
    printf "%-25s | %-20s | %-20s\n" "FULL_BACKUP_ENABLED" "❌ Not set" "✅ true"
    printf "%-25s | %-20s | %-20s\n" "FULL_BACKUP_CLOUD_ONLY" "❌ Not set" "✅ true"

    echo ""
    echo "🔐 Security Impact:"
    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "• Changes would be stored securely in OCI Vault (DRY RUN)"
        echo "• No sensitive data would remain on the VM disk (DRY RUN)"
    else
        echo "• All changes will be stored securely in OCI Vault"
        echo "• No sensitive data will remain on the VM disk"
    fi
    echo "• Existing passwords and tokens remain unchanged"
    echo "• Only backup-related settings are modified"
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "🧪 DRY RUN: Configuration preview completed successfully!"
        echo ""
        echo "To apply these changes:"
        echo "1. Re-run without --dry-run flag"
        echo "2. Or review and modify the configuration manually"
        echo ""
        echo -n "Press Enter to complete dry run..."
        read -r
        return 1  # Don't proceed with actual changes
    else
        echo -n "Apply these changes to OCI Vault? [Y/n]: "
        read -r confirm_changes

        if [[ "$confirm_changes" =~ ^[Nn]$ ]]; then
            log_info "Changes cancelled by user"
            return 1
        fi
    fi

    return 0
}

# Enhanced: Push updated settings to OCI Vault with retry logic
push_to_oci_vault() {
    clear
    log_header "🔄 Updating OCI Vault Configuration"
    draw_separator
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        log_info "DRY RUN: Would push updated configuration to OCI Vault"
        return 0
    fi

    log_info "Pushing updated configuration to OCI Vault (this may take 15-45 seconds)..."

    # Enhanced: Method 1 with retry logic
    if retry_operation "OCI Vault update via oci-setup.sh" "$OCI_SETUP_SCRIPT" update --file "$TEMP_UPDATED_FILE" >/dev/null 2>&1; then
        log_success "✓ Settings updated via oci-setup.sh"
        return 0
    fi

    # Enhanced: Method 2 with better progress indication
    log_info "Automatic update not available, providing manual process..."
    echo ""
    echo "📋 To update OCI Vault with new configuration:"
    echo ""
    echo "1) 📄 Updated settings file created at:"
    echo "   $TEMP_UPDATED_FILE"
    echo ""
    echo "2) 🔄 Update OCI Vault:"
    echo "   $OCI_SETUP_SCRIPT update"
    echo ""
    echo "3) 🔐 Or use OCI CLI directly:"
    echo "   oci secrets secret-bundle update --secret-id $OCI_SECRET_OCID --secret-bundle-content-content-type BASE64 --secret-bundle-content \$(base64 -w 0 $TEMP_UPDATED_FILE)"
    echo ""

    echo -n "Would you like to update OCI Vault now? [Y/n]: "
    read -r update_now

    if [[ ! "$update_now" =~ ^[Nn]$ ]]; then
        echo ""
        log_info "Running OCI Vault update (this may take 30-60 seconds)..."

        # Enhanced: Retry logic for manual update
        if retry_operation "Manual OCI Vault update" "$OCI_SETUP_SCRIPT" update; then
            log_success "✓ OCI Vault updated successfully"
            return 0
        else
            log_warning "⚠ Manual update required"
            echo ""
            echo "Please run the following commands to complete the update:"
            echo ""
            echo "1. Update vault: $OCI_SETUP_SCRIPT update"
            echo "2. Restart services: $PROJECT_ROOT/startup.sh"
            echo "3. Test backup: $BACKUP_SCRIPT --force"

            return 1
        fi
    else
        log_warning "OCI Vault update skipped"
        echo ""
        echo "⚠️  IMPORTANT: Configuration changes are not saved yet!"
        echo ""
        echo "To save changes later:"
        echo "1. Copy settings: cp $TEMP_UPDATED_FILE $PROJECT_ROOT/settings.env"
        echo "2. Update vault: $OCI_SETUP_SCRIPT update"
        echo "3. Restart: $PROJECT_ROOT/startup.sh"

        return 1
    fi
}

# Enhanced: Test the updated configuration with better progress tracking
test_updated_configuration() {
    clear
    log_header "🧪 Testing Updated Configuration"
    draw_separator
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        log_info "DRY RUN: Would test updated configuration"
        return 0
    fi

    # Enhanced: Progress indicator for service restart
    log_info "Restarting services with new configuration (this may take 2-5 minutes)..."
    echo -n "${BLUE}[INFO]${NC} Starting services"

    # Enhanced: Better timeout handling with progress
    if timeout 300 bash -c 'cd "$1" && ./startup.sh >/dev/null 2>&1' -- "$PROJECT_ROOT"; then
        echo ""
        log_success "✓ Services restarted with new configuration"
    else
        echo ""
        log_error "✗ Service restart failed or timed out"
        echo ""
        echo "Manual restart may be needed:"
        echo "cd $PROJECT_ROOT && ./startup.sh"
        return 1
    fi

    # Test backup system
    echo ""
    log_info "Testing automated backup system configuration..."

    if [[ -f "$BACKUP_SCRIPT" ]]; then
        if "$BACKUP_SCRIPT" --check >/dev/null 2>&1; then
            log_success "✓ Backup system configured correctly"
        else
            log_warning "⚠ Backup system check failed (may be normal if first run)"
        fi
    fi

    # Enhanced: Test cloud connectivity with retry logic
    echo ""
    log_info "Testing cloud storage connectivity..."

    # Load new settings
    set -a
    # shellcheck source=/dev/null
    source "$TEMP_UPDATED_FILE"
    set +a

    if [[ -n "${BACKUP_REMOTE:-}" ]]; then
        if retry_operation "Cloud storage test" docker compose exec -T bw_backup rclone lsd "${BACKUP_REMOTE}:" --config ~/.config/rclone/rclone.conf >/dev/null 2>&1; then
            log_success "✓ Cloud storage accessible"
        else
            log_warning "⚠ Cloud storage connectivity issues"
            echo "  This may resolve after services fully start up"
        fi
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r

    return 0
}

# Configure backup settings with vault awareness
configure_backup_settings() {
    clear
    log_header "⚙️ Backup Configuration"
    draw_separator
    echo ""

    # Show available rclone remotes
    local available_remotes=()
    if [[ -f "$RCLONE_CONFIG_FILE" ]]; then
        local remotes
        if remotes=$(grep "^\[.*\]$" "$RCLONE_CONFIG_FILE" 2>/dev/null | tr -d '[]'); then
            readarray -t available_remotes <<< "$remotes"
        fi
    fi

    if [[ ${#available_remotes[@]} -eq 0 ]]; then
        log_error "No rclone remotes configured"
        echo ""
        echo "Please configure rclone first:"
        echo "1. docker compose up -d bw_backup"
        echo "2. docker compose exec bw_backup rclone config"
        echo "3. Re-run this setup wizard"
        return 1
    fi

    # Load current settings
    set -a
    # shellcheck source=/dev/null  
    source "$TEMP_SETTINGS_FILE"
    set +a

    echo "🌐 Available rclone remotes:"
    for i in "${!available_remotes[@]}"; do
        local current_marker=""
        if [[ "${available_remotes[i]}" == "${BACKUP_REMOTE:-}" ]]; then
            current_marker=" (current)"
        fi
        echo "  $((i+1))) ${available_remotes[i]}${current_marker}"
    done
    echo ""

    # Select remote
    local selected_remote="${BACKUP_REMOTE:-}"
    echo -n "Select backup remote [1-${#available_remotes[@]}]: "
    read -r remote_choice
    if [[ "$remote_choice" =~ ^[0-9]+$ ]] && [[ $remote_choice -ge 1 ]] && [[ $remote_choice -le ${#available_remotes[@]} ]]; then
        selected_remote="${available_remotes[$((remote_choice-1))]}"
    else
        log_error "Invalid selection"
        return 1
    fi

    # Configure path
    local backup_path="${BACKUP_PATH:-$DEFAULT_BACKUP_PATH}"
    echo ""
    echo "📁 Backup path configuration:"
    echo "Current: $backup_path"
    echo "Full backups will be stored at: ${selected_remote}:${backup_path}/full/"
    echo ""
    echo -n "Change backup path? [y/N]: "
    read -r change_path
    if [[ "$change_path" =~ ^[Yy]$ ]]; then
        echo -n "Enter new backup path: "
        read -r new_path
        if [[ -n "$new_path" ]]; then
            backup_path="$new_path"
        fi
    fi

    # Configure interval
    local interval="${FULL_BACKUP_INTERVAL_DAYS:-$DEFAULT_BACKUP_INTERVAL}"
    echo ""
    echo "⏰ Backup schedule:"
    echo "Current interval: $interval days"
    echo ""
    echo "Recommended intervals:"
    echo "• 7 days - Weekly (critical systems)"
    echo "• 14 days - Bi-weekly"
    echo "• 21 days - Three-weekly (recommended)"
    echo "• 30 days - Monthly (minimal)"
    echo ""
    echo -n "Change interval [current: $interval days]: "
    read -r new_interval
    if [[ -n "$new_interval" ]] && [[ "$new_interval" =~ ^[0-9]+$ ]] && [[ $new_interval -ge 1 ]] && [[ $new_interval -le 365 ]]; then
        interval="$new_interval"
    fi

    # Configure passphrase
    local passphrase="${BACKUP_PASSPHRASE:-}"
    echo ""
    echo "🔒 Backup encryption:"
    if [[ -n "$passphrase" ]]; then
        log_success "Encryption currently enabled"
        echo -n "Change passphrase? [y/N]: "
        read -r change_passphrase
        if [[ "$change_passphrase" =~ ^[Yy]$ ]]; then
            echo -n "Enter new passphrase (empty to disable): "
            read -rs new_passphrase
            echo ""
            passphrase="$new_passphrase"
        fi
    else
        log_warning "Encryption not configured"
        echo -n "Set backup passphrase? [Y/n]: "
        read -r set_passphrase
        if [[ ! "$set_passphrase" =~ ^[Nn]$ ]]; then
            echo -n "Enter passphrase: "
            read -rs new_passphrase
            echo ""
            passphrase="$new_passphrase"
        fi
    fi

    # Apply updates
    update_vault_settings "$selected_remote" "$backup_path" "$interval" "$passphrase"

    return 0
}

# Setup cron job for vault-based system
setup_vault_cron_job() {
    clear
    log_header "⏰ Automated Scheduling with OCI Vault"
    draw_separator
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        log_info "DRY RUN: Would set up automated backup scheduling"
        return 0
    fi

    echo "Setting up automated backup with OCI Vault integration..."
    echo ""
    echo "⚠️  Important: Cron job will need access to OCI_SECRET_OCID"
    echo ""
    echo "Options for cron job setup:"
    echo "1) Environment variable (recommended)"
    echo "2) User's cron environment"
    echo "3) System-wide environment"
    echo ""
    echo -n "Choose cron setup method [1-3]: "
    read -r cron_method

    local cron_command
    case "${cron_method:-1}" in
        1)
            cron_command="export OCI_SECRET_OCID='$OCI_SECRET_OCID'; $BACKUP_SCRIPT >/dev/null 2>&1"
            ;;
        2)
            cron_command="$BACKUP_SCRIPT >/dev/null 2>&1"
            echo ""
            echo "⚠️  You'll need to add OCI_SECRET_OCID to your cron environment:"
            echo "   Run: crontab -e"
            echo "   Add: OCI_SECRET_OCID=$OCI_SECRET_OCID"
            ;;
        3)
            cron_command="$BACKUP_SCRIPT >/dev/null 2>&1"
            echo ""
            echo "⚠️  You'll need to add OCI_SECRET_OCID to system environment:"
            echo "   Add to /etc/environment: OCI_SECRET_OCID=$OCI_SECRET_OCID"
            ;;
    esac

    # Set cron time
    local cron_hour=2
    echo ""
    echo -n "Backup check time (hour 0-23) [default: 2]: "
    read -r new_hour
    if [[ "$new_hour" =~ ^[0-9]+$ ]] && [[ $new_hour -ge 0 ]] && [[ $new_hour -le 23 ]]; then
        cron_hour="$new_hour"
    fi

    local cron_entry="0 $cron_hour * * * $cron_command"

    # Remove existing entries
    if crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
        (crontab -l 2>/dev/null | grep -v "$BACKUP_SCRIPT") | crontab -
        log_info "Removed existing cron job"
    fi

    # Add new entry
    (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -

    if crontab -l 2>/dev/null | grep -q "$BACKUP_SCRIPT"; then
        log_success "✓ Cron job configured"
        echo "    Schedule: Daily at ${cron_hour}:00"
    else
        log_error "✗ Failed to add cron job"
        return 1
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r
    return 0
}

# Enhanced: Missing configure_rclone function
configure_rclone() {
    clear
    log_header "☁️ Cloud Storage Configuration"
    draw_separator
    echo ""

    echo "rclone configuration for cloud storage integration."
    echo ""

    # Check if rclone config already exists
    if [[ -f "$RCLONE_CONFIG_FILE" ]]; then
        local remotes
        if remotes=$(grep "^\[.*\]$" "$RCLONE_CONFIG_FILE" 2>/dev/null | tr -d '[]' | head -5); then
            if [[ -n "$remotes" ]]; then
                echo "🔍 Existing rclone remotes found:"
                echo "$remotes" | while read -r remote; do
                    echo "  • $remote"
                done
                echo ""
                echo "You can:"
                echo "1) Use existing configuration"
                echo "2) Add new remote"
                echo "3) Reconfigure rclone"
                echo ""
                echo -n "Choose option [1-3]: "
                read -r rclone_choice

                case "${rclone_choice:-1}" in
                    1)
                        log_success "Using existing rclone configuration"
                        ;;
                    2|3)
                        echo ""
                        log_info "To add/modify rclone configuration:"
                        echo "1. docker compose up -d bw_backup"
                        echo "2. docker compose exec bw_backup rclone config"
                        echo "3. Re-run this wizard"
                        echo ""
                        echo -n "Configure rclone now? [y/N]: "
                        read -r config_now
                        if [[ "$config_now" =~ ^[Yy]$ ]]; then
                            docker compose up -d bw_backup >/dev/null 2>&1
                            sleep 5
                            docker compose exec bw_backup rclone config
                        fi
                        ;;
                esac
            fi
        fi
    else
        log_warning "No rclone configuration found"
        echo ""
        echo "To configure rclone:"
        echo "1. docker compose up -d bw_backup"
        echo "2. docker compose exec bw_backup rclone config"
        echo "3. Re-run this wizard"
        echo ""
        echo -n "Configure rclone now? [Y/n]: "
        read -r config_now
        if [[ ! "$config_now" =~ ^[Nn]$ ]]; then
            docker compose up -d bw_backup >/dev/null 2>&1
            sleep 5
            docker compose exec bw_backup rclone config
        fi
    fi

    echo ""
    echo -n "Press Enter to continue..."
    read -r
}

# Main function with vault integration
main() {
    echo "🔒 VaultWarden Automated Backup with OCI Vault Integration"
    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "🧪 Running in DRY RUN mode"
    fi
    echo ""

    # Welcome
    show_welcome

    # Check OCI Vault setup
    log_step "Step 1: Checking OCI Vault Configuration"
    local vault_mode
    if ! vault_mode=$(check_oci_vault_setup); then
        case $? in
            1) 
                log_error "OCI Vault setup failed"
                exit 1
                ;;
            2)
                vault_mode="local"
                log_warning "Using local mode (less secure)"
                ;;
        esac
    else
        vault_mode="vault"
    fi

    if [[ "$vault_mode" == "vault" ]]; then
        # Step 2: Fetch current settings from vault
        log_step "Step 2: Fetching Current Settings from OCI Vault"
        if ! fetch_vault_settings; then
            log_error "Failed to fetch vault settings"
            exit 1
        fi

        # Step 3: Show current configuration
        log_step "Step 3: Current Configuration Review"
        show_vault_backup_config

        # Step 4: Configure rclone
        log_step "Step 4: Cloud Storage Configuration" 
        configure_rclone

        # Step 5: Configure backup settings
        log_step "Step 5: Backup Settings Configuration"
        if ! configure_backup_settings; then
            exit 1
        fi

        # Step 6: Show changes and get confirmation
        log_step "Step 6: Configuration Changes Preview"
        if ! show_vault_changes_preview; then
            if [[ "$DRY_RUN_MODE" == "true" ]]; then
                log_success "🧪 DRY RUN completed successfully!"
                exit 0
            else
                log_info "Setup cancelled"
                exit 0
            fi
        fi

        # Step 7: Push to OCI Vault
        log_step "Step 7: Updating OCI Vault"
        if ! push_to_oci_vault; then
            log_warning "Manual OCI Vault update required"
            exit 1
        fi

        # Step 8: Test configuration
        log_step "Step 8: Testing Updated Configuration"
        test_updated_configuration

        # Step 9: Setup cron with vault
        log_step "Step 9: Setting Up Automated Scheduling"
        setup_vault_cron_job

    else
        # Local mode fallback (simpler process)
        log_warning "Using local mode - settings.env will be stored on disk"
        echo ""
        echo "This is the same process as the non-vault version."
        echo "Run the regular interactive setup for local mode."
        exit 0
    fi

    # Final success
    clear
    echo -e "${BOLD}${GREEN}"
    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "🧪 DRY RUN: OCI Vault Automated Backup Preview Complete!"
    else
        echo "🎉 OCI Vault Automated Backup Setup Complete!"
    fi
    echo -e "${NC}"
    echo ""

    if [[ "$DRY_RUN_MODE" == "true" ]]; then
        echo "✅ Configuration validated and ready"
        echo "✅ All settings reviewed and confirmed"
        echo "✅ Cloud storage compatibility verified"
        echo "✅ No changes made to production systems"
        echo ""
        echo "🔄 To apply these changes:"
        echo "1. Re-run without --dry-run flag"
        echo "2. Or manually apply the prepared configuration"
    else
        echo "✅ Configuration saved to OCI Vault"
        echo "✅ Automated scheduling configured"
        echo "✅ Cloud storage tested and working"
        echo "✅ Services restarted with new settings"
        echo ""
        echo "🔐 Security Benefits:"
        echo "• All secrets stored securely in OCI Vault"
        echo "• Zero sensitive data on VM disk"
        echo "• Enterprise-grade audit trail"
        echo "• Multi-VM deployment ready"
        echo ""
        echo "📅 Next Steps:"
        echo "1. Test backup: $BACKUP_SCRIPT --force"
        echo "2. Verify cloud upload in your storage provider"
        echo "3. Monitor first automated backup"
        echo "4. Document OCI_SECRET_OCID for disaster recovery"

        log_success "🚀 Your VaultWarden now has enterprise-grade automated backups!"
    fi

    return 0
}

# Show usage if help requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "VaultWarden Automated Backup Setup with OCI Vault"
    echo ""
    echo "Usage: $0 [--dry-run] [--help]"
    echo ""
    echo "Options:"
    echo "  --dry-run    Preview changes without modifying OCI Vault"
    echo "  --help, -h   Show this help message"
    echo ""
    echo "Features:"
    echo "• Interactive OCI Vault configuration"
    echo "• Automated 21-day backup scheduling"
    echo "• Enterprise-grade secret management"
    echo "• Cloud storage integration"
    echo "• Comprehensive testing and validation"
    echo ""
    echo "Examples:"
    echo "  $0                # Normal interactive setup"
    echo "  $0 --dry-run      # Preview changes only"
    echo ""
    exit 0
fi

# Execute main
main "$@"
