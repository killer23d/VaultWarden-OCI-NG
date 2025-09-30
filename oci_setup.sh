#!/usr/bin/env bash
# oci_setup.sh - OCI Vault setup and management for VaultWarden-OCI

set -euo pipefail

# Source library modules if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
if [[ -f "$SCRIPT_DIR/lib/common.sh" ]]; then
    source "$SCRIPT_DIR/lib/common.sh"
else
    # Basic fallback functions
    log_info() { echo "[INFO] $1"; }
    log_success() { echo "[SUCCESS] $1"; }
    log_warning() { echo "[WARNING] $1" >&2; }
    log_error() { echo "[ERROR] $1" >&2; exit 1; }
fi

# Configuration files
SETTINGS_FILE="./settings.env"
LOG_FILE="/tmp/oci_vault_setup_$(date +%Y%m%d_%H%M%S).log"

# OCI CLI version
OCI_CLI_VERSION="3.39.0"

# Variables for setup
COMPARTMENT_OCID=""
VAULT_OCID=""
KEY_OCID=""
SECRET_OCID=""

# ================================
# SYSTEM REQUIREMENTS
# ================================

check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check for required commands
    local missing_commands=()
    local required_commands=("curl" "jq" "openssl" "base64")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_commands[*]}"
        echo "Please install missing packages and try again"
        exit 1
    fi
    
    # Check for settings.env
    if [[ ! -f "$SETTINGS_FILE" ]]; then
        log_error "settings.env file not found"
        echo "Create $SETTINGS_FILE from settings.env.example first"
        exit 1
    fi
    
    log_success "System requirements check passed"
}

# ================================
# OCI CLI INSTALLATION
# ================================

install_oci_cli() {
    log_info "Installing OCI CLI..."
    
    local temp_dir
    temp_dir=$(mktemp -d)
    
    pushd "$temp_dir" >/dev/null
    
    local arch
    arch=$(uname -m)
    case "$arch" in
        "x86_64") arch="x86_64" ;;
        "aarch64"|"arm64") arch="aarch64" ;;
        *) log_error "Unsupported architecture for OCI CLI: $arch" ;;
    esac
    
    local oci_url="https://github.com/oracle/oci-cli/releases/download/v${OCI_CLI_VERSION}/oci-cli-${OCI_CLI_VERSION}-linux-${arch}.tar.gz"
    
    log_info "Downloading OCI CLI from $oci_url..."
    if ! curl -L "$oci_url" -o oci-cli.tar.gz; then
        log_error "Failed to download OCI CLI"
    fi
    
    tar -xzf oci-cli.tar.gz
    
    # Install OCI CLI
    if sudo ./oci-cli-*/install.sh --accept-all-defaults; then
        log_success "OCI CLI installed successfully"
    else
        log_error "OCI CLI installation failed"
    fi
    
    popd >/dev/null
    rm -rf "$temp_dir"
}

check_and_setup_cli() {
    log_info "Checking OCI CLI installation..."
    
    if command -v oci >/dev/null 2>&1; then
        log_success "OCI CLI is installed: $(oci --version)"
        
        # Check if OCI config exists
        if [[ ! -f "$HOME/.oci/config" ]]; then
            log_info "OCI CLI configuration not found"
            
            cat <<EOF

Before proceeding, you need to set up OCI CLI authentication.
You have two options:

1. Instance Principal (Recommended for OCI compute instances)
   - No configuration needed
   - Uses instance's permissions automatically

2. User Principal (For local development or other environments)
   - Run: oci setup config
   - Follow the prompts to configure authentication

Which would you like to use?
[1] Instance Principal (auto-detect)
[2] User Principal (manual setup)
[3] Skip (I'll configure manually)

EOF
            read -p "Enter choice [1-3]: " auth_choice
            
            case "$auth_choice" in
                1)
                    log_info "Using Instance Principal authentication"
                    export OCI_CLI_AUTH=instance_principal
                    ;;
                2)
                    log_info "Starting OCI CLI configuration..."
                    oci setup config
                    ;;
                3)
                    log_info "Skipping automatic configuration"
                    ;;
                *)
                    log_warning "Invalid choice, using Instance Principal"
                    export OCI_CLI_AUTH=instance_principal
                    ;;
            esac
        fi
    else
        log_info "OCI CLI not found, installing..."
        install_oci_cli
    fi
    
    # Test OCI CLI
    if oci iam region list >/dev/null 2>&1; then
        log_success "OCI CLI is working correctly"
    else
        log_error "OCI CLI authentication failed"
        echo "Please configure OCI CLI with: oci setup config"
        exit 1
    fi
}

# ================================
# OCI RESOURCE SELECTION
# ================================

select_compartment() {
    log_info "Selecting compartment..."
    
    # List available compartments
    local compartments
    compartments=$(oci iam compartment list --output json 2>/dev/null)
    
    if [[ -z "$compartments" ]] || [[ "$compartments" == "null" ]]; then
        log_error "Failed to list compartments"
        echo "Check your OCI CLI configuration and permissions"
        exit 1
    fi
    
    echo ""
    echo "Available compartments:"
    echo "$compartments" | jq -r '.data[] | "\(.name) - \(.id)"' | nl
    
    echo ""
    read -p "Enter the number of the compartment to use: " comp_choice
    
    COMPARTMENT_OCID=$(echo "$compartments" | jq -r ".data[$((comp_choice - 1))].id")
    
    if [[ "$COMPARTMENT_OCID" == "null" ]] || [[ -z "$COMPARTMENT_OCID" ]]; then
        log_error "Invalid compartment selection"
        exit 1
    fi
    
    local comp_name
    comp_name=$(echo "$compartments" | jq -r ".data[$((comp_choice - 1))].name")
    log_success "Selected compartment: $comp_name"
    log_info "Compartment OCID: $COMPARTMENT_OCID"
}

select_vault() {
    log_info "Selecting or creating vault..."
    
    # List existing vaults
    local vaults
    vaults=$(oci kms management vault list --compartment-id "$COMPARTMENT_OCID" --output json 2>/dev/null)
    
    echo ""
    echo "Existing vaults:"
    if [[ $(echo "$vaults" | jq '.data | length') -gt 0 ]]; then
        echo "$vaults" | jq -r '.data[] | "\(.display-name) - \(.id)"' | nl
        echo "$(($(echo "$vaults" | jq '.data | length') + 1)). Create new vault"
    else
        echo "No existing vaults found."
        echo "1. Create new vault"
    fi
    
    echo ""
    read -p "Enter your choice: " vault_choice
    
    local vault_count
    vault_count=$(echo "$vaults" | jq '.data | length')
    
    if [[ $vault_choice -le $vault_count ]] && [[ $vault_count -gt 0 ]]; then
        # Use existing vault
        VAULT_OCID=$(echo "$vaults" | jq -r ".data[$((vault_choice - 1))].id")
        local vault_name
        vault_name=$(echo "$vaults" | jq -r ".data[$((vault_choice - 1))].display-name")
        log_success "Selected existing vault: $vault_name"
    else
        # Create new vault
        echo ""
        read -p "Enter name for new vault: " new_vault_name
        
        if [[ -z "$new_vault_name" ]]; then
            new_vault_name="VaultWarden-Vault"
        fi
        
        log_info "Creating vault: $new_vault_name..."
        
        local vault_response
        vault_response=$(oci kms management vault create \
            --compartment-id "$COMPARTMENT_OCID" \
            --display-name "$new_vault_name" \
            --vault-type DEFAULT \
            --output json 2>/dev/null)
        
        VAULT_OCID=$(echo "$vault_response" | jq -r '.data.id')
        
        if [[ "$VAULT_OCID" == "null" ]] || [[ -z "$VAULT_OCID" ]]; then
            log_error "Failed to create vault"
            exit 1
        fi
        
        log_success "Created vault: $new_vault_name"
        log_info "Waiting for vault to become active..."
        
        # Wait for vault to become active
        local vault_state=""
        while [[ "$vault_state" != "ACTIVE" ]]; do
            sleep 10
            vault_state=$(oci kms management vault get --vault-id "$VAULT_OCID" --output json | jq -r '.data."lifecycle-state"')
            log_info "Vault state: $vault_state"
        done
    fi
    
    log_info "Vault OCID: $VAULT_OCID"
}

select_key() {
    log_info "Selecting or creating encryption key..."
    
    # Get vault management endpoint
    local vault_endpoint
    vault_endpoint=$(oci kms management vault get --vault-id "$VAULT_OCID" --output json | jq -r '.data."management-endpoint"')
    
    # List existing keys
    local keys
    keys=$(oci kms management key list \
        --compartment-id "$COMPARTMENT_OCID" \
        --endpoint "$vault_endpoint" \
        --output json 2>/dev/null)
    
    echo ""
    echo "Existing keys:"
    if [[ $(echo "$keys" | jq '.data | length') -gt 0 ]]; then
        echo "$keys" | jq -r '.data[] | "\(.display-name) - \(.id)"' | nl
        echo "$(($(echo "$keys" | jq '.data | length') + 1)). Create new key"
    else
        echo "No existing keys found."
        echo "1. Create new key"
    fi
    
    echo ""
    read -p "Enter your choice: " key_choice
    
    local key_count
    key_count=$(echo "$keys" | jq '.data | length')
    
    if [[ $key_choice -le $key_count ]] && [[ $key_count -gt 0 ]]; then
        # Use existing key
        KEY_OCID=$(echo "$keys" | jq -r ".data[$((key_choice - 1))].id")
        local key_name
        key_name=$(echo "$keys" | jq -r ".data[$((key_choice - 1))].display-name")
        log_success "Selected existing key: $key_name"
    else
        # Create new key
        echo ""
        read -p "Enter name for new key: " new_key_name
        
        if [[ -z "$new_key_name" ]]; then
            new_key_name="VaultWarden-Key"
        fi
        
        log_info "Creating encryption key: $new_key_name..."
        
        local key_response
        key_response=$(oci kms management key create \
            --compartment-id "$COMPARTMENT_OCID" \
            --display-name "$new_key_name" \
            --endpoint "$vault_endpoint" \
            --key-shape '{"algorithm":"AES","length":32}' \
            --output json 2>/dev/null)
        
        KEY_OCID=$(echo "$key_response" | jq -r '.data.id')
        
        if [[ "$KEY_OCID" == "null" ]] || [[ -z "$KEY_OCID" ]]; then
            log_error "Failed to create key"
            exit 1
        fi
        
        log_success "Created encryption key: $new_key_name"
        log_info "Waiting for key to become enabled..."
        
        # Wait for key to become enabled
        local key_state=""
        while [[ "$key_state" != "ENABLED" ]]; do
            sleep 5
            key_state=$(oci kms management key get --key-id "$KEY_OCID" --endpoint "$vault_endpoint" --output json | jq -r '.data."lifecycle-state"')
            log_info "Key state: $key_state"
        done
    fi
    
    log_info "Key OCID: $KEY_OCID"
}

manage_secret() {
    log_info "Creating secret from settings.env..."
    
    # Get vault secrets endpoint
    local vault_secrets_endpoint
    vault_secrets_endpoint=$(oci kms management vault get --vault-id "$VAULT_OCID" --output json | jq -r '.data."secrets-endpoint"')
    
    # Read settings.env and encode to base64
    local settings_content
    settings_content=$(base64 -w0 "$SETTINGS_FILE")
    
    echo ""
    read -p "Enter name for the secret: " secret_name
    
    if [[ -z "$secret_name" ]]; then
        secret_name="VaultWarden-Settings"
    fi
    
    log_info "Creating secret: $secret_name..."
    
    local secret_response
    secret_response=$(oci vault secret create \
        --compartment-id "$COMPARTMENT_OCID" \
        --secret-name "$secret_name" \
        --vault-id "$VAULT_OCID" \
        --key-id "$KEY_OCID" \
        --endpoint "$vault_secrets_endpoint" \
        --secret-content "{\"content\":\"$settings_content\",\"encoding\":\"BASE64\"}" \
        --output json 2>/dev/null)
    
    SECRET_OCID=$(echo "$secret_response" | jq -r '.data.id')
    
    if [[ "$SECRET_OCID" == "null" ]] || [[ -z "$SECRET_OCID" ]]; then
        log_error "Failed to create secret"
        exit 1
    fi
    
    log_success "Created secret: $secret_name"
    log_info "Secret OCID: $SECRET_OCID"
}

# ================================
# OUTPUT AND LOGGING
# ================================

log_output() {
    log_info "Writing setup information to log file..."
    
    {
        echo "VaultWarden-OCI Vault Setup Log"
        echo "==============================="
        echo "Date: $(date)"
        echo "Host: $(hostname)"
        echo ""
        echo "OCI Resources Created:"
        echo "Compartment OCID: $COMPARTMENT_OCID"
        echo "Vault OCID: $VAULT_OCID"
        echo "Key OCID: $KEY_OCID"
        echo "Secret OCID: $SECRET_OCID"
        echo ""
        echo "Important: Save the SECRET_OCID for your deployment!"
        echo ""
        echo "To retrieve your settings:"
        echo "oci vault secret get --secret-id '$SECRET_OCID' --raw-output | base64 -d"
        echo ""
        echo "To update the secret:"
        echo "$0 update '$SECRET_OCID'"
    } > "$LOG_FILE"
    
    # Also show on screen
    echo ""
    echo "=========================================="
    echo "Setup completed successfully!"
    echo "=========================================="
    echo ""
    echo "IMPORTANT - Save this information:"
    echo "SECRET_OCID: $SECRET_OCID"
    echo ""
    echo "This SECRET_OCID is required for:"
    echo "- Updating the secret: $0 update <SECRET_OCID>"
    echo "- Retrieving configuration in production"
    echo ""
    echo "Full setup details saved to: $LOG_FILE"
    echo ""
    echo "Next steps:"
    echo "1. Update your deployment scripts with the SECRET_OCID"
    echo "2. Test secret retrieval:"
    echo "   oci vault secret get --secret-id '$SECRET_OCID' --raw-output | base64 -d"
    echo ""
}

# ================================
# OCI VAULT MANAGEMENT COMMANDS
# ================================

# Setup new vault and secret
cmd_setup() {
    log_info "Starting OCI Vault setup..."
    
    check_system_requirements
    check_and_setup_cli
    select_compartment
    select_vault
    select_key
    manage_secret
    log_output
}

# Update existing secret
cmd_update() {
    local secret_ocid="${1:-}"
    
    if [[ -z "$secret_ocid" ]]; then
        log_error "Secret OCID is required for update command"
    fi
    
    if [[ ! -f "$SETTINGS_FILE" ]]; then
        log_error "settings.env file not found"
    fi
    
    # Validate OCID format
    if [[ ! "$secret_ocid" =~ ^ocid1\.vaultsecret\. ]]; then
        log_error "Invalid Secret OCID format. Expected: ocid1.vaultsecret...."
    fi
    
    log_info "Updating OCI Vault secret: $secret_ocid"
    echo "This will overwrite the remote secret with your local settings.env file"
    echo ""
    
    read -p "Are you sure you want to proceed? (y/N): " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        echo "Update cancelled."
        exit 0
    fi
    
    log_info "Updating secret..."
    local b64_content
    b64_content=$(base64 -w0 "$SETTINGS_FILE")
    
    if oci vault secret update --secret-id "$secret_ocid" --secret-content "{\"content\":\"$b64_content\",\"encoding\":\"BASE64\"}" --force; then
        log_success "Secret updated successfully"
    else
        log_error "Failed to update secret"
    fi
}

# List existing secrets
cmd_list() {
    local compartment_id="${1:-}"
    
    if [[ -z "$compartment_id" ]]; then
        read -p "Enter Compartment OCID: " compartment_id
    fi
    
    if [[ ! "$compartment_id" =~ ^ocid1\.compartment\. ]]; then
        log_error "Invalid Compartment OCID format"
    fi
    
    log_info "Listing secrets in compartment..."
    oci vault secret list --compartment-id "$compartment_id" --output table --query "data[].{Name:\"secret-name\",OCID:id,State:\"lifecycle-state\"}"
}

# Test secret access
cmd_test() {
    local secret_ocid="${1:-}"
    
    if [[ -z "$secret_ocid" ]]; then
        log_error "Secret OCID is required for test command"
    fi
    
    log_info "Testing secret access: $secret_ocid"
    
    if oci vault secret get --secret-id "$secret_ocid" --raw-output >/dev/null 2>&1; then
        log_success "Secret is accessible"
        echo ""
        echo "To retrieve the secret content:"
        echo "oci vault secret get --secret-id '$secret_ocid' --raw-output | base64 -d"
    else
        log_error "Cannot access secret - check OCID and permissions"
    fi
}

# ================================
# MAIN EXECUTION
# ================================

show_help() {
    cat <<EOF
VaultWarden-OCI Vault Management

Usage: $0 <command> [options]

Commands:
    setup                   Interactive setup of new vault and secret
    update <secret-ocid>    Update existing secret with local settings.env
    list [compartment-ocid] List secrets in compartment
    test <secret-ocid>      Test access to existing secret
    help                    Show this help message

Examples:
    $0 setup                                    # Interactive setup
    $0 update ocid1.vaultsecret.oc1....        # Update existing secret
    $0 list ocid1.compartment.oc1....          # List secrets
    $0 test ocid1.vaultsecret.oc1....          # Test secret access

Requirements:
    - OCI CLI installed and configured
    - settings.env file in current directory
    - Appropriate OCI permissions for Vault operations

For more information:
    https://docs.oracle.com/en-us/iaas/tools/oci-cli/3.39.0/oci_cli_docs/

EOF
}

main() {
    local command="${1:-help}"
    
    case "$command" in
        "setup")
            cmd_setup
            ;;
        "update")
            cmd_update "${2:-}"
            ;;
        "list")
            cmd_list "${2:-}"
            ;;
        "test")
            cmd_test "${2:-}"
            ;;
        "help"|"-h"|"--help"|"")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
