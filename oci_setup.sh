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
    else
        log_error "Cannot access secret - check OCID and permissions"
    fi
}

# [Include all the original oci_setup.sh functions here - install_oci_cli, check_system_requirements, etc.]
# ... (keeping the existing functions for brevity)

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

EOF
}

main() {
    local command="${1:-help}"
    
    case "$command" in
        "setup")
            cmd_setup
            ;;
        "update")
            cmd_update "$2"
            ;;
        "list")
            cmd_list "${2:-}"
            ;;
        "test")
            cmd_test "$2"
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
