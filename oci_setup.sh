#!/usr/bin/env bash

# oci_setup.sh - An interactive script to facilitate OCI Vault setup,
# including automatic OCI CLI installation and configuration if needed.

set -euo pipefail

# --- Helper Functions ---

# Install OCI CLI automatically
install_oci_cli() {
    echo "=== Installing OCI CLI ==="
    echo "--> OCI CLI not found. Installing automatically..."
    
    # Detect OS/Distribution
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian
            echo "--> Detected Ubuntu/Debian system"
            echo "--> Installing required dependencies..."
            sudo apt-get update
            sudo apt-get install -y curl python3 python3-pip
            
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS/Oracle Linux
            echo "--> Detected RHEL/CentOS/Oracle Linux system"
            echo "--> Installing required dependencies..."
            sudo yum install -y curl python3 python3-pip
            
        elif command -v dnf &> /dev/null; then
            # Fedora
            echo "--> Detected Fedora system"
            echo "--> Installing required dependencies..."
            sudo dnf install -y curl python3 python3-pip
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo "--> Detected macOS system"
        if ! command -v python3 &> /dev/null; then
            echo "ERROR: Python3 is required but not installed."
            echo "Please install Python3 via Homebrew: brew install python3"
            exit 1
        fi
    fi
    
    # Download and run the official OCI CLI installer
    echo "--> Downloading OCI CLI installer..."
    curl -L -O https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh
    
    echo "--> Running OCI CLI installer with defaults..."
    chmod +x install.sh
    
    # Install with non-interactive defaults
    ./install.sh --accept-all-defaults
    
    # Clean up installer
    rm -f install.sh
    
    # Add to PATH for current session
    export PATH="$HOME/bin:$PATH"
    
    # Verify installation
    if command -v oci &> /dev/null; then
        echo "✓ OCI CLI installed successfully"
        oci --version
        
        # Add permanent PATH update suggestion
        echo ""
        echo "📝 Note: Add the following to your ~/.bashrc or ~/.profile for permanent PATH:"
        echo "export PATH=\"\$HOME/bin:\$PATH\""
        echo ""
        
        # Auto-add to ~/.bashrc if it exists and doesn't already contain the path
        if [[ -f ~/.bashrc ]] && ! grep -q "HOME/bin" ~/.bashrc; then
            echo "--> Adding OCI CLI to ~/.bashrc..."
            echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
            echo "✓ PATH updated in ~/.bashrc"
        fi
        
    else
        echo "ERROR: OCI CLI installation failed or not found in PATH"
        echo "Please install manually: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"
        exit 1
    fi
}

# Check for required system dependencies
check_system_requirements() {
    echo "=== Checking System Requirements ==="
    
    # Check for curl
    if ! command -v curl &> /dev/null; then
        echo "ERROR: curl is required but not installed."
        echo "Please install curl: sudo apt-get install curl (Ubuntu/Debian)"
        exit 1
    fi
    
    # Check for base64
    if ! command -v base64 &> /dev/null; then
        echo "ERROR: base64 is required but not installed."
        echo "This should be available by default on most systems."
        exit 1
    fi
    
    echo "✓ System requirements met"
}

# 1. Check for OCI CLI and install if needed, then validate configuration
check_and_setup_cli() {
    echo "=== OCI CLI Setup ==="
    
    # Check if OCI CLI is installed
    if ! command -v oci &> /dev/null; then
        echo "--> OCI CLI not found in PATH"
        
        # Ask user if they want automatic installation
        read -p "Would you like to install OCI CLI automatically? (Y/n): " install_choice
        if [[ "$install_choice" =~ ^[Nn]$ ]]; then
            echo "Aborting. Please install OCI CLI manually before running this script."
            echo "See: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"
            exit 1
        fi
        
        install_oci_cli
    else
        echo "✓ OCI CLI found: $(oci --version)"
    fi
    
    # Check for a valid, working configuration
    echo "--> Checking OCI CLI configuration..."
    if oci os ns get > /dev/null 2>&1; then
        echo "✓ OCI CLI is installed and configured."
    else
        echo "--> OCI CLI is installed, but a working configuration was not found."
        read -p "Would you like to run 'oci setup config' now? (y/N): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            echo "---"
            echo "🔧 You will now be guided through the OCI setup process."
            echo "You will need the following information from your OCI console:"
            echo " - User OCID"
            echo " - Tenancy OCID" 
            echo " - Your OCI Region"
            echo ""
            echo "💡 For help finding these, see:"
            echo "   https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliconfigure.htm"
            echo "---"
            
            # Run the interactive setup command
            oci setup config
            
            echo "---"
            echo "Configuration complete. Validating new setup..."
            if oci os ns get > /dev/null 2>&1; then
                echo "✓ New OCI CLI configuration is working successfully."
            else
                echo "ERROR: The OCI CLI configuration is still not working."
                echo "Please run 'oci setup config' again or troubleshoot your setup."
                exit 1
            fi
        else
            echo "Aborting. Please configure the OCI CLI manually before running this script."
            echo "Run: oci setup config"
            exit 1
        fi
    fi
}

# 2. Get the Compartment OCID from the user
select_compartment() {
    echo "=== Compartment Selection ==="
    read -p "Enter the Compartment OCID: " COMPARTMENT_OCID
    
    # Basic validation for an OCID
    if [[ ! "$COMPARTMENT_OCID" =~ ^ocid1\.compartment\.oc1\..*$ ]]; then
        echo "ERROR: Invalid Compartment OCID format."
        echo "Expected format: ocid1.compartment.oc1...."
        exit 1
    fi
    
    echo "✓ Using Compartment OCID: $COMPARTMENT_OCID"
}

# 3. List and select a Vault, or create a new one
select_vault() {
    echo "=== Vault Selection ==="
    echo "--> Fetching existing vaults in the compartment..."
    
    # Use --query to format output as 'DisplayName (OCID)'
    mapfile -t vaults < <(oci kms vault list --compartment-id "$COMPARTMENT_OCID" --all --query "data[].{\"display-name\": \"display-name\", ocid: id}" --output tsv | awk '{print $1 " (" $2 ")"}')
    
    if [ ${#vaults[@]} -gt 0 ]; then
        echo "--> Found existing vaults:"
        PS3="Select a vault (or type '0' to create a new one): "
        select vault_selection in "CREATE NEW VAULT" "${vaults[@]}"; do
            if [[ "$REPLY" == "0" ]]; then
                read -p "Enter a name for the new vault: " new_vault_name
                echo "--> Creating new vault '$new_vault_name'..."
                VAULT_OCID=$(oci kms vault create --compartment-id "$COMPARTMENT_OCID" --display-name "$new_vault_name" --vault-type "DEFAULT" --query "data.id" --raw-output)
                break
            elif [[ -n "$vault_selection" ]]; then
                # Extract the OCID from the selection string "DisplayName (OCID)"
                VAULT_OCID=$(echo "$vault_selection" | grep -o 'ocid1\..*')
                break
            else
                echo "Invalid selection."
            fi
        done
    else
        echo "No existing vaults found."
        read -p "Enter a name for your new vault: " new_vault_name
        echo "--> Creating new vault '$new_vault_name'..."
        VAULT_OCID=$(oci kms vault create --compartment-id "$COMPARTMENT_OCID" --display-name "$new_vault_name" --vault-type "DEFAULT" --query "data.id" --raw-output)
    fi
    
    echo "✓ Using Vault OCID: $VAULT_OCID"
}

# 4. List and select a Key, or create a new one
select_key() {
    echo "=== Encryption Key Selection ==="
    echo "--> Fetching keys in vault..."
    local management_endpoint=$(oci kms vault get --vault-id "$VAULT_OCID" --query "data.\"management-endpoint\"" --raw-output)
    
    mapfile -t keys < <(oci kms management key list --compartment-id "$COMPARTMENT_OCID" --endpoint "$management_endpoint" --all --query "data[].{\"display-name\": \"display-name\", ocid: id}" --output tsv | awk '{print $1 " (" $2 ")"}')
    
    if [ ${#keys[@]} -gt 0 ]; then
        echo "--> Found existing keys:"
        PS3="Select a key (or type '0' to create a new one): "
        select key_selection in "CREATE NEW KEY" "${keys[@]}"; do
            if [[ "$REPLY" == "0" ]]; then
                read -p "Enter a name for the new key: " new_key_name
                echo "--> Creating new AES-256 key '$new_key_name'..."
                KEY_OCID=$(oci kms management key create --compartment-id "$COMPARTMENT_OCID" --display-name "$new_key_name" --key-shape '{"algorithm":"AES","length":"32"}' --endpoint "$management_endpoint" --query "data.id" --raw-output)
                break
            elif [[ -n "$key_selection" ]]; then
                KEY_OCID=$(echo "$key_selection" | grep -o 'ocid1\..*')
                break
            else
                echo "Invalid selection."
            fi
        done
    else
        echo "No existing keys found."
        read -p "Enter a name for your new key: " new_key_name
        echo "--> Creating new AES-256 key '$new_key_name'..."
        KEY_OCID=$(oci kms management key create --compartment-id "$COMPARTMENT_OCID" --display-name "$new_key_name" --key-shape '{"algorithm":"AES","length":"32"}' --endpoint "$management_endpoint" --query "data.id" --raw-output)
    fi
    
    echo "✓ Using Key OCID: $KEY_OCID"
}

# 5. Manage the secret: create or update
manage_secret() {
    echo "=== Secret Management ==="
    read -p "Enter the name for your secret (e.g., 'vaultwarden-settings'): " SECRET_NAME
    read -p "Enter the path to the file to upload (e.g., ./settings.env): " FILE_PATH
    
    if [ ! -f "$FILE_PATH" ]; then
        echo "ERROR: File not found at '$FILE_PATH'."
        echo "Please ensure your settings.env file exists and is properly configured."
        exit 1
    fi
    
    # Validate file content (basic check)
    if [ ! -s "$FILE_PATH" ]; then
        echo "ERROR: File '$FILE_PATH' is empty."
        exit 1
    fi
    
    echo "--> Processing file: $FILE_PATH ($(wc -l < "$FILE_PATH") lines)"
    
    # Base64 encode the file content
    local b64_content
    b64_content=$(base64 -w0 "$FILE_PATH")
    
    echo "--> Checking if secret '$SECRET_NAME' already exists..."
    local existing_secret_ocid
    existing_secret_ocid=$(oci vault secret list --compartment-id "$COMPARTMENT_OCID" --name "$SECRET_NAME" --query "data[0].id" --raw-output 2>/dev/null || echo "null")
    
    if [[ -n "$existing_secret_ocid" && "$existing_secret_ocid" != "null" ]]; then
        echo "--> Secret found. Updating existing secret..."
        SECRET_OCID=$existing_secret_ocid
        oci vault secret update --secret-id "$SECRET_OCID" --secret-content "{\"content\":\"$b64_content\",\"encoding\":\"BASE64\"}" --force
        echo "✓ Secret updated successfully"
    else
        echo "--> Secret not found. Creating a new secret..."
        SECRET_OCID=$(oci vault secret create-base64 --compartment-id "$COMPARTMENT_OCID" --secret-name "$SECRET_NAME" --vault-id "$VAULT_OCID" --key-id "$KEY_OCID" --secret-content-content "$b64_content" --query "data.id" --raw-output)
        echo "✓ Secret created successfully"
    fi
    
    if [[ -n "$SECRET_OCID" && "$SECRET_OCID" != "null" ]]; then
        echo "✓ Secret OCID: $SECRET_OCID"
    else
        echo "ERROR: Failed to create or update the secret."
        exit 1
    fi
}

# 6. Log the results and provide usage instructions
log_output() {
    echo "=== Setup Complete ==="
    local log_file="oci_vault_setup_$(date +%Y%m%d_%H%M%S).log"
    
    {
        echo "--- OCI Vault Setup Details ---"
        echo "Timestamp: $(date)"
        echo "Compartment OCID: $COMPARTMENT_OCID"
        echo "Vault OCID: $VAULT_OCID"
        echo "Key OCID: $KEY_OCID"
        echo "Secret Name: $SECRET_NAME"
        echo "Secret OCID: $SECRET_OCID"
        echo "File Path: $FILE_PATH"
        echo "---------------------------------"
    } > "$log_file"
    
    echo "✓ All details saved to $log_file"
    echo ""
    echo "🎉 OCI Vault setup completed successfully!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Export the secret OCID:"
    echo "   export OCI_SECRET_OCID=$SECRET_OCID"
    echo ""
    echo "2. Launch your VaultWarden stack:"
    echo "   ./startup.sh"
    echo ""
    echo "3. Your settings will be securely fetched from OCI Vault on startup"
    echo ""
    echo "💾 Keep your log file safe: $log_file"
}

# --- Main Execution ---
main() {
    echo "🚀 VaultWarden OCI Vault Setup Script"
    echo "======================================"
    echo ""
    
    # Run all setup steps
    check_system_requirements
    check_and_setup_cli
    select_compartment
    select_vault
    select_key
    manage_secret
    log_output
}

# Run main function
main "$@"
