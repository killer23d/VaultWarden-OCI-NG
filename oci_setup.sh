#!/usr/bin/env bash
# oci_setup.sh - An interactive script to facilitate OCI Vault setup,
# including initial OCI CLI configuration if needed.

set -euo pipefail

# --- Main Functions ---

# 1. Check for OCI CLI and a valid configuration, or guide user through setup.
check_and_setup_cli() {
  if ! command -v oci &> /dev/null; then
    echo "ERROR: The OCI CLI is not installed or not in your PATH."
    echo "Please install it before running this script."
    echo "See: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm"
    exit 1
  fi

  # Check for a valid, working configuration
  if oci os ns get > /dev/null 2>&1; then
    echo "✓ OCI CLI is installed and configured."
  else
    echo "--> OCI CLI is installed, but a working configuration was not found."
    read -p "Would you like to run 'oci setup config' now? (y/N): " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
      echo "---"
      echo "You will now be guided through the OCI setup process."
      echo "You will need the following information from your OCI console:"
      echo "  - User OCID"
      echo "  - Tenancy OCID"
      echo "  - Your OCI Region"
      echo "For help finding these, see: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliconfigure.htm"
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
      exit 1
    fi
  fi
}


# 2. Get the Compartment OCID from the user
select_compartment() {
  read -p "Enter the Compartment OCID: " COMPARTMENT_OCID
  # Basic validation for an OCID
  if [[ ! "$COMPARTMENT_OCID" =~ ^ocid1\.compartment\.oc1\..*$ ]]; then
    echo "ERROR: Invalid Compartment OCID format."
    exit 1
  fi
  echo "✓ Using Compartment OCID: $COMPARTMENT_OCID"
}

# 3. List and select a Vault, or create a new one
select_vault() {
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
  echo "--> Fetching keys in vault..."
  local management_endpoint=$(oci kms vault get --vault-id "$VAULT_OCID" --query "data.\"management-endpoint\"" --raw-output)

  mapfile -t keys < <(oci kms management key list --compartment-id "$COMPARTMENT_OCID" --endpoint "$management_endpoint" --all --query "data[].{\"display-name\": \"display-name\", ocid: id}" --output tsv | awk '{print $1 " (" $2 ")"}')

  if [ ${#keys[@]} -gt 0 ]; then
    echo "--> Found existing keys:"
    PS3="Select a key (or type '0' to create a new one): "
    select key_selection in "CREATE NEW KEY" "${keys[@]}"; do
      if [[ "$REPLY" == "0" ]]; then
        read -p "Enter a name for the new key: " new_key_name
        echo "--> Creating new key '$new_key_name'..."
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
    echo "--> Creating new key '$new_key_name'..."
    KEY_OCID=$(oci kms management key create --compartment-id "$COMPARTMENT_OCID" --display-name "$new_key_name" --key-shape '{"algorithm":"AES","length":"32"}' --endpoint "$management_endpoint" --query "data.id" --raw-output)
  fi
  echo "✓ Using Key OCID: $KEY_OCID"
}

# 5. Manage the secret: create or update
manage_secret() {
  read -p "Enter the name for your secret (e.g., 'vaultwarden-settings'): " SECRET_NAME
  read -p "Enter the path to the file to upload (e.g., ./settings.env): " FILE_PATH

  if [ ! -f "$FILE_PATH" ]; then
    echo "ERROR: File not found at '$FILE_PATH'."
    exit 1
  fi

  # Base64 encode the file content
  local b64_content=$(base64 -w0 "$FILE_PATH")

  echo "--> Checking if secret '$SECRET_NAME' already exists..."
  local existing_secret_ocid=$(oci vault secret list --compartment-id "$COMPARTMENT_OCID" --name "$SECRET_NAME" --query "data[0].id" --raw-output)

  if [[ -n "$existing_secret_ocid" && "$existing_secret_ocid" != "null" ]]; then
    echo "--> Secret found. Updating existing secret."
    SECRET_OCID=$existing_secret_ocid
    oci vault secret update --secret-id "$SECRET_OCID" --secret-content "{\"content\":\"$b64_content\",\"encoding\":\"BASE64\"}" --force
  else
    echo "--> Secret not found. Creating a new secret."
    SECRET_OCID=$(oci vault secret create-base64 --compartment-id "$COMPARTMENT_OCID" --secret-name "$SECRET_NAME" --vault-id "$VAULT_OCID" --key-id "$KEY_OCID" --secret-content-content "$b64_content" --query "data.id" --raw-output)
  fi

  if [[ -n "$SECRET_OCID" ]]; then
    echo "✓ Secret processed successfully."
    echo "✓ Secret OCID: $SECRET_OCID"
  else
    echo "ERROR: Failed to create or update the secret."
    exit 1
  fi
}

# 6. Log the results
log_output() {
  local log_file="oci_vault_setup_$(date +%Y%m%d_%H%M%S).log"
  echo "--- OCI Vault Setup Details ---" > "$log_file"
  echo "Timestamp: $(date)" >> "$log_file"
  echo "Compartment OCID: $COMPARTMENT_OCID" >> "$log_file"
  echo "Vault OCID: $VAULT_OCID" >> "$log_file"
  echo "Key OCID: $KEY_OCID" >> "$log_file"
  echo "Secret Name: $SECRET_NAME" >> "$log_file"
  echo "Secret OCID: $SECRET_OCID" >> "$log_file"
  echo "---------------------------------" >> "$log_file"
  echo "✓ All details saved to $log_file"
}
