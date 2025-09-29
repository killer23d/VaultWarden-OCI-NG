#!/usr/bin/env bash
# update-settings.sh
# Usage: ./update-settings.sh <oci-secret-ocid>
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <oci-secret-ocid>"
  exit 2
fi

SECRET_OCID="$1"
if [ ! -f settings.env ]; then
  echo "settings.env not found in current directory"
  exit 2
fi

if [[ ! "$SECRET_OCID" == ocid1.* ]]; then
  echo "Error: Invalid OCID format. Please provide a valid secret OCID."
  exit 1
fi

echo "You are about to update the contents of the existing secret in OCI Vault."
echo -e "  \033[1;33mSecret OCID:\033[0m $SECRET_OCID"
echo "This will overwrite the current remote settings with the contents of your local './settings.env' file."
echo ""

# New: Confirmation Prompt
read -p "Are you sure you want to proceed? (y/N): " choice
if [[ ! "$choice" =~ ^[Yy]$ ]]; then
    echo "Update cancelled by user."
    exit 0
fi

echo ""
echo "Updating existing secret..."
oci vault secret update --secret-id "$SECRET_OCID" --secret-content "{\"content\":\"$(base64 -w0 settings.env)\"}"

echo "Secret updated successfully."
