#!/usr/bin/env bash
# update-settings.sh
# Usage: ./update-settings.sh <secret-name>  (reads settings.env from local cwd and uploads to OCI Vault)
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <oci-secret-name-or-ocid>"
  exit 2
fi

SECRET_NAME="$1"
if [ ! -f settings.env ]; then
  echo "settings.env not found in current directory"
  exit 2
fi

# encode to base64 inline and upload
b64file=$(mktemp)
trap 'rm -f "$b64file"' EXIT
base64 -w0 settings.env > "$b64file"

# if SECRET_OCID provided, try to use it; otherwise create new secret
if [[ "$SECRET_NAME" == ocid1.* ]]; then
  echo "Updating existing secret OCID: $SECRET_NAME"
  oci vault secret update --secret-id "$SECRET_NAME" --secret-content "{\"content\":\"$(cat "$b64file")\"}"
else
  echo "Creating secret named: $SECRET_NAME"
  # You must set COMPARTMENT_OCID, VAULT_OCID, and KEY_OCID env vars before running
  : "${COMPARTMENT_OCID:?Set COMPARTMENT_OCID env var to upload new secret}"
  : "${VAULT_OCID:?Set VAULT_OCID env var to upload new secret}"
  : "${KEY_OCID:?Set KEY_OCID env var to upload new secret}"
  # Use create-base64 and pass the required IDs
  oci vault secret create-base64 --compartment-id "$COMPARTMENT_OCID" --secret-name "$SECRET_NAME" --vault-id "$VAULT_OCID" --key-id "$KEY_OCID" --secret-content-content "$(cat "$b64file")"
fi

echo "Secret uploaded/updated successfully."
