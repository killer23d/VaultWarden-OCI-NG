#!/bin/bash
set -e

# Fetch settings.env from OCI Vault
oci vault secret get --secret-id <secret-ocid> --raw-output | jq -r '.data."secret-content".content' | base64 -d > temp_settings.env

# Export variables in memory
source temp_settings.env

# Run docker compose up -d
docker compose up -d

# Delete the temporary file
rm temp_settings.env

echo "Deployment complete. settings.env fetched, used, and deleted."
