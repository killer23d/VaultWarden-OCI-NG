#!/bin/bash
set -e

# Base64 encode settings.env
echo -n "$(cat settings.env | base64)" > secrets.b64

# Update secret in OCI Vault
oci vault secret update --secret-id <secret-ocid> --secret-content '{"content": "'$(cat secrets.b64)'"}'

# Clean up
rm secrets.b64

echo "settings.env uploaded to OCI Vault."
