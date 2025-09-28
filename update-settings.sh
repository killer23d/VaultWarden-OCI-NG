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

echo "Updating existing secret OCID: $SECRET_OCID"
oci vault secret update --secret-id "$SECRET_OCID" --secret-content "{\"content\":\"$(base64 -w0 settings.env)\"}"

echo "Secret updated successfully."
