#!/usr/bin/env bash
# startup.sh -- secure fetch of settings.env into RAM, then start compose
set -euo pipefail

# --- New Block: Auto-update Cloudflare IPs ---
# Check for the IP update script and run it if it exists
CLOUDFLARE_IP_SCRIPT="./caddy/update_cloudflare_ips.sh"
if [ -f "$CLOUDFLARE_IP_SCRIPT" ]; then
  echo "--> Found Cloudflare IP update script. Running it now..."
  # Make sure it's executable first
  chmod +x "$CLOUDFLARE_IP_SCRIPT"
  # Run the script
  "$CLOUDFLARE_IP_SCRIPT"
else
  echo "--> INFO: Cloudflare IP update script not found at $CLOUDFLARE_IP_SCRIPT. Skipping."
fi
# --- End of New Block ---

# If OCI_SECRET_OCID is set, fetch from OCI Vault, else use local settings.env
TMPDIR=${TMPDIR:-/dev/shm/bwsettings}
mkdir -p "$TMPDIR"
chmod 700 "$TMPDIR"

ENVFILE="$TMPDIR/settings.env"
cleanup() {
  # securely remove file if shred available; fall back to rm
  if command -v shred >/dev/null 2>&1; then
    shred -u "$ENVFILE" || rm -f "$ENVFILE"
  else
    rm -f "$ENVFILE"
  fi
  # attempt to remove tmpdir
  rmdir "$TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

if [ -n "${OCI_SECRET_OCID:-}" ]; then
  echo "Fetching settings from OCI Vault (OCID: ${OCI_SECRET_OCID})..."
  
  # Validate OCI CLI configuration before attempting to fetch secrets
  if ! command -v oci &> /dev/null; then
    echo "ERROR: OCI CLI is not installed or not in PATH"
    echo "Please install OCI CLI or use local settings.env instead"
    exit 1
  fi
  
  # Test OCI CLI configuration
  if ! oci os ns get > /dev/null 2>&1; then
    echo "ERROR: OCI CLI is not properly configured"
    echo "Run 'oci setup config' or check your configuration"
    echo "Alternatively, remove OCI_SECRET_OCID to use local settings.env"
    exit 1
  fi
  
  # Validate Secret OCID format
  if [[ ! "${OCI_SECRET_OCID}" =~ ^ocid1\.vaultsecret\. ]]; then
    echo "ERROR: Invalid Secret OCID format"
    echo "Expected format: ocid1.vaultsecret.oc1...."
    exit 1
  fi
  
  # Attempt to fetch the secret
  if ! oci vault secret get --secret-id "${OCI_SECRET_OCID}" --raw-output | jq -r '.data."secret-content".content' | base64 -d > "$ENVFILE"; then
    echo "ERROR: Failed to fetch secret from OCI Vault"
    echo "Please verify the Secret OCID and your permissions"
    exit 1
  fi
  
  echo "✓ Successfully fetched settings from OCI Vault"
else
  if [ -f ./settings.env ]; then
    echo "Copying local settings.env into RAM..."
    cp ./settings.env "$ENVFILE"
  else
    echo "ERROR: No settings.env found and OCI_SECRET_OCID not set"
    echo "Either:"
    echo "  1. Copy settings.env.example to settings.env and configure it"
    echo "  2. Set OCI_SECRET_OCID environment variable to use OCI Vault"
    exit 1
  fi
fi

chmod 600 "$ENVFILE"

# Process Fail2ban Configuration ---
echo "--> Processing Fail2ban configuration template..."
# Source the settings file from RAM to make variables available for substitution
source "$ENVFILE"
# Use envsubst to replace variables in the template and create the final config
envsubst < ./fail2ban/jail.d/jail.local.template > ./fail2ban/jail.d/jail.local
echo "✓ Fail2ban configuration created."

# run compose using env file in RAM
docker compose --env-file "$ENVFILE" up -d --remove-orphans

echo "✓ Containers started successfully"
echo "✓ Settings file exists in RAM and will be removed on script exit"
exit 0
