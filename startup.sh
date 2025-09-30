#!/usr/bin/env bash
# startup.sh -- secure fetch of settings.env into RAM, then start compose
set -euo pipefail

# --- Ensure IP files exist for first run ---
CLOUDFLARE_IP_SCRIPT="./caddy/update_cloudflare_ips.sh"
SKIP_POST_UPDATE=false  # Track if we already updated

if [ -f "$CLOUDFLARE_IP_SCRIPT" ]; then
  # Only run if files don't exist (first run) or if --force-ip-update flag is passed
  if [ ! -f "./caddy/cloudflare_ips.caddy" ] || [ ! -f "./caddy/cloudflare_ips.txt" ] || [ "${1:-}" = "--force-ip-update" ]; then
    echo "--> Generating initial Cloudflare IP files..."
    chmod +x "$CLOUDFLARE_IP_SCRIPT"
    "$CLOUDFLARE_IP_SCRIPT"
    SKIP_POST_UPDATE=true  # We just updated, skip post-start check
  else
    echo "--> Cloudflare IP files exist. Will update after containers start if needed."
  fi
else
  echo "--> INFO: Cloudflare IP update script not found at $CLOUDFLARE_IP_SCRIPT. Skipping."
fi

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

# Process Fail2ban Configuration BEFORE starting containers ---
echo "--> Processing Fail2ban configuration template..."
# Source the settings file from RAM to make variables available for substitution
source "$ENVFILE"
# Use envsubst to replace variables in the template and create the final config
envsubst < ./fail2ban/jail.d/jail.local.template > ./fail2ban/jail.d/jail.local
echo "✓ Fail2ban configuration created."

# run compose using env file in RAM
echo "--> Starting containers..."
docker compose --env-file "$ENVFILE" up -d --remove-orphans

# Now update IPs with running containers (only if we didn't just update)
if [ -f "$CLOUDFLARE_IP_SCRIPT" ] && [ "$SKIP_POST_UPDATE" = false ]; then
  echo "--> Checking for Cloudflare IP updates with running containers..."
  "$CLOUDFLARE_IP_SCRIPT"
elif [ "$SKIP_POST_UPDATE" = true ]; then
  echo "--> Skipping post-start IP check (already updated during pre-start)"
fi

echo "✓ Containers started successfully"
echo "✓ Settings file exists in RAM and will be removed on script exit"
exit 0
