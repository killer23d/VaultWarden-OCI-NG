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
  # requires oci cli authenticated (oci setup config)
  oci vault secret get --secret-id "${OCI_SECRET_OCID}" --raw-output | jq -r '.data."secret-content".content' | base64 -d > "$ENVFILE"
else
  if [ -f ./settings.env ]; then
    echo "Copying local settings.env into RAM..."
    cp ./settings.env "$ENVFILE"
  else
    echo "No settings.env found and OCI_SECRET_OCID not set. Aborting."
    exit 1
  fi
fi

chmod 600 "$ENVFILE"
# run compose using env file in RAM
docker compose --env-file "$ENVFILE" up -d --remove-orphans

echo "Containers started. settings.env exists in RAM and will be removed on script exit."
# Keep script running until user exits — but we will return so trap will delete on exit.
exit 0
