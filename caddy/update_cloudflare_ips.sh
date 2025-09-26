#!/usr/bin/env bash
# /caddy/update_cloudflare_ips.sh
# This script fetches the latest Cloudflare IP ranges and formats them for Caddy.

set -euo pipefail

# The file where Caddy will find the trusted proxy ranges
OUTPUT_FILE="$(dirname "$0")/cloudflare_ips.caddy"

echo "--> Fetching Cloudflare IPs..."

# Fetch IPv4 and IPv6 ranges, combine them, and format for Caddy
(curl -s https://www.cloudflare.com/ips-v4; echo; curl -s https://www.cloudflare.com/ips-v6) \
| awk '{printf "static %s ", $0}' > "$OUTPUT_FILE"

echo "✓ Successfully updated Cloudflare IPs in $OUTPUT_FILE"
