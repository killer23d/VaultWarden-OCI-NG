#!/usr/bin/env bash
# lib/constants.sh - Centralized constants for the VaultWarden-OCI-NG project.

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
# No project root needed here, as it defines constants for others
# LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing (only if needed) ---
# This library should generally not source others to avoid circular dependencies.
# Logging might be useful for debugging, but keep it minimal.
# Define minimalist logging functions locally if needed for debugging this file.
_log_debug_constants() { if [[ "${DEBUG:-false}" == "true" ]]; then echo "[constants.sh][DEBUG] $*"; fi }

# --- Library functions follow ---

# --- Header Guard ---
# Prevent multiple sourcing which could lead to errors if variables are redefined
if [[ -n "${CONSTANTS_LIB_LOADED:-}" ]]; then
    _log_debug_constants "Constants library already loaded."
    return 0
fi
CONSTANTS_LIB_LOADED=true
_log_debug_constants "Loading constants library..."

# This file is intended to be sourced by other scripts.
# It contains read-only variables for magic numbers, default values, and fixed strings.

# --- Health & Monitoring ---
readonly DEFAULT_MONITOR_INTERVAL_SECONDS=300
readonly DEFAULT_MAX_CONSECUTIVE_FAILURES=3
readonly HEALTH_CHECK_WAIT_SECONDS=30
readonly SSL_EXPIRY_FAIL_DAYS=7       # Fail health check if cert expires within this many days
readonly SSL_EXPIRY_WARN_DAYS=30      # Warn if cert expires within this many days

# --- Backups ---
readonly DEFAULT_BACKUP_KEEP_DB=14    # Default number of daily DB backups to keep by date
readonly DEFAULT_BACKUP_KEEP_FULL=4   # Default number of weekly Full backups to keep by date
readonly MAX_BACKUP_DISK_PERCENTAGE=40 # Target maximum disk % used by backups before size cleanup

# --- SQLite Maintenance ---
readonly SQLITE_COMMAND_TIMEOUT_SECONDS=600 # 10 minutes timeout for VACUUM etc.

# --- Startup & System ---
readonly DEFAULT_COMPOSE_TIMEOUT_SECONDS=60 # Timeout for docker compose commands
readonly AGE_KEY_PERMISSIONS="600"        # Required permissions for Age private key
readonly DOCKER_SECRETS_DIR_PERMISSIONS="700" # Permissions for temp Docker secrets dir
readonly DOCKER_SECRET_FILE_PERMISSIONS="600" # Permissions for individual Docker secret files

# --- File Paths (relative to project root, used if sourced script sets PROJECT_ROOT) ---
# Note: Scripts sourcing this should define PROJECT_ROOT *before* sourcing constants
# or construct absolute paths based on their own location. These are primarily for reference.
readonly COMPOSE_FILE="docker-compose.yml"
readonly ENV_FILE=".env"
readonly SECRETS_FILE="secrets/secrets.yaml"
readonly SECRETS_EXAMPLE_FILE="secrets/secrets.yaml.example"
readonly AGE_KEY_FILE="secrets/keys/age-key.txt"
readonly PUBLIC_KEY_FILE="secrets/keys/age-public-key.txt"
readonly SOPS_CONFIG_FILE=".sops.yaml"

# --- URLs ---
# Moved Cloudflare IP URLs here for centralization
readonly CF_IPV4_URL="https://www.cloudflare.com/ips-v4"
readonly CF_IPV6_URL="https://www.cloudflare.com/ips-v6"

# --- Misc ---
readonly DEFAULT_EDITOR="nano"


# --- Self-test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "[constants.sh] This is a library of constants and should be sourced, not executed directly." >&2
    echo "[constants.sh] Example constant: DEFAULT_MONITOR_INTERVAL_SECONDS=${DEFAULT_MONITOR_INTERVAL_SECONDS}" >&2
    exit 1 # Indicate error if executed directly
fi

_log_debug_constants "Constants library loaded successfully."
