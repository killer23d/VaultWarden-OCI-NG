#!/usr/bin/env bash
# lib/logging.sh - Simple logging system for VaultWarden-OCI-NG

# Ensure strict mode and error handling
set -euo pipefail

# --- Header Guard ---
if [[ -n "${LOGGING_LIB_LOADED:-}" ]]; then return 0; fi
LOGGING_LIB_LOADED=true

# --- Standardized Library Directory Resolution ---
# No PROJECT_ROOT needed directly in logging.sh, but define for consistency if sourced by others
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)" # Define if needed later

# --- Configuration ---
# Use PROJECT_STATE_DIR if available (sourced elsewhere), otherwise default path.
readonly LOG_FILE="${PROJECT_STATE_DIR:-/var/log/vaultwarden}/system.log"
# Allow overriding log file prefix for specific scripts
_LOG_PREFIX=""

# --- Colors for Console Output ---
# Check if stdout is a terminal
if [[ -t 1 ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[1;33m' # Bold Yellow for Warn
    readonly C_BLUE='\033[0;34m'
    readonly C_CYAN='\033[0;36m'   # Cyan for Debug/Header
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN='' C_BOLD=''
fi

# --- Internal Core Logging Function ---
# Should generally not be called directly from other scripts.
_write_log() {
    # Check if exactly 3 arguments were passed
    if [[ $# -ne 3 ]]; then
        echo "[_write_log internal error] Expected 3 arguments, got $#" >&2
        return 1
    fi
    local level="$1" color="$2" message="$3"
    local timestamp log_line log_dir

    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    # Format: [Timestamp] [LEVEL] [OptionalPrefix] Message
    log_line="[${timestamp}] [${level}] ${_LOG_PREFIX:+${_LOG_PREFIX} }${message}"

    # Write to log file if possible
    log_dir=$(dirname "$LOG_FILE")
    # Check if directory exists and is writable, try creating if not
    if [[ ! -d "$log_dir" ]]; then
         # Try creating (might need sudo if run by non-root initially)
         # Use command -v to check for sudo before attempting
         if command -v sudo > /dev/null && [[ $EUID -ne 0 ]]; then
            sudo mkdir -p "$log_dir" 2>/dev/null || true
         else
             mkdir -p "$log_dir" 2>/dev/null || true
         fi
    fi
    # Check writability again after attempting creation
    if [[ -d "$log_dir" && -w "$log_dir" ]]; then
         # Append to the log file
         echo "$log_line" >> "$LOG_FILE"
    else
         # Fallback: Log failure to write to stderr once per script run?
         # Or just skip file logging silently? Silently for now.
         : # Silently ignore file logging failure
    fi


    # Write formatted message to stderr (standard practice for logs)
    echo -e "${color}[${level}]${C_RESET} ${message}" >&2
}

# --- Internal Debug Logging Function ---
# Logs only if DEBUG=true environment variable is set.
_log_debug() {
    # Check DEBUG variable, default to false if unset or empty
    if [[ "${DEBUG:-false}" == "true" ]]; then
        # Use CYAN for debug messages
        _write_log "DEBUG" "$C_CYAN" "$*"
    fi
}

# --- Internal Prefix Setting Function ---
# Sets a prefix (like [script_name]) for subsequent log messages from the calling script.
_set_log_prefix() {
    # Add brackets if not already present, basic formatting
    local prefix="$1"
    if [[ -n "$prefix" && ! "$prefix" =~ ^\[.*\]$ ]]; then
        _LOG_PREFIX="[$prefix]"
    else
        _LOG_PREFIX="$prefix" # Use as is if already formatted or empty
    fi
    _log_debug "Log prefix set to: ${_LOG_PREFIX:-<none>}" # Log the change in debug mode
}


# --- Public Logging Functions ---
# Use these functions in your scripts.

# Informational messages
log_info() { _write_log "INFO " "$C_BLUE" "$*"; } # Padded level for alignment
# Success messages
log_success() { _write_log "SUCCESS" "$C_GREEN" "$*"; }
# Warning messages (potential issues)
log_warn() { _write_log "WARN " "$C_YELLOW" "$*"; } # Padded level
# Error messages (failures)
log_error() { _write_log "ERROR" "$C_RED" "$*"; }
# Section headers
log_header() { echo -e "\n${C_CYAN}--- ${C_BOLD}${*}${C_RESET}${C_CYAN} ---${C_RESET}\n" >&2; } # To stderr
# Simple key-value pair printing for summaries
_print_key_value() { printf "%-20s: %s\n" "$1" "$2" >&2; } # To stderr

# Logs an error message and provides actionable help text.
log_error_with_help() {
    local error_message="$1"
    local help_suggestion="$2"
    log_error "$error_message"
    log_info "💡 Try: $help_suggestion"
}


# --- Public Aliases for Backward Compatibility ---
# Scripts were incorrectly calling _log_debug and _set_log_prefix.
# These aliases allow those scripts to work without modification, while encouraging
# use of the non-underscored versions in new code.
# log_debug() { _log_debug "$@"; } # Keep commented unless strict compatibility needed
# set_log_prefix() { _set_log_prefix "$@"; } # Keep commented unless strict compatibility needed


# --- Initialization ---
# Ensure log directory exists on first load (best effort)
# _ensure_log_dir is called within _write_log now

# --- Self-Test ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     echo "Running lib/logging.sh self-test..."
     # Define PROJECT_STATE_DIR for test if needed, or rely on default
     # export PROJECT_STATE_DIR="/tmp/vw-log-test"
     export DEBUG=true # Enable debug messages for test
     log_header "Logging Test"
     _set_log_prefix "self-test" # Use internal function for direct test
     log_info "This is an info message."
     log_success "This indicates success."
     log_warn "This is a warning."
     log_error "This is an error."
     _log_debug "This debug message should appear because DEBUG=true." # Use internal for direct test
     log_error_with_help "This is a failure." "This is the suggested fix."
     # Test alias (if enabled)
     # set_log_prefix "alias-test"
     # log_info "Testing alias prefix."
     # Test without prefix
     _set_log_prefix "" # Use internal for direct test
     log_info "Message without prefix."
     echo "Self-test complete. Check console output and '$LOG_FILE' (if writable)."
fi
