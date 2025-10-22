#!/usr/bin/env bash
# lib/install.sh - Package installation orchestrator for VaultWarden setup

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing (only if needed) ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[install.sh][INFO] $*"; }
    log_warn() { echo "[install.sh][WARN] $*"; }
    log_error() { echo "[install.sh][ERROR] $*" >&2; }
    log_success() { echo "[install.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi

# Source dependency management library (essential for this script)
DEPS_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/deps.sh" ]]; then
    source "$LIB_DIR/deps.sh"
    DEPS_LIB_AVAILABLE=true
else
    log_error "CRITICAL: Dependency library (lib/deps.sh) not found!"
    exit 1 # Cannot function without deps library
fi

# Source system library (needed by deps.sh)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then
    source "$LIB_DIR/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
     log_error "CRITICAL: System library (lib/system.sh) not found! Cannot perform system operations."
     exit 1 # Cannot function without system library
fi


# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "install"

# --- Main Installation Functions ---

# Install required and optional system packages using the deps library.
# This function acts as a high-level wrapper around ensure_dependencies.
# Usage: install_system_packages [auto_mode]
# auto_mode: 'true' (non-interactive, install optionals), 'false' (interactive, prompt for optionals)
install_system_packages() {
    local auto_mode="${1:-false}" # Default to interactive ('false')
    local install_required=true # Assume required installation is needed initially
    local install_optional="$auto_mode" # Install optionals if auto_mode is true

    _log_section "System Package Installation"

    # Check if dependencies library is actually available
    if [[ "$DEPS_LIB_AVAILABLE" != "true" ]]; then
         log_error "Dependency library failed to load. Cannot manage packages."
         return 1
    fi

    # Check if root privileges are available (needed for installation)
    if [[ $EUID -ne 0 ]]; then
         log_error "Root privileges (sudo) are required to install system packages."
         return 1
    fi

    # If not in auto mode, check dependencies first and potentially prompt
    if [[ "$auto_mode" != "true" ]]; then
         log_info "Checking current dependency status..."
         # Run check-only first to see if installation is needed
         if ensure_dependencies false false >/dev/null 2>&1; then
             log_info "All required dependencies are already met."
             install_required=false # No need to run required install step
         else
              # Prompt user to install required packages
              local response="Y" # Default Yes
              read -p "Required dependencies are missing. Install them now? [Y/n]: " -r response_raw
              response=${response_raw:-Y}
              if [[ ! "$response" =~ ^[yY]([eE][sS])?$ ]]; then
                  log_warn "User cancelled installation of required dependencies. System may not function correctly."
                  install_required=false # User declined
              fi
         fi

         # Ask about optional packages if required install is happening or already done
         if [[ "$install_required" == "true" ]] || ensure_dependencies false false >/dev/null 2>&1; then
              local opt_response="Y" # Default Yes
              read -p "Install optional utility packages (htop, ncdu, tree, etc.)? [Y/n]: " -r opt_response_raw
              opt_response=${opt_response_raw:-Y}
              if [[ "$opt_response" =~ ^[yY]([eE][sS])?$ ]]; then
                   install_optional=true
              else
                   install_optional=false
                   log_info "Skipping installation of optional packages."
              fi
         else
              # If required install was cancelled, don't ask about optionals
              install_optional=false
              log_info "Skipping optional packages because required installation was cancelled."
         fi
    else
         log_info("Auto mode enabled: Attempting installation of required and optional packages.")
    fi

    # Call the core dependency management function with the determined flags
    log_info "Running dependency management (Required: $install_required, Optional: $install_optional)..."
    if ! ensure_dependencies "$install_required" "$install_optional"; then
        log_error "Failed to ensure all dependencies were met. Check logs from 'deps' module."
        return 1 # Return failure if ensure_dependencies failed
    fi

    log_success "System package installation process finished successfully."
    return 0
}


# --- Script Execution / Self-Test ---

# This script is primarily intended to be sourced by tools/install-deps.sh or similar.
# Direct execution can serve as a test.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _log_warning "lib/install.sh is a library and should typically be sourced, not executed directly."
    _log_info "Running a test installation of system packages (requires root)..."
    export DEBUG=true # Enable debug for test

    # Example direct execution (requires sudo)
    if [[ $EUID -ne 0 ]]; then
       log_error "Direct execution test requires root privileges (sudo)."
       log_info "Try: sudo ./lib/install.sh"
       exit 1
    fi

    # Run in interactive mode ('false') for testing prompts
    if install_system_packages false; then
        log_success "Test installation completed successfully."
        exit 0
    else
        log_error "Test installation FAILED."
        exit 1
    fi
else
     _log_debug "lib/install.sh loaded successfully as a library."
fi
