#!/usr/bin/env bash
# tools/install-deps.sh - Install VaultWarden-OCI-NG system dependencies

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Standardized Library Sourcing ---
# Critical library - must exist
if [[ ! -f "lib/logging.sh" ]]; then
    echo "[ERROR] Critical library not found: lib/logging.sh" >&2
    echo "[ERROR] Ensure script is run from project directory or PROJECT_ROOT is correct" >&2
    # Define minimal log functions if logging.sh failed, then exit? No, just exit.
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
# Source deps.sh (provides dependency checking and installation logic)
DEPS_LIB_AVAILABLE=false
if [[ -f "lib/deps.sh" ]]; then
    source "lib/deps.sh"
    DEPS_LIB_AVAILABLE=true
else
    log_error "CRITICAL: Required library not found: lib/deps.sh"
    exit 1
fi
# Source system.sh (needed by deps.sh for package management, OS detection)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "lib/system.sh" ]]; then
    source "lib/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
    log_error "CRITICAL: Required library not found: lib/system.sh (needed by deps.sh)"
    exit 1
fi
# Source validation.sh (optional, for OS check confirmation)
VALIDATION_LIB_AVAILABLE=false
if [[ -f "lib/validation.sh" ]]; then
    source "lib/validation.sh"
    VALIDATION_LIB_AVAILABLE=true
fi


# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Configuration ---
AUTO_MODE=false

# --- Help text ---
show_help() {
    cat << 'EOF'
VaultWarden-OCI-NG Dependency Installer

USAGE:
    sudo ./tools/install-deps.sh [OPTIONS]

DESCRIPTION:
    Installs all required system packages and commands for VaultWarden-OCI-NG using the
    dependency management library (lib/deps.sh). This includes:
    - Docker Engine and Docker Compose plugin
    - Age encryption tool
    - SOPS secret management (manual install if needed)
    - yq YAML processor (manual install if needed)
    - Essential system utilities (curl, jq, sqlite3, coreutils, etc.)
    - Security tools (ufw, fail2ban)

OPTIONS:
    --help          Show this help message
    --auto          Run in non-interactive mode (assume yes for prompts, install optional packages)
    --check-only    Only check if dependencies are met, do not install anything
    --debug         Enable debug logging (set DEBUG=true)

REQUIREMENTS:
    - Supported Linux distribution (Ubuntu 24.04 LTS recommended)
    - Root privileges (run with sudo) for package installation
    - Internet connectivity to download packages

EXAMPLES:
    sudo ./tools/install-deps.sh --auto   # Install all required and optional packages non-interactively
    sudo ./tools/install-deps.sh         # Check dependencies, prompt to install required, prompt for optional
    ./tools/install-deps.sh --check-only # Check dependencies without installing (no sudo needed)
EOF
}

# --- Argument parsing ---
CHECK_ONLY_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --help) show_help; exit 0 ;;
        --auto) AUTO_MODE=true; shift ;;
        --check-only) CHECK_ONLY_MODE=true; shift ;;
        --debug) export DEBUG=true; shift ;; # Enable debug logging
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# --- Prerequisite checks ---
check_prerequisites() {
    log_header "Checking Prerequisites"

    # Check if root is needed and available (only needed for installation, not check-only)
    if [[ "$CHECK_ONLY_MODE" == "false" ]]; then
        if [[ $EUID -ne 0 ]]; then
            # Check if sudo is available
            if ! command -v sudo >/dev/null; then
                 log_error "This script needs root privileges (or sudo) to install packages, but sudo is not found."
                 exit 1
            fi
            # Re-run with sudo if not already root
            log_warn "Root privileges required for installation. Re-running with sudo..."
            # Preserve arguments using "$@"
            exec sudo bash "$0" "$@"
            # exec replaces the current process, so script doesn't continue here if sudo fails
            log_error "Failed to re-run with sudo." # Should not be reached if exec works
            exit 1
        else
             _log_debug("Running as root. Proceeding with installation checks.")
        fi
    else
        _log_debug("Running in check-only mode. Root privileges not required.")
    fi


    # Detect OS using system library function
    if [[ "$SYSTEM_LIB_AVAILABLE" != "true" ]]; then
        log_error "System library failed to load. Cannot reliably detect OS or manage packages."
        exit 1
    fi
    # _detect_system should have run when system.sh was sourced
    if [[ -z "$DETECTED_OS" || "$DETECTED_OS" == "unknown" ]]; then
        log_error "Could not detect operating system. Cannot guarantee dependency compatibility."
        # Allow proceeding with warning? Or exit? Exit for now.
        exit 1
    fi

    # Check OS compatibility using validation library function if available
    if [[ "$VALIDATION_LIB_AVAILABLE" == "true" ]]; then
         if ! _validate_os_compatibility; then
             log_warn "OS validation reported potential incompatibility (Detected: $DETECTED_OS $DETECTED_OS_VERSION)."
             if [[ "$AUTO_MODE" != "true" && "$CHECK_ONLY_MODE" == "false" ]]; then
                 read -p "Continue with installation anyway? (y/N): " -r
                 if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
                     log_info "Installation cancelled by user."
                     exit 0
                 fi
             elif [[ "$CHECK_ONLY_MODE" == "false" ]]; then
                  log_warn "Proceeding with installation on potentially unsupported OS due to --auto flag."
             fi
         fi
    else
         # Basic check if validation lib missing
         case "$DETECTED_OS" in
             ubuntu|debian) log_info "Detected compatible OS family: $DETECTED_OS" ;;
             *) log_warn "Detected OS '$DETECTED_OS' may not be fully supported. Best effort installation." ;;
         esac
    fi


    # Check internet connectivity (only if installing)
    if [[ "$CHECK_ONLY_MODE" == "false" ]]; then
        log_info "Checking internet connectivity..."
        # Use _test_connectivity from system.sh if available
        local connectivity_ok=false
        if declare -f _test_connectivity > /dev/null; then
             _test_connectivity && connectivity_ok=true
        else
            # Fallback using curl/ping
             if curl -fsSL --max-time 10 https://google.com > /dev/null 2>&1 || ping -c 1 -W 5 8.8.8.8 > /dev/null 2>&1; then
                 connectivity_ok=true
             fi
        fi

        if [[ "$connectivity_ok" != "true" ]]; then
             log_error "No internet connectivity detected. Cannot download packages."
             exit 1
        else
             log_success "Internet connectivity check passed."
        fi
    fi

    log_success "Prerequisites check completed."
}


# --- Main execution ---
main() {
    log_header "VaultWarden-OCI-NG Dependency Management"

    # Check prerequisites first
    check_prerequisites || exit 1

    # Use the ensure_dependencies function from deps.sh
    if [[ "$DEPS_LIB_AVAILABLE" != "true" ]]; then
        log_error "Dependency library (lib/deps.sh) is not available. Cannot proceed."
        exit 1
    fi

    if [[ "$CHECK_ONLY_MODE" == "true" ]]; then
        log_info "Running in check-only mode..."
        # Call ensure_dependencies without installation flags
        if ensure_dependencies false false; then
             log_success "All required dependencies are met."
             exit 0
        else
             log_error "One or more required dependencies are missing. Run without --check-only to install."
             exit 1
        fi
    else
        # Installation mode
        log_info "Running in installation mode..."
        local install_required=true # Always install required in this mode
        local install_optional="$AUTO_MODE" # Install optional only if --auto is set

        if [[ "$AUTO_MODE" != "true" ]]; then
             # Confirm installation of required packages
             log_info "Checking required dependencies..."
             # Temporarily run check-only to see what's missing
             if ensure_dependencies false false >/dev/null 2>&1; then
                 log_info "All required dependencies already met."
                 install_required=false # Skip required install step
             else
                  # Prompt user to install required
                  read -p "Required dependencies are missing. Install them now? (Y/n): " -r install_confirm
                  if [[ "$install_confirm" =~ ^[Nn]$ ]]; then
                       log_info "Installation of required dependencies cancelled by user."
                       install_required=false # User chose not to install
                  fi
             fi

             # Ask about optional packages if required are met or user confirmed install
             if [[ "$install_required" == true ]] || ensure_dependencies false false >/dev/null 2>&1; then
                 read -p "Install optional utility packages (htop, ncdu, tree, etc.)? (Y/n): " -r optional_confirm
                 if [[ ! "$optional_confirm" =~ ^[Nn]$ ]]; then # Default yes
                      install_optional=true
                 fi
             fi
        fi

        # Call ensure_dependencies with determined flags
        log_info "Proceeding with installation (Required: $install_required, Optional: $install_optional)..."
        if ensure_dependencies "$install_required" "$install_optional"; then
            log_success "Dependency installation process completed successfully."

            # Add user to docker group if applicable (running with sudo, user isn't root)
            if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
                # Check if user is already in the docker group
                if ! groups "$SUDO_USER" | grep -q '\bdocker\b'; then
                    log_info "Adding user '$SUDO_USER' to the 'docker' group for easier Docker management..."
                    usermod -aG docker "$SUDO_USER" || log_warn "Failed to add user '$SUDO_USER' to docker group."
                    log_warn "User '$SUDO_USER' needs to log out and back in for group changes to take effect."
                else
                     _log_debug "User '$SUDO_USER' is already in the 'docker' group."
                fi
            fi

            exit 0
        else
            log_error "Dependency installation failed. Please review the errors above."
            exit 1
        fi
    fi
}

# --- Script Entry Point ---
# Run main execution logic
main
