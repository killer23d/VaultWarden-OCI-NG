#!/usr/bin/env bash
# lib/deps.sh - Enhanced dependency management with host OS maintenance support

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
    _log_info() { echo "[deps.sh][INFO] $*"; }
    _log_error() { echo "[deps.sh][ERROR] $*" >&2; }
    _log_success() { echo "[deps.sh][SUCCESS] $*"; }
    _log_warn() { echo "[deps.sh][WARN] $*"; }
    _log_debug() { :; } # No-op debug
    _log_section() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi
# Source system library (essential for OS detection, package management)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then
    source "$LIB_DIR/system.sh"
    # system.sh should call _detect_system on source
    if [[ -n "$DETECTED_OS" && "$DETECTED_OS" != "unknown" ]]; then
         SYSTEM_LIB_AVAILABLE=true
         _log_debug "System library loaded successfully."
    else
         log_error "Failed to detect OS via system.sh. Dependency management might fail."
    fi
else
    log_error "CRITICAL: System library (lib/system.sh) not found. Cannot manage dependencies."
    # Exit if system lib is absolutely required? Yes.
    exit 1
fi

# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "deps"

# Core system dependencies - Commands needed for scripts to function
# Moved list definition inside functions to avoid potential issues if sourced multiple times
_define_required_commands() {
    # Define array locally within function scope
    local cmds=(
        "docker"      # Docker CLI
        "curl"        # HTTP client
        "jq"          # JSON processor
        "age"         # Encryption tool
        "sops"        # Secret management wrapper
        "sqlite3"     # Database maintenance
        "tar"         # Archiving
        "gzip"        # Compression
        "flock"       # File locking (util-linux)
        "openssl"     # Crypto tool, random generation
        "awk" "sed" "grep" # Basic text processing
        "date" "stat" "find" "chmod" "chown" "mkdir" "rm" "mv" # Core utils
        "shred"       # Secure deletion (coreutils)
        "envsubst"    # Template rendering (gettext-base)
        "id" "groups" "useradd" "usermod" "chpasswd" # User management (add-console-admin)
        "hostname" "ip" # Network info
        "systemctl" "journalctl" # Systemd interaction
        "ufw"         # Firewall
        "fail2ban-client" # Fail2ban interaction
    )
    # Print space-separated list for caller
    echo "${cmds[@]}"
}
# yq is essential but often manually installed
_define_required_manual_commands() {
    local cmds=("yq")
    echo "${cmds[@]}"
}

# System packages for Ubuntu/Debian - What 'apt install' needs
# Corresponds to commands where applicable, plus services/libraries
_define_required_system_packages() {
    local pkgs=(
        # Docker & Compose
        "docker.io"                 # Provides docker CLI (official Ubuntu package)
        "docker-compose-plugin"     # Provides docker compose (V2) - preferred
        # Core Tools
        "curl"                      # HTTP client
        "jq"                        # JSON processor
        "age"                       # Encryption tool (in Ubuntu 22.04+ repos)
        "sqlite3"                   # DB tool
        "util-linux"                # Provides flock, dmesg, etc.
        "openssl"                   # Crypto tool
        "coreutils"                 # Provides date, stat, shred, etc.
        "findutils"                 # Provides find
        "gawk"                      # Provides awk
        "sed"                       # Provides sed
        "grep"                      # Provides grep
        "gzip"                      # Compression
        "tar"                       # Archiving
        "gettext-base"              # Provides envsubst
        "passwd"                    # Provides useradd, chpasswd etc. (usually core)
        "hostname"                  # Provides hostname command
        "iproute2"                  # Provides ip command
        # Services & Daemons
        "systemd"                   # Init system (usually core)
        "ufw"                       # Firewall service
        "fail2ban"                  # Intrusion prevention service
        "cron"                      # Job scheduler (usually core)
        # Networking & Support
        "ca-certificates"           # Needed for TLS/SSL verification
        "apt-transport-https"       # Needed for HTTPS apt repos
        "gnupg"                     # For signing repos, sometimes GPG usage
        # Potentially needed by other scripts
        "rsync"                     # File sync (used in backups/recovery)
        "dnsutils"                  # Provides dig (troubleshooting)
        "net-tools"                 # Provides netstat (troubleshooting)
        "iputils-ping"              # Provides ping (troubleshooting)
        "git"                       # Needed for initial clone/updates
        "wget"                      # Alternative downloader
    )
    # Check if 'sops' package exists in the repo (unlikely for older Ubuntu)
    if apt-cache show sops >/dev/null 2>&1; then
        _log_debug "'sops' package found in repository, adding to required list."
        pkgs+=("sops")
    else
         _log_debug "'sops' package not found in repository, will require manual install."
    fi
    # Check for 'yq' package (exists in newer Ubuntu)
    if apt-cache show yq >/dev/null 2>&1; then
        _log_debug "'yq' package found in repository, adding to required list."
        pkgs+=("yq")
    else
         _log_debug "'yq' package not found in repository, will require manual install."
    fi

    echo "${pkgs[@]}"
}

# Optional packages (nice to have for manual administration)
_define_optional_packages() {
    local pkgs=(
        "htop"                      # Process viewer
        "ncdu"                      # Disk usage analyzer
        "tree"                      # Directory listing
        "vim"                       # Text editor
        "nano"                      # Text editor
        "less"                      # Pager
        "logrotate"                 # Log management (though docker handles its logs)
        "bc"                        # For calculations in monitoring scripts
        "numfmt"                    # For human-readable numbers in monitoring (coreutils?) - already required
    )
    # Remove duplicates from optional list if also required (e.g. numfmt)
    # This is complex, assume lists are maintained correctly for now.
    echo "${pkgs[@]}"
}

# --- Helper Functions (using system.sh functions) ---

# Install yq if not found (using system lib helpers where possible)
_install_yq() {
    # Use _have_cmd from system.sh
    if _have_cmd yq; then
        _log_debug "yq command found."
        return 0
    fi

    _log_info "Attempting to install yq manually..."
    local yq_version="v4.40.5" # Check for latest stable version periodically
    local yq_binary="/usr/local/bin/yq"
    local arch install_success=false download_url

    # Get architecture using uname -m
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv*) arch="arm" ;; # Generic ARM
        *) _log_error "Unsupported architecture for yq automatic installation: $arch"; return 1 ;;
    esac

    download_url="https://github.com/mikefarah/yq/releases/download/${yq_version}/yq_linux_${arch}"
    _log_debug "Determined yq download URL: $download_url"

    local temp_file
    temp_file=$(mktemp) || { log_error "Failed to create temp file for download."; return 1; }
    trap 'rm -f "$temp_file"' RETURN # Ensure temp file cleanup

    # Use curl or wget for download
    _log_info "Downloading yq from: $download_url"
    if _have_cmd curl; then
        if curl -fsSL "$download_url" -o "$temp_file"; then install_success=true; fi
    elif _have_cmd wget; then
        if wget -q -O "$temp_file" "$download_url"; then install_success=true; fi
    else
        _log_error "Cannot download yq: Neither curl nor wget found."
        return 1
    fi

    if [[ "$install_success" == "true" ]]; then
        _log_debug "Download successful. Installing to $yq_binary..."
        # Use install command (coreutils) for setting permissions and moving
        if install -m 755 "$temp_file" "$yq_binary"; then
            # Verify execution
            if "$yq_binary" --version >/dev/null 2>&1; then
                log_success "yq installed successfully to $yq_binary"
                return 0
            else
                log_error "Downloaded yq binary failed verification. Removing."
                rm -f "$yq_binary" # Use rm, sudo might be needed if install failed partially
                return 1
            fi
        else
            log_error "Failed to install yq binary to $yq_binary. Check permissions."
            # Check if running without sudo needed
            if [[ $EUID -ne 0 ]] && [[ -w "/usr/local/bin" ]]; then log_info "Try running install script with sudo."; fi
            return 1
        fi
    else
        log_error "Failed to download yq from $download_url"
        return 1
    fi
}

# Install SOPS if not found via package manager (common)
_install_sops() {
     if _have_cmd sops; then
        _log_debug "sops command found."
        return 0
    fi

    _log_info "Attempting to install SOPS manually..."
    local sops_version="v3.8.1" # Check for latest stable version periodically
    local sops_binary="/usr/local/bin/sops"
    local arch install_success=false download_url

    arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) _log_error "Unsupported architecture for SOPS automatic installation: $arch"; return 1 ;;
    esac

    # Adjust URL format based on SOPS releases
    download_url="https://github.com/getsops/sops/releases/download/${sops_version}/sops-${sops_version}.linux.${arch}"
    _log_debug "Determined SOPS download URL: $download_url"

    local temp_file
    temp_file=$(mktemp) || { log_error "Failed to create temp file for SOPS download."; return 1; }
    trap 'rm -f "$temp_file"' RETURN

    _log_info "Downloading SOPS from: $download_url"
    if _have_cmd curl; then
         if curl -fsSL "$download_url" -o "$temp_file"; then install_success=true; fi
    elif _have_cmd wget; then
         if wget -q -O "$temp_file" "$download_url"; then install_success=true; fi
    else
         _log_error "Cannot download SOPS: Neither curl nor wget found."
         return 1
    fi

     if [[ "$install_success" == "true" ]]; then
          _log_debug "Download successful. Installing SOPS to $sops_binary..."
          if install -m 755 "$temp_file" "$sops_binary"; then
             if "$sops_binary" --version >/dev/null 2>&1; then
                 log_success "SOPS installed successfully to $sops_binary"
                 return 0
             else
                 log_error "Downloaded SOPS binary failed verification. Removing."
                 rm -f "$sops_binary"
                 return 1
             fi
         else
             log_error "Failed to install SOPS binary to $sops_binary. Check permissions."
             return 1
         fi
     else
         _log_error "Failed to download SOPS from $download_url"
         return 1
     fi
}

# Check all required dependencies (commands and packages)
# Uses _have_cmd and _is_package_installed from system.sh
check_required_deps() {
    log_info "Checking required dependencies..."
    local missing_commands=() missing_packages=() missing_manual=() overall_missing=false errors=0

    # Ensure system library loaded correctly
    if [[ "$SYSTEM_LIB_AVAILABLE" != "true" ]]; then
         log_error "System library not available. Cannot perform checks."
         return 1
    fi

    # Define lists using helper functions
    local req_cmds req_pkgs req_man_cmds
    req_cmds=$(_define_required_commands)
    req_pkgs=$(_define_required_system_packages)
    req_man_cmds=$(_define_required_manual_commands)

    _log_debug "Checking essential commands: $req_cmds"
    for cmd in $req_cmds; do
        if ! _have_cmd "$cmd"; then
            _log_debug("Command missing: $cmd")
            missing_commands+=("$cmd")
            overall_missing=true
        fi
    done
     _log_debug "Checking manual commands: $req_man_cmds"
     for cmd in $req_man_cmds; do
         if ! _have_cmd "$cmd"; then
              _log_debug("Manual command missing: $cmd")
             missing_manual+=("$cmd")
             overall_missing=true
         fi
     done

    _log_debug "Checking required system packages (using '$PACKAGE_MANAGER')..."
    # Only check packages if package manager is known and supported (apt for now)
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        for package in $req_pkgs; do
            # Simple check using _is_package_installed from system.sh
            if ! _is_package_installed "$package"; then
                 _log_debug("Package missing: $package")
                 # Check if this package provides a command we already found missing (avoid duplicate reports)
                 # This mapping is complex, skip for now - might report missing package AND missing command
                 missing_packages+=("$package")
                 overall_missing=true
            fi
        done
    elif [[ -n "$PACKAGE_MANAGER" ]]; then
         log_warn "Package manager '$PACKAGE_MANAGER' detected, but only 'apt' package checks are fully implemented."
         log_info "Relying primarily on command checks."
    else
         log_error "Cannot determine package manager. Cannot verify system packages."
         # Assume commands must be present if package manager check skipped
         errors=1 # Mark as error state
    fi


    # Report results
    if [[ "$overall_missing" == "false" && $errors -eq 0 ]]; then
        log_success "All required dependencies appear to be satisfied."
        return 0
    else
        log_error "Missing dependencies detected:"
        [[ ${#missing_commands[@]} -gt 0 ]] && log_error "  Missing commands (need installation or PATH adjustment): ${missing_commands[*]}"
        [[ ${#missing_manual[@]} -gt 0 ]] && log_error "  Missing commands (require manual install attempt): ${missing_manual[*]}"
        [[ ${#missing_packages[@]} -gt 0 ]] && log_error "  Missing packages (install via '$PACKAGE_MANAGER'): ${missing_packages[*]}"
        [[ $errors -gt 0 ]] && log_error "  System check errors occurred (e.g., package manager unknown)."
        return 1
    fi
}

# Install missing dependencies automatically (Debian/Ubuntu focused)
# Uses _install_package from system.sh
install_missing_deps() {
    _log_section "Installing Missing Required Dependencies"
    local install_needed=false packages_to_install=() install_errors=0 manual_install_errors=0

    # Ensure system library loaded correctly
    if [[ "$SYSTEM_LIB_AVAILABLE" != "true" ]]; then
         log_error "System library not available. Cannot install packages."
         return 1
    fi
    # Check if we are root (needed for install)
     if [[ $EUID -ne 0 ]]; then
         log_error "Root privileges are required to install packages."
         return 1
     fi

    # Check which system packages need installation
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
         local req_pkgs
         req_pkgs=$(_define_required_system_packages)
        for package in $req_pkgs; do
            if ! _is_package_installed "$package"; then
                 packages_to_install+=("$package")
                 install_needed=true
            fi
        done
    else
        log_warn "Unsupported package manager '$PACKAGE_MANAGER'. Skipping automatic system package installation."
        log_info "Relying on manual command installs (sops, yq)."
        # Do not fail here, let manual installs proceed
    fi

    # Install system packages if needed
    if [[ "$install_needed" == "true" ]]; then
        log_info "Updating package lists before installation..."
        if ! _update_package_index; then
             log_error "Failed to update package lists ($PACKAGE_MANAGER update failed)."
             log_info "Check network connection and repository configuration."
             return 1
        fi

        log_info "Attempting to install missing required system packages: ${packages_to_install[*]}"
        # Install packages one by one for better error reporting? No, batch install is faster.
        # Use _install_package loop or direct apt call? Direct call is simpler.
        local apt_cmd=("apt-get" "install" "-y" "-qq" "--no-install-recommends") # Use recommends? Maybe safer. Remove --no-install-recommends for now.
        apt_cmd=("apt-get" "install" "-y" "-qq")
        if ! DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" "${packages_to_install[@]}"; then
            log_error "Failed to install one or more required system packages via $PACKAGE_MANAGER."
            log_info "Run 'sudo $PACKAGE_MANAGER update && sudo $PACKAGE_MANAGER install -y ${packages_to_install[*]}' manually to diagnose."
            ((install_errors++))
        else
            log_success "Required system packages installed successfully via $PACKAGE_MANAGER."
        fi
    elif [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        log_info "All required system packages (checked via $PACKAGE_MANAGER) are already installed."
    fi

    # Attempt manual installs for tools not always in repos (sops, yq)
    # Check first if they were installed via package manager successfully
    _install_yq || { log_error "Manual installation of yq failed."; ((manual_install_errors++)); }
    _install_sops || { log_error "Manual installation of SOPS failed."; ((manual_install_errors++)); }

    # Final result
    if [[ $install_errors -eq 0 && $manual_install_errors -eq 0 ]]; then
         log_success "Dependency installation process completed."
         return 0
    else
         log_error "Dependency installation finished with errors (System: $install_errors, Manual: $manual_install_errors)."
         return 1
    fi
}


# Install optional nice-to-have packages
# Uses _install_package from system.sh
install_optional_deps() {
    _log_section "Installing Optional Packages"
    local install_needed=false packages_to_install=()

    # Ensure system library loaded correctly and root privileges
    if [[ "$SYSTEM_LIB_AVAILABLE" != "true" ]]; then log_warn "System library unavailable. Cannot install optional packages."; return 0; fi
    if [[ $EUID -ne 0 ]]; then log_warn "Root privileges required to install optional packages. Skipping."; return 0; fi

    # Check which optional packages need installation
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
         local opt_pkgs
         opt_pkgs=$(_define_optional_packages)
        for package in $opt_pkgs; do
            if ! _is_package_installed "$package"; then
                packages_to_install+=("$package")
                 install_needed=true
            fi
        done
    else
        log_warn "Unsupported package manager '$PACKAGE_MANAGER'. Skipping optional package installation."
        return 0 # Not a failure
    fi

    # Install if needed
    if [[ "$install_needed" == "true" ]]; then
        log_info "Attempting to install optional packages: ${packages_to_install[*]}"
        # Update lists first? Generally not needed if required install ran just before.
        # _update_package_index || log_warn "Failed to update package lists before optional install."
        local apt_cmd=("apt-get" "install" "-y" "-qq")
        if ! DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" "${packages_to_install[@]}"; then
             log_warn "Failed to install some optional packages (non-critical)."
             # Log which ones failed if possible (difficult with -qq)
        else
            log_success "Optional packages installed successfully."
        fi
    else
        log_info "All optional packages (checked via $PACKAGE_MANAGER) are already installed."
    fi
    return 0 # Always return success for optional packages
}

# Main dependency check and installation function (public interface)
# Usage: ensure_dependencies [auto_install_mode] [install_optionals_mode]
# Modes: true/false (strings)
# Returns 0 on success (all *required* deps met), 1 on failure.
ensure_dependencies() {
    local auto_install="${1:-false}"    # String 'true' or 'false'
    local install_optionals="${2:-false}" # String 'true' or 'false'
    local check_result=0 required_install_failed=false

    _log_debug "Ensuring dependencies (AutoInstall: $auto_install, InstallOptionals: $install_optionals)"

    # Initial check for required dependencies
    check_required_deps
    check_result=$? # Capture exit code

    # If required dependencies are missing, decide whether to install
    if [[ $check_result -ne 0 ]]; then
        if [[ "$auto_install" == "true" ]]; then
             log_info "Required dependencies missing. Attempting automatic installation..."
             if ! install_missing_deps; then
                 log_error "FATAL: Failed to automatically install all required dependencies."
                 required_install_failed=true # Mark failure
                 # Do not return yet, still check/install optionals if requested
             fi
        else
             log_error "Required dependencies are missing. Installation required."
             log_info "Please install them manually or run the installer script without check-only mode."
             return 1 # Hard fail if required deps are missing and auto-install is off
        fi
    else
         log_info("Initial check found all required dependencies.")
    fi

    # Install optionals if requested (runs even if required install failed, maybe useful?)
    if [[ "$install_optionals" == "true" ]]; then
        log_info "Proceeding with optional package installation..."
        install_optional_deps # Log warnings on failure, but don't cause main function to fail
    else
         _log_debug("Skipping optional package installation.")
    fi

    # Final verification *only if* installation was attempted and didn't fail critically earlier
    if [[ "$auto_install" == "true" && "$required_install_failed" == false ]]; then
         log_info "Performing final verification of required dependencies..."
         if ! check_required_deps; then
              log_error "FATAL: Dependency check failed even after installation attempt."
              return 1
         fi
    elif [[ "$required_install_failed" == true ]]; then
         # If initial required install failed, return failure now
         return 1
    fi


    log_success "Dependency requirements satisfied."
    return 0
}


# --- Self-Test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/deps.sh is a library and should be sourced, not executed directly."
     _log_info "Running self-check..."
     export DEBUG=true # Enable debug for test
     # Example: Run check-only mode
     ensure_dependencies false false
     exit $? # Exit with the status of the check
else
      _log_debug "lib/deps.sh loaded successfully as a library."
fi
