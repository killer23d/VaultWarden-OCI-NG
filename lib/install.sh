#!/usr/bin/env bash
# lib/install.sh - Package installation library for VaultWarden setup

set -euo pipefail

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/system.sh"

# Setup constants
readonly REQUIRED_PACKAGES=("docker.io" "docker-compose-plugin" "jq" "curl" "openssl" "age" "wget" "gnupg")
readonly OPTIONAL_PACKAGES=("fail2ban" "ufw" "gettext" "nftables")

# Install required and optional system packages
install_system_packages() {
    local auto_mode="${1:-false}"
    _log_section "Package Installation"

    _update_package_index

    for package in "${REQUIRED_PACKAGES[@]}"; do
        _install_package "$package"
    done

    if [[ "$auto_mode" != "true" ]]; then
        _log_confirm "Install optional security packages (fail2ban, ufw, nftables)?" "Y"
        read -r response
        response=${response:-Y}

        if [[ "$response" =~ ^[yY][eE][sS]?$ ]]; then
            for package in "${OPTIONAL_PACKAGES[@]}"; do
                _install_package "$package"
            done
        fi
    else
        for package in "${OPTIONAL_PACKAGES[@]}"; do
            _install_package "$package"
        done
    fi
}

# Install SOPS and Age tools
install_sops_age_tools() {
    _log_section "Installing SOPS and Age Tools"

    # Install Age if not already installed
    if ! command -v age >/dev/null 2>&1; then
        _log_info "Installing Age encryption tool..."
        _install_package "age"
        _log_success "Age installed successfully"
    else
        _log_info "Age is already installed"
    fi

    # Install SOPS if not already installed
    if ! command -v sops >/dev/null 2>&1; then
        _log_info "Installing latest version of SOPS (Secrets OPerationS)..."
        local sops_binary="/usr/local/bin/sops"
        
        # Dynamically find the latest SOPS release URL for linux amd64
        _log_info "Fetching latest SOPS release information from GitHub..."
        local sops_url
        sops_url=$(curl -s "https://api.github.com/repos/mozilla/sops/releases/latest" | jq -r '.assets[] | select(.name | endswith("linux.amd64")) | .browser_download_url')

        if [[ -z "$sops_url" || "$sops_url" == "null" ]]; then
            _log_error "Could not determine latest SOPS download URL. Please install it manually."
            return 1
        fi
        
        _log_info "Downloading from: $sops_url"

        if wget -q --show-progress -O "$sops_binary" "$sops_url"; then
            chmod +x "$sops_binary"
            local sops_version
            sops_version=$(sops --version 2>/dev/null | head -1)
            _log_success "SOPS installed successfully ($sops_version)"
        else
            _log_error "Failed to download SOPS"
            return 1
        fi
    else
        _log_info "SOPS is already installed ($(sops --version 2>/dev/null | head -1))"
    fi

    # Verify installations
    if ! command -v age >/dev/null 2>&1 || ! command -v sops >/dev/null 2>&1; then
        _log_error "SOPS or Age installation verification failed"
        return 1
    fi

    _log_success "SOPS and Age tools are ready"
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "lib/install.sh loaded successfully"
else
    _log_warning "lib/install.sh should be sourced, not executed directly."
fi