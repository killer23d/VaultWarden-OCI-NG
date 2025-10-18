#!/usr/bin/env bash
# tools/install-deps.sh - Idempotent installer for all system dependencies.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/system.sh"
source "$ROOT_DIR/lib/deps.sh"

_set_log_prefix "install-deps"

_require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    _log_error "This installer must be run as root (use sudo)."
    exit 1
  fi
}

_install_docker_engine() {
  if command -v docker >/dev/null 2>&1; then
    _log_success "Docker already installed: $(docker --version)"
    systemctl enable --now docker >/dev/null 2>&1 || true
    return 0
  fi
  _log_info "Installing Docker Engine..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  _log_success "Docker installed and service started"
}

_install_latest_sops() {
  if command -v sops >/dev/null 2>&1; then
    _log_success "SOPS already installed: $(sops --version | head -n1)"
    return 0
  fi
  _log_info "Installing latest SOPS (linux amd64)..."
  local sops_url
  sops_url="$(curl -fsSL https://api.github.com/repos/mozilla/sops/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux.*amd64|linux.amd64|linux-x86_64")) | .browser_download_url' | head -n1)"
  if [[ -z "$sops_url" || "$sops_url" == "null" ]]; then
    _log_error "Could not resolve SOPS download URL"
    exit 1
  fi
  wget -qO /usr/local/bin/sops "$sops_url"
  chmod +x /usr/local/bin/sops
  _log_success "SOPS installed: $(sops --version | head -n1)"
}

_install_latest_yq() {
  if command -v yq >/dev/null 2>&1; then
    _log_success "yq already installed: $(yq --version)"
    return 0
  fi
  _log_info "Installing latest yq (linux amd64)..."
  local yq_url
  yq_url="$(curl -fsSL https://api.github.com/repos/mikefarah/yq/releases/latest \
    | jq -r '.assets[] | select(.name == "yq_linux_amd64") | .browser_download_url' | head -n1)"
  if [[ -z "$yq_url" || "$yq_url" == "null" ]]; then
    _log_error "Could not resolve yq download URL"
    exit 1
  fi
  wget -qO /usr/local/bin/yq "$yq_url"
  chmod +x /usr/local/bin/yq
  _log_success "yq installed: $(yq --version)"
}

_install_core_packages() {
  _log_section "Installing core/optional packages via $PACKAGE_MANAGER"
  _update_package_index
  local pkgs=(
    jq curl wget gnupg openssl sqlite3 age rclone fail2ban ufw gettext-base nftables msmtp-mta git
  )
  for p in "${pkgs[@]}"; do
    _install_package "$p"
  done
}

_post_install_notes() {
  local current_user="${SUDO_USER:-$USER}"
  if id -nG "$current_user" 2>/dev/null | grep -qw docker; then
    _log_info "User '$current_user' is already in the docker group."
  else
    usermod -aG docker "$current_user" || true
    _log_info "Added '$current_user' to docker group. Re-login is required to take effect."
  fi
}

main() {
  _log_header "VaultWarden-OCI-NG Dependency Installer"
  _require_root
  _detect_system

  _install_core_packages
  _install_docker_engine
  _install_latest_sops
  _install_latest_yq

  _log_section "Validating installed dependencies"
  check_required_deps docker curl jq yq age sops fail2ban-client ufw rclone msmtp

  _post_install_notes
  _log_success "All dependencies installed and validated."
}

main "$@"
