#!/usr/bin/env bash
# lib/security.sh - Security configuration library for VaultWarden setup

set -euo pipefail

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/system.sh"

# Configure system security (UFW, Fail2ban service)
configure_system_security() {
    local auto_mode="${1:-false}"
    _log_section "System Security Configuration"

    if command -v ufw >/dev/null 2>&1; then
        _log_info "Configuring UFW firewall..."

        ufw --force enable >/dev/null 2>&1
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1

        ufw allow ssh >/dev/null 2>&1
        ufw allow 80/tcp >/dev/null 2>&1
        ufw allow 443/tcp >/dev/null 2>&1

        _log_success "UFW firewall configured"

        if [[ "$auto_mode" != "true" ]]; then
            _log_info "Current UFW rules:"
            ufw status numbered
        fi
    fi

    if command -v fail2ban-client >/dev/null 2>&1; then
        _log_info "Enabling fail2ban service..."
        _enable_service "fail2ban"
        _start_service "fail2ban"
        _log_success "fail2ban service enabled (configuration will be loaded from Docker mount)"
    fi
}

# Configure Fail2ban integration with Cloudflare
configure_cloudflare_fail2ban() {
    _log_section "Cloudflare Fail2Ban Integration"

    local cloudflare_conf="$ROOT_DIR/fail2ban/action.d/cloudflare.conf"
    local jail_local_template="$ROOT_DIR/fail2ban/jail.local"
    local jail_local_output="$ROOT_DIR/fail2ban/jail.d/jail.local"
    local fail2ban_action="nftables-multiport"

    if [[ ! -f "$cloudflare_conf" ]] || [[ ! -f "$jail_local_template" ]]; then
        _log_warning "Fail2ban configuration files not found, skipping integration."
        return 0
    fi
    
    _log_info "Rendering fail2ban jail configuration..."
    mkdir -p "$(dirname "$jail_local_output")"
    sed "s/{{FAIL2BAN_ACTION}}/$fail2ban_action/g" "$jail_local_template" > "$jail_local_output"
    _log_success "Fail2ban jail configured to use '$fail2ban_action' action."
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    _log_debug "lib/security.sh loaded successfully"
else
    _log_warning "lib/security.sh should be sourced, not executed directly."
fi