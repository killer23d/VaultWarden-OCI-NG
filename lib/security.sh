#!/usr/bin/env bash
# lib/security.sh - Security utilities with Cloudflare allowlisting and hybrid fail2ban

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/system.sh"

_set_log_prefix "security"

# Update UFW to allow only Cloudflare IP ranges on ports 80/443 while keeping SSH safe
update_cloudflare_ufw_allowlist() {
  if ! command -v ufw >/dev/null 2>&1; then
    _log_warning "UFW not installed; skipping UFW allowlist update."
    return 0
  fi

  # Safety guard: ensure SSH rule exists
  if ! ufw status | grep -Eiq '22/tcp.*ALLOW|OpenSSH'; then
    _log_warning "No explicit SSH rule detected in UFW; adding allow ssh as safety guard."
    ufw allow ssh >/dev/null 2>&1 || true
  fi

  local ipv4_ranges ipv6_ranges
  ipv4_ranges="$(curl -fsSL --connect-timeout 10 https://www.cloudflare.com/ips-v4 || true)"
  ipv6_ranges="$(curl -fsSL --connect-timeout 10 https://www.cloudflare.com/ips-v6 || true)"
  if [[ -z "$ipv4_ranges" && -z "$ipv6_ranges" ]]; then
    _log_error "Failed to fetch Cloudflare IP ranges."
    return 1
  fi

  # Remove only Cloudflare-tagged rules
  local numbered
  numbered="$(ufw status numbered | sed -n 's/^\[\([0-9]\+\)\]\s\+\(.*Cloudflare.*\)$/\1/p' | sort -rn || true)"
  if [[ -n "$numbered" ]]; then
    _log_info "Removing existing Cloudflare-tagged UFW rules..."
    while read -r n; do
      [[ -n "$n" ]] || continue
      yes | ufw delete "$n" >/dev/null 2>&1 || true
    done <<< "$numbered"
  fi

  # Add new Cloudflare ranges
  local count=0
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    ufw allow from "$ip" to any port 80,443 proto tcp comment "Cloudflare IPv4" >/dev/null 2>&1 || true
    ((count++))
  done <<<"$(printf '%s\n' "$ipv4_ranges" | awk 'NF')"

  while read -r ip; do
    [[ -n "$ip" ]] || continue
    ufw allow from "$ip" to any port 80,443 proto tcp comment "Cloudflare IPv6" >/dev/null 2>&1 || true
    ((count++))
  done <<<"$(printf '%s\n' "$ipv6_ranges" | awk 'NF')"

  ufw --force enable >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
  _log_success "UFW updated with $count Cloudflare web rules; SSH remains allowed."
}

# Configure hybrid fail2ban (edge bans via Cloudflare for web, local iptables for SSH)
configure_hybrid_fail2ban() {
  _log_section "Configuring Hybrid Fail2ban (Cloudflare edge + local iptables)"

  local jail_file="$ROOT_DIR/fail2ban/jail.local"
  if [[ ! -f "$jail_file" ]]; then
    _log_warning "Fail2ban jail.local not found at $jail_file"
    return 0
  fi

  local ban_action="iptables-multiport"
  # If Cloudflare token present (via env or SOPS), prefer cloudflare action name present in repo
  if [[ -f "$ROOT_DIR/secrets/.docker_secrets/cloudflare_api_token" ]] \
     || env | grep -q '^CLOUDFLARE_API_TOKEN='; then
    ban_action="cloudflare.conf"
  fi

  # Replace placeholder in jail.local if present
  if grep -q '{{FAIL2BAN_ACTION}}' "$jail_file"; then
    sed -i "s/{{FAIL2BAN_ACTION}}/${ban_action}/g" "$jail_file"
    _log_info "Applied ban action '${ban_action}' to jail.local"
  fi

  # Ensure SSH jail with refined settings (idempotent)
  if ! grep -q '^\[sshd\]' "$jail_file"; then
    cat >>"$jail_file" <<'EOF'

[sshd]
enabled   = true
maxretry  = 3
bantime   = 48h
findtime  = 30m
EOF
    _log_success "Appended SSH jail configuration to jail.local"
  fi
}
