#!/usr/bin/env bash
# tools/update-firewall-rules.sh - Manages Caddy trusted proxies and UFW Cloudflare allowlist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/security.sh" 2>/dev/null || true

_set_log_prefix "firewall-updater"

_have_cmd() { command -v "$1" >/dev/null 2>&1; }

_update_caddy_trusted() {
  if [[ -x "$ROOT_DIR/tools/update-cloudflare-ips.sh" ]]; then
    _log_info "Updating Caddy trusted Cloudflare IPs..."
    "$ROOT_DIR/tools/update-cloudflare-ips.sh" --quiet || _log_warning "Caddy IP update exited with warnings"
  else
    _log_warning "tools/update-cloudflare-ips.sh not found or not executable; skipping Caddy IP update"
  fi
}

_fetch_cf_ranges() {
  local v4 v6
  v4="$(curl -fsSL --connect-timeout 10 https://www.cloudflare.com/ips-v4 || true)"
  v6="$(curl -fsSL --connect-timeout 10 https://www.cloudflare.com/ips-v6 || true)"
  if [[ -z "$v4" && -z "$v6" ]]; then
    _log_error "Failed to fetch Cloudflare IP ranges"
    return 1
  fi
  printf '%s\n' "$v4" | awk 'NF' > /tmp/cf_ipv4.txt
  printf '%s\n' "$v6" | awk 'NF' > /tmp/cf_ipv6.txt
}

_safe_ensure_ssh_rule() {
  if _have_cmd ufw; then
    if ! ufw status | grep -Eiq '22/tcp.*ALLOW|OpenSSH'; then
      _log_warning "No explicit SSH rule detected in UFW; adding allow ssh as safety guard."
      ufw allow ssh >/dev/null 2>&1 || true
    fi
  fi
}

_prune_cf_rules() {
  # Delete only rules with comment "Cloudflare"
  local numbered
  numbered="$(ufw status numbered | sed -n 's/^\[\([0-9]\+\)\]\s\+\(.*Cloudflare.*\)$/\1/p' | sort -rn || true)"
  if [[ -n "$numbered" ]]; then
    _log_info "Removing existing Cloudflare-tagged UFW rules..."
    while read -r n; do
      [[ -n "$n" ]] || continue
      yes | ufw delete "$n" >/dev/null 2>&1 || true
    done <<< "$numbered"
  fi
}

_apply_cf_rules() {
  local count=0
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    ufw allow from "$ip" to any port 80,443 proto tcp comment "Cloudflare IPv4" >/dev/null 2>&1 || true
    ((count++))
  done < /tmp/cf_ipv4.txt

  while read -r ip; do
    [[ -n "$ip" ]] || continue
    ufw allow from "$ip" to any port 80,443 proto tcp comment "Cloudflare IPv6" >/dev/null 2>&1 || true
    ((count++))
  done < /tmp/cf_ipv6.txt
  _log_success "Applied $count Cloudflare UFW rules (80/443)"
}

_update_ufw_allowlist() {
  if ! _have_cmd ufw; then
    _log_warning "UFW not installed; skipping system firewall allowlist."
    return 0
  fi
  _safe_ensure_ssh_rule
  _prune_cf_rules
  _apply_cf_rules
  ufw --force enable >/dev/null 2>&1 || true
  ufw reload >/dev/null 2>&1 || true
}

_cleanup_temp() {
  rm -f /tmp/cf_ipv4.txt /tmp/cf_ipv6.txt 2>/dev/null || true
}

main() {
  _log_header "Updating Cloudflare firewall rules (Caddy + UFW)"
  _update_caddy_trusted
  if _fetch_cf_ranges; then
    _update_ufw_allowlist
  fi
  _cleanup_temp
  _log_success "Firewall rules update complete."
}

main "$@"
