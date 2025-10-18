#!/usr/bin/env bash
# lib/notifications.sh - Email notification library using msmtp and project config/secrets

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/config.sh"
# sops.sh may be used indirectly via get_secret

_set_log_prefix "notify"

_send_via_msmtp() {
  local subject="$1" body="$2" admin_email="$3" smtp_host="$4" smtp_port="$5" smtp_user="$6" smtp_from="$7" smtp_pass="$8"

  if ! command -v msmtp >/dev/null 2>&1; then
    _log_warning "msmtp not installed; cannot send email notification."
    return 1
  fi

  local tmpcfg
  tmpcfg="$(mktemp)"
  chmod 600 "$tmpcfg"
  cat > "$tmpcfg" <<EOF
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        ~/.msmtp.log

account        vaultwarden
host           ${smtp_host}
port           ${smtp_port}
from           ${smtp_from}
user           ${smtp_user}
password       ${smtp_pass}

account default : vaultwarden
EOF

  {
    echo "To: ${admin_email}"
    echo "Subject: VaultWarden Notify: ${subject}"
    echo "Content-Type: text/plain; charset=UTF-8"
    echo
    echo -e "${body}"
  } | msmtp --file="$tmpcfg" "${admin_email}" 2>/dev/null

  local rc=$?
  rm -f "$tmpcfg"
  return $rc
}

send_notification() {
  local subject="$1"
  local body="$2"

  if ! load_config; then
    _log_error "Failed to load configuration for notifications."
    return 1
  fi

  local admin_email smtp_host smtp_port smtp_user smtp_from smtp_pass
  admin_email="$(get_config_value "ADMIN_EMAIL" 2>/dev/null || echo "")"
  smtp_host="$(get_config_value "SMTP_HOST" 2>/dev/null || echo "")"
  smtp_port="$(get_config_value "SMTP_PORT" 2>/dev/null || echo "587")"
  smtp_user="$(get_config_value "SMTP_USERNAME" 2>/dev/null || echo "$admin_email")"
  smtp_from="$(get_config_value "SMTP_FROM" 2>/dev/null || echo "$admin_email")"

  # Prefer Docker secret at runtime; fall back to SOPS secret if available
  if [[ -f "/run/secrets/smtp_password" ]]; then
    smtp_pass="$(cat /run/secrets/smtp_password)"
  else
    # Best-effort: get_secret available if sops.sh was sourced by config load path
    smtp_pass="$(get_secret "smtp_password" 2>/dev/null || echo "")"
  fi

  if [[ -z "$admin_email" || -z "$smtp_host" || -z "$smtp_pass" ]]; then
    _log_warning "SMTP not fully configured (ADMIN_EMAIL/SMTP_HOST/smtp_password). Skipping email."
    return 1
  fi

  if _send_via_msmtp "$subject" "$body" "$admin_email" "$smtp_host" "$smtp_port" "$smtp_user" "$smtp_from" "$smtp_pass"; then
    _log_success "Email notification sent to $admin_email."
    return 0
  else
    _log_warning "Failed to send email notification."
    return 1
  fi
}
