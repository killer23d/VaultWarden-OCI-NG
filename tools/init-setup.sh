#!/usr/bin/env bash
# tools/init-setup.sh - One-time initialization with explicit error checks

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
    exit 1
fi
source "lib/logging.sh"

# Additional libraries as needed (add after logging.sh)
source "lib/config.sh" || true # Source config, ignore errors initially as it might not be set up
source "lib/validation.sh" # Needed for input validation
source "lib/sops.sh" # Needed for key generation/SOPS setup
source "lib/security.sh" # Needed for firewall setup

# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---

# --- Help Text ---
usage() {
  cat << EOF
Usage: sudo $0 --domain DOMAIN --email ADMIN_EMAIL [--auto] [--restore-mode]
DESCRIPTION:
  Performs the initial one-time setup for VaultWarden-OCI-NG.
  Generates keys, creates initial configuration files, sets up firewall,
  and prepares the system for the first run. Requires sudo privileges.
OPTIONS:
  --domain DOMAIN       (Required) Your public domain name (e.g., vault.example.com). No protocol!
  --email ADMIN_EMAIL   (Required) Your email for admin/Let's Encrypt.
  --auto                Run non-interactively, assuming defaults.
  --restore-mode        Skips key/config generation if files exist (for recovery).
  --help                Show this help message.
EOF
  exit 1
}

# --- Argument Parsing ---
AUTO=false
DOMAIN_ARG=""
EMAIL_ARG=""
RESTORE_MODE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN_ARG="${2:-}"; shift 2;;
    --email) EMAIL_ARG="${2:-}"; shift 2;;
    --auto) AUTO=true; shift;;
    --restore-mode) RESTORE_MODE=true; shift;;
    --help) usage;; # Call usage function on --help
    *) log_error "Unknown option: $1"; usage;;
  esac
done

# Validate required arguments
if [[ -z "$DOMAIN_ARG" || -z "$EMAIL_ARG" ]]; then
    log_error "Missing required arguments --domain and --email."
    usage
fi

# Validate input formats using functions from lib/validation.sh
if ! validate_domain_format "$DOMAIN_ARG"; then
    log_error "Invalid domain format provided for --domain."
    exit 1
fi
# Re-assign potentially cleaned domain (protocol stripped)
DOMAIN_ARG="$CLEAN_DOMAIN" # Assumes validate_domain_format exports CLEAN_DOMAIN or similar

if ! validate_email_format "$EMAIL_ARG"; then
    log_error "Invalid email format provided for --email."
    exit 1
fi

# --- Helper Functions for Safety ---
mkdir_safe() { local d="$1"; mkdir -p "$d" || { log_error "mkdir failed: $d"; return 1; }; }
cp_safe() { cp "$1" "$2" || { log_error "cp failed: $1 -> $2"; return 1; }; }
chmod_safe() { chmod "$1" "$2" || { log_error "chmod failed: $1 $2"; return 1; }; }
chown_safe() { chown "$1" "$2" || { log_error "chown failed: $1 $2"; return 1; }; }
render_template() {
    local template_file="$1"
    local output_file="$2"
    local vars_to_subst="$3" # e.g., '$VAR1,$VAR2'
    if [[ ! -f "$template_file" ]]; then log_error "Template not found: $template_file"; return 1; fi
    log_info "Rendering template '$template_file' to '$output_file'..."
    # Use envsubst if available
    if command -v envsubst >/dev/null; then
        <"$template_file" envsubst "$vars_to_subst" > "$output_file" || { log_error "envsubst failed for $template_file"; return 1; }
    else
        # Basic sed fallback (less robust)
        local content EscapedEmail EscapedDomain
        content=$(<"$template_file")
        # Escape for sed
        EscapedEmail=$(printf '%s\n' "$ADMIN_EMAIL" | sed 's:[][\\/.^$*]:\\&:g')
        EscapedDomain=$(printf '%s\n' "$DOMAIN_ARG" | sed 's:[][\\/.^$*]:\\&:g')
        # Simple substitution
        content="${content//\$ADMIN_EMAIL/$EscapedEmail}"
        content="${content//\$DOMAIN/$EscapedDomain}"
        # Add more vars if template uses them
        echo "$content" > "$output_file" || { log_error "sed fallback failed for $template_file"; return 1; }
    fi
     log_success "Rendered '$output_file'."
}

# --- Main Initialization Logic ---
main() {
  log_header "VaultWarden-OCI-NG Initial Setup"

  # Ensure running as root
  if [[ $EUID -ne 0 ]]; then
      log_error "This script must be run with sudo privileges."
      exit 1
  fi

  # 1. Create essential directories
  log_info "Creating required directories..."
  local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}" # Get from config or default
  mkdir_safe "secrets/keys" || exit 1
  mkdir_safe "caddy" || exit 1
  mkdir_safe "data/bwdata" || exit 1 # Deprecated local data, but structure might be expected
  mkdir_safe "$state_dir/data/bwdata" || exit 1 # Main persistent data
  mkdir_safe "$state_dir/logs/caddy" || exit 1
  mkdir_safe "$state_dir/logs/fail2ban" || exit 1
  mkdir_safe "$state_dir/backups/db" || exit 1
  mkdir_safe "$state_dir/backups/full" || exit 1
  mkdir_safe "ddclient" || exit 1 # For rendered config

  # 2. Setup .env file
  if [[ ! -f .env ]] || [[ "$RESTORE_MODE" == "false" ]]; then
    log_info "Setting up .env configuration file..."
    if [[ -f settings.env.example ]]; then
      cp_safe settings.env.example .env || exit 1
      # Update DOMAIN and ADMIN_EMAIL in the copied file
      sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN_ARG/" .env || log_warn "Failed to set DOMAIN in .env"
      sed -i "s/^ADMIN_EMAIL=.*/ADMIN_EMAIL=$EMAIL_ARG/" .env || log_warn "Failed to set ADMIN_EMAIL in .env"
      log_success ".env created from template and updated."
    else
      log_warn "settings.env.example not found. Creating basic .env file."
      # Create minimal .env if template missing
      cat > .env <<EOF
# Basic VaultWarden-NG Configuration
PROJECT_STATE_DIR=$state_dir
COMPOSE_PROJECT_NAME=vaultwarden
TZ=UTC
DOMAIN=$DOMAIN_ARG
ADMIN_EMAIL=$EMAIL_ARG
# Add other essential defaults if template is missing
SIGNUPS_ALLOWED=false
INVITATIONS_ALLOWED=true
WEBSOCKET_ENABLED=true
EOF
      log_success "Basic .env file created."
    fi
    chmod_safe 640 .env || exit 1
  else
      log_info ".env file already exists. Skipping creation (--restore-mode)."
  fi
  # Export vars from .env for subsequent steps (like template rendering)
  set -a; source .env; set +a

  # 3. Generate Age Key
  local age_key_file="secrets/keys/age-key.txt"
  if [[ ! -f "$age_key_file" ]] || [[ "$RESTORE_MODE" == "false" ]]; then
    log_info "Generating Age encryption key..."
    age-keygen -o "$age_key_file" || { log_error "age-keygen failed"; exit 1; }
    chmod_safe 600 "$age_key_file" || exit 1
    log_success "Age key generated."
  else
    log_info "Age key file already exists. Skipping generation (--restore-mode)."
    # Ensure permissions are correct even in restore mode
    chmod_safe 600 "$age_key_file" || exit 1
  fi
  # Ensure public key exists
  local age_pubkey_file="secrets/keys/age-public-key.txt"
  if [[ ! -f "$age_pubkey_file" ]] || [[ "$RESTORE_MODE" == "false" ]]; then
       log_info "Generating Age public key..."
       age-keygen -y "$age_key_file" > "$age_pubkey_file" || { log_error "Failed to generate public key"; exit 1; }
       chmod_safe 644 "$age_pubkey_file" || exit 1
  fi
  export AGE_PUBLIC_KEY; AGE_PUBLIC_KEY=$(cat "$age_pubkey_file")

  # 4. Setup SOPS configuration
  local sops_config_file=".sops.yaml"
  local sops_template_file=".sops.yaml.tmpl"
  if [[ ! -f "$sops_config_file" ]] || [[ "$RESTORE_MODE" == "false" ]]; then
       if [[ -f "$sops_template_file" ]]; then
            render_template "$sops_template_file" "$sops_config_file" '${AGE_PUBLIC_KEY}' || exit 1
            chmod_safe 644 "$sops_config_file" || exit 1
       else
            log_error "SOPS template file '$sops_template_file' not found. Cannot create '$sops_config_file'."
            exit 1
       fi
  else
       log_info "SOPS configuration file '$sops_config_file' already exists. Skipping creation (--restore-mode)."
  fi

  # 5. Initialize encrypted secrets file if it doesn't exist
  local secrets_file="secrets/secrets.yaml"
  local secrets_example="secrets/secrets.yaml.example"
  if [[ ! -f "$secrets_file" ]] || [[ "$RESTORE_MODE" == "false" ]]; then
       if [[ -f "$secrets_example" ]]; then
            log_info "Creating initial encrypted secrets file from template..."
            cp_safe "$secrets_example" "$secrets_file" || exit 1
            # Encrypt the template using SOPS rules defined in .sops.yaml
            sops --encrypt --in-place "$secrets_file" || { log_error "Failed to encrypt initial secrets file"; rm -f "$secrets_file"; exit 1; }
            chmod_safe 600 "$secrets_file" || exit 1 # Should SOPS set this? Let's be explicit.
            log_success "Initial secrets file created and encrypted."
            log_warn "IMPORTANT: Edit secrets now using './tools/edit-secrets.sh' to set required passwords/tokens."
       else
            log_error "Secrets example file '$secrets_example' not found. Cannot create initial secrets file."
            # Maybe create an empty secrets file? No, better to fail.
            exit 1
       fi
  else
       log_info "Encrypted secrets file '$secrets_file' already exists. Skipping creation (--restore-mode)."
  fi

  # 6. Setup Caddyfile
  local caddy_file="caddy/Caddyfile"
  if [[ ! -f "$caddy_file" ]] || [[ "$RESTORE_MODE" == "false" ]]; then
    log_info "Creating basic Caddyfile..."
    # Create a basic Caddyfile, assuming advanced one doesn't exist yet
    # The main Caddyfile might be more complex, this is just a fallback/initial setup
    cat > "$caddy_file" <<EOF
# Basic Caddyfile for VaultWarden-NG (will be enhanced by Caddyfile example)
{
  email {$ADMIN_EMAIL}
  # acme_ca https://acme-staging-v02.api.letsencrypt.org/directory # Uncomment for testing
}
https://{$DOMAIN} {
  log {
      output file /var/log/caddy/access.log {
          roll_size 10mb
          roll_keep 5
      }
      format json
  }
  reverse_proxy vaultwarden:8080
  # Add WebSocket proxy if enabled
  reverse_proxy /notifications/hub vaultwarden:3012
}
EOF
    chmod_safe 644 "$caddy_file" || exit 1
    log_success "Basic Caddyfile created."
  else
    log_info "Caddyfile already exists. Skipping creation (--restore-mode)."
  fi
  # Ensure Cloudflare IP import file exists, even if empty initially
  touch caddy/cloudflare-ips.caddy
  chmod_safe 644 caddy/cloudflare-ips.caddy

  # 7. Configure System Security (Firewall, Fail2ban setup)
  # Needs root privileges, call functions from security.sh
  configure_system_security "$AUTO" || exit 1
  # Initial update of Cloudflare IPs for firewall
  update_cloudflare_ufw_allowlist || log_warn "Failed initial Cloudflare IP update for UFW."
  # Setup fail2ban config (copy defaults, enable jails)
  # TODO: Add specific fail2ban setup steps if needed (copying jail.local, etc.)

  # 8. Setup Cron Jobs
  # Needs root privileges, call function from cron.sh
  setup_cron_jobs "$AUTO" || exit 1

  # 9. Final Permissions Fix
  log_info "Setting final project permissions..."
  # Ensure correct ownership (e.g., ubuntu user if run via sudo)
  chown_safe -R "${SUDO_USER:-$(id -u)}:${SUDO_GROUP:-$(id -g)}" "$PROJECT_ROOT" || exit 1
  # Secure permissions using function from security.sh
  secure_project_permissions || exit 1


  log_success "Initialization complete. Run './tools/edit-secrets.sh' to set passwords/tokens, then './startup.sh'."
}

# --- Execute Main Function ---
main
