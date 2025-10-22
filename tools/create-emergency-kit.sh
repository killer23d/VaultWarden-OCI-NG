#!/usr/bin/env bash
# tools/create-emergency-kit.sh - Create encrypted emergency access kit for VaultWarden-OCI-NG

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
CONFIG_LOADED_SUCCESS=false
NOTIFICATIONS_AVAILABLE=false
SOPS_AVAILABLE=false # Track sops availability for AGE_KEY_FILE
SYSTEM_AVAILABLE=false # Track system availability for hostname/ip

# Source config first as it defines PROJECT_STATE_DIR etc.
if [[ -f "lib/config.sh" ]]; then
    source "lib/config.sh"
    # Attempt to load config data early
    if load_config >/dev/null 2>&1; then
        CONFIG_LOADED_SUCCESS=true
    else
        log_warn "Failed to load project configuration via lib/config.sh during initial sourcing."
    fi
else
    log_error "CRITICAL: Required library not found: lib/config.sh"
    exit 1
fi

# Source sops library (needed for AGE_KEY_FILE constant)
if [[ -f "lib/sops.sh" ]]; then
    source "lib/sops.sh"
    SOPS_AVAILABLE=true # Mark as available
else
    log_error "CRITICAL: Required library not found: lib/sops.sh"
    exit 1
fi

# Source notifications library (optional, for sending email)
if [[ -f "lib/notifications.sh" ]]; then
    source "lib/notifications.sh"
    NOTIFICATIONS_AVAILABLE=true
else
    log_warn "Optional library not found: lib/notifications.sh. Email sending disabled."
fi

# Source system library (optional, for hostname/ip in docs)
if [[ -f "lib/system.sh" ]]; then
    source "lib/system.sh"
    SYSTEM_AVAILABLE=true
else
    log_warn "Optional library not found: lib/system.sh. Some system info might be missing from docs."
fi


# Set script-specific log prefix
_set_log_prefix "$(basename "$0" .sh)"

# --- Rest of script follows ---


# --- Configuration ---
readonly EMERGENCY_KIT_STAGING_DIR="/tmp/emergency-kit-staging.$$" # Unique temp dir
# Use AGE_KEY_FILE from sops.sh, provide fallback just in case
readonly AGE_KEY_FILE="${AGE_KEY_FILE:-secrets/keys/age-key.txt}"
readonly SECRETS_FILE="${SECRETS_FILE:-secrets/secrets.yaml}" # Use constant from sops.sh if available
# Config variables (DOMAIN, ADMIN_EMAIL) are loaded via load_config()

# --- Help text ---
show_help() {
    cat << EOF
Emergency Access Kit Creator for VaultWarden-OCI-NG

USAGE:
    sudo $0 [OPTIONS] # Sudo might be needed for UFW status check

DESCRIPTION:
    Creates an encrypted emergency access kit containing essential secrets, configuration,
    and recovery documentation needed to restore VaultWarden-OCI-NG from scratch.

    The kit is encrypted with Age using a password (user-provided or auto-generated)
    and should be sent via email (if configured) or saved manually.
    Contains ALL system secrets - treat the generated kit as highly sensitive.

OPTIONS:
    --help                  Show this help message
    --auto-password         Generate a secure random password non-interactively
    --test-mode             Create kit locally but do not attempt to send email
    --output-file FILE      Save the encrypted kit locally to FILE instead of emailing/deleting
    --debug                 Enable debug logging (set DEBUG=true)

SECURITY WARNING:
    The generated kit file contains ALL system secrets (decrypted temporarily during
    creation). Ensure the kit file is stored securely offline and the password is safe.
EOF
}

# --- Argument Parsing ---
AUTO_PASSWORD=false
TEST_MODE=false
OUTPUT_FILE=""

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help) show_help; exit 0 ;;
            --auto-password) AUTO_PASSWORD=true; shift ;;
            --test-mode) TEST_MODE=true; shift ;;
            --output-file)
                OUTPUT_FILE="$2"
                 # Basic check: needs directory or absolute path, or just filename (save to current dir)
                 local out_dir
                 out_dir=$(dirname "$OUTPUT_FILE")
                 # Check if dirname returns '.' (current dir) or an actual path
                 if [[ "$out_dir" != "." && "$out_dir" != /* ]]; then # Relative path with directory specified
                     out_dir="$PROJECT_ROOT/$out_dir" # Resolve relative to project root
                     OUTPUT_FILE="$out_dir/$(basename "$OUTPUT_FILE")" # Rebuild full path
                 elif [[ "$out_dir" == "." ]]; then # Just filename, save to project root
                     OUTPUT_FILE="$PROJECT_ROOT/$OUTPUT_FILE"
                 fi
                 # Ensure output dir can be created later by checking parent
                 out_dir=$(dirname "$OUTPUT_FILE")
                  if ! mkdir -p "$out_dir" 2>/dev/null && ! [[ -d "$out_dir" ]]; then
                       log_error "Cannot create or access output directory: $out_dir"
                       exit 1
                  fi
                shift 2
                ;;
            --debug) export DEBUG=true; shift ;; # Enable debug logging via environment variable
            *) log_error "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
}

# --- Cleanup Function ---
cleanup_staging() {
    if [[ -d "$EMERGENCY_KIT_STAGING_DIR" ]]; then
        _log_debug "Cleaning up temporary staging directory ($EMERGENCY_KIT_STAGING_DIR)..."
        # P1 FIX: Use find + shred for ALL files within staging before removing directory
        # Check if shred command exists
        if command -v shred >/dev/null 2>&1; then
            find "$EMERGENCY_KIT_STAGING_DIR" -type f -exec shred -uz {} \; 2>/dev/null || true
            _log_debug "Staging files shredded."
        else
            log_warn "shred command not found. Using rm -rf (less secure deletion)."
        fi
        # Now safe to remove the directory structure
        rm -rf "$EMERGENCY_KIT_STAGING_DIR"
        _log_debug "Staging directory removed."
    fi
}
# Register cleanup
trap cleanup_staging EXIT HUP INT TERM


# --- Prerequisite Validation ---
validate_prerequisites() {
    _log_section "Validating Prerequisites"
    local errors=0

    # Check required commands - P1 FIX: Add shred as required dependency
    # Use _have_cmd from system.sh if available
    local check_cmd_func="_have_cmd"
    if ! declare -f "$check_cmd_func" > /dev/null; then check_cmd_func="command -v"; fi

    local required_commands=("age" "tar" "gzip" "sha256sum" "openssl" "curl" "hostname" "date" "grep" "sed" "shred")
    # Add yq and ip if available (optional for better output)
    if "$check_cmd_func" yq > /dev/null; then required_commands+=("yq"); else log_warn "yq not found, secrets parsing might be less reliable."; fi
    if "$check_cmd_func" ip > /dev/null; then required_commands+=("ip"); else log_warn "ip command not found, network info will be limited."; fi


    for cmd in "${required_commands[@]}"; do
        if ! "$check_cmd_func" "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
             # Specific help for yq/age/shred if missing
             [[ "$cmd" == "yq" ]] && log_info "Try installing yq via 'sudo apt install yq' or manually."
             [[ "$cmd" == "age" ]] && log_info "Try installing age via 'sudo apt install age'."
             [[ "$cmd" == "shred" ]] && log_info "shred command required. Install via 'sudo apt install coreutils'."
            ((errors++))
        fi
    done

    # Check Age key (use constant from sourced sops.sh)
    if [[ ! -f "$AGE_KEY_FILE" || ! -r "$AGE_KEY_FILE" ]]; then
        log_error "Age private key not found or not readable: $AGE_KEY_FILE"
        ((errors++))
    fi

    # Check secrets file (Warn if missing, but allow continuation for init-setup case)
    if [[ ! -f "$SECRETS_FILE" ]]; then
        log_warn "'$SECRETS_FILE' not found. Kit will be incomplete (missing application secrets)."
        # Do not increment errors here, handle failure later if decryption needed
    elif [[ ! -r "$SECRETS_FILE" ]]; then
         log_error "Cannot read secrets file '$SECRETS_FILE'."
         ((errors++))
    fi

     # Check config file (.env) existence (Warn only)
     if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
         log_warn ".env file not found. Kit configuration section might be incomplete."
     fi


    if [[ $errors -gt 0 ]]; then
        log_error "Prerequisite validation failed with $errors critical error(s)."
        return 1
    else
        log_success "Prerequisites validated successfully."
        return 0
    fi
}

# --- Staging Area Setup ---
create_staging_structure() {
    _log_debug "Creating temporary staging directory: $EMERGENCY_KIT_STAGING_DIR..."
    cleanup_staging # Ensure clean start
    # Create subdirectories using iteration for cleaner code
    local subdirs=("secrets" "configuration" "recovery" "verification")
    for subdir in "${subdirs[@]}"; do
         if ! mkdir -p "$EMERGENCY_KIT_STAGING_DIR/$subdir"; then
             log_error "Failed to create staging subdirectory: $subdir"
             return 1
         fi
    done
    # Set restrictive permissions on the main staging dir
    chmod 700 "$EMERGENCY_KIT_STAGING_DIR" || { log_error "Failed to set permissions on staging directory."; return 1; }
    log_success "Staging directory created with subdirectories."
}

# --- Content Generation Functions ---

generate_secrets_content() {
    _log_section "Generating Secrets Content"
    local secrets_dir="$EMERGENCY_KIT_STAGING_DIR/secrets"
    local errors=0
    local temp_decrypted_secrets="$secrets_dir/secrets.decrypted.yaml"

    # Decrypt secrets.yaml
    if [[ -f "$SECRETS_FILE" ]]; then
        log_info "Decrypting '$SECRETS_FILE' to staging area..."
        # Decryption attempt
        if ! age -d -i "$AGE_KEY_FILE" "$SECRETS_FILE" > "$temp_decrypted_secrets" 2>/dev/null; then
            log_error "Failed to decrypt secrets file '$SECRETS_FILE'. Check Age key and file."
            ((errors++))
        else
            chmod 600 "$temp_decrypted_secrets" # Secure the decrypted file
            log_success "Secrets decrypted to staging area (sensitive)."
        fi
    else
         log_warn "'$SECRETS_FILE' not found. Kit will not contain application secrets."
         # Create a placeholder file to avoid errors later
         echo "# Secrets file '$SECRETS_FILE' was not found during kit creation." > "$temp_decrypted_secrets"
         chmod 600 "$temp_decrypted_secrets"
    fi

    # Copy Age keys
    log_info "Copying Age keys..."
    if ! cp "$AGE_KEY_FILE" "$secrets_dir/" || ! chmod 600 "$secrets_dir/$(basename "$AGE_KEY_FILE")"; then
        log_error "Failed to copy or set permissions on Age private key."
        ((errors++))
    fi
    # Generate/copy public key
    local pubkey_file="$PROJECT_ROOT/secrets/keys/age-public-key.txt" # Relative to project root
    local dest_pubkey_file="$secrets_dir/age-public-key.txt"
    if [[ -f "$pubkey_file" ]]; then
        cp "$pubkey_file" "$dest_pubkey_file" || log_warn "Failed to copy existing public key."
    else
         log_info "Generating public key from private key..."
         if ! age-keygen -y "$AGE_KEY_FILE" > "$dest_pubkey_file"; then
              log_error "Failed to generate public key from private key."
              ((errors++))
         fi
    fi
     chmod 644 "$dest_pubkey_file" 2>/dev/null || true # Ensure readable


    if [[ $errors -eq 0 ]]; then
        log_success "Secrets content generated successfully."
        return 0
    else
         log_error "Errors occurred during secrets content generation."
         # Ensure partially decrypted file is cleaned up even on error (handled by trap)
         return 1
    fi
}

generate_configuration_content() {
    _log_section "Generating Configuration Content"
    local config_dir="$EMERGENCY_KIT_STAGING_DIR/configuration" errors=0

    # Define files relative to PROJECT_ROOT
    local files_to_copy=(
        "docker-compose.yml"
        ".env"
        ".sops.yaml"
        "caddy/Caddyfile"
        "caddy/cloudflare-ips.caddy"
        "fail2ban/jail.local"
        "templates/ddclient.conf.tmpl"
         # Add fail2ban components
         "fail2ban/filter.d/vaultwarden.conf"
         "fail2ban/filter.d/vaultwarden-admin.conf"
         "fail2ban/filter.d/caddy-json.conf"
         "fail2ban/filter.d/caddy-404.conf"
         "fail2ban/filter.d/caddy-bad-bots.conf"
         "fail2ban/filter.d/caddy-vulnerability-scan.conf"
         "fail2ban/action.d/cloudflare.conf" # If used
         "fail2ban/action.d/sendmail-whois.local" # If used
    )

    for relative_path in "${files_to_copy[@]}"; do
         local source_file="$PROJECT_ROOT/$relative_path"
         local dest_path="$config_dir/$relative_path"

        if [[ -f "$source_file" ]]; then
             # Ensure destination directory exists
             mkdir -p "$(dirname "$dest_path")" || { log_error "Cannot create dir for '$dest_path'"; ((errors++)); continue; }
             if cp "$source_file" "$dest_path"; then
                  _log_debug "Copied config: $relative_path"
             else
                  log_warn "Failed to copy configuration file: $source_file"
                  ((errors++))
             fi
        else
            log_warn "Configuration file not found, skipping: $source_file"
            # Decide which missing files are critical errors
            case "$relative_path" in
                 "docker-compose.yml"|".env"|".sops.yaml"|"caddy/Caddyfile")
                     log_error "Essential config file missing: $relative_path"
                     ((errors++))
                     ;;
                 *) ;; # Other files might be optional or generated later
            esac
        fi
    done

    if [[ $errors -eq 0 ]]; then
        log_success "Configuration content generated."
        return 0
    else
         log_error "Errors occurred during configuration content generation."
         return 1
    fi
}

generate_recovery_content() {
    _log_section "Generating Recovery Documentation"
    local recovery_dir="$EMERGENCY_KIT_STAGING_DIR/recovery" errors=0

    # Ensure variables are available (best effort using get_config_value)
    local domain_val admin_email_val clean_domain_val
    domain_val=$(get_config_value "DOMAIN" "your-domain.com")
    admin_email_val=$(get_config_value "ADMIN_EMAIL" "admin@example.com")
    # Get CLEAN_DOMAIN if set by config.sh, otherwise derive it
    clean_domain_val=$(get_config_value "CLEAN_DOMAIN" "")
    if [[ -z "$clean_domain_val" ]]; then
         clean_domain_val="${domain_val#http://}"
         clean_domain_val="${clean_domain_val#https://}"
         clean_domain_val="${clean_domain_val%/}"
    fi


    # Create recovery guide
    log_info "Generating recovery-guide.md..."
    # Use cat with HERE document, ensure correct variable expansion
    cat > "$recovery_dir/recovery-guide.md" <<- EOF
# VaultWarden-OCI-NG Emergency Recovery Guide (from Kit)

**Generated:** $(date -u '+%Y-%m-%d %H:%M:%S UTC')
**From Server:** $(hostname -f 2>/dev/null || hostname)
**Project Version (Git):** $(git rev-parse --short HEAD 2>/dev/null || echo "N/A")

## 1. Prerequisites
* A new **Ubuntu 24.04 LTS** server instance.
* This Emergency Access Kit archive (\`.tar.gz.age\`), decrypted using your password.
* Your backed-up Age private key (\`age-key.txt\` - **must be restored from YOUR secure offline backup**). A copy is included in the \`secrets/\` directory of this kit for reference only.
* Internet access on the new server.
* DNS configured to point your domain (\`${clean_domain_val}\`) to the new server's IP address.

## 2. Server Preparation
Log in to the new server via SSH.

\`\`\`bash
# Update system and install essential tools
sudo apt update && sudo apt upgrade -y
# Ensure git, age, curl, wget, tar, gzip, coreutils (for shred) are installed
sudo apt install -y git age curl wget tar gzip coreutils

# (Recommended) Set up SSH keys for secure access and disable password auth later
# ssh-keygen ... ; ssh-copy-id your_user@new-server-ip
# sudo nano /etc/ssh/sshd_config # Set PasswordAuthentication no
# sudo systemctl reload sshd
\`\`\`

## 3. Clone Repository & Restore Kit Contents
\`\`\`bash
# Clone the project repository into /opt (or preferred location)
cd /opt
sudo git clone https://github.com/killer23d/VaultWarden-OCI-NG
# Assign ownership to your user for easier management initially
sudo chown -R \$USER:\$USER VaultWarden-OCI-NG
cd VaultWarden-OCI-NG

# *** IMPORTANT: Copy extracted kit contents ***
# Replace '/path/to/extracted/kit/' with the actual path where you extracted this kit archive.

# Restore Age Key (Use YOUR secure backup copy primarily)
echo "Restoring Age key..."
mkdir -p secrets/keys
# cp /path/to/your/secure/backup/age-key.txt secrets/keys/ # Recommended method
cp /path/to/extracted/kit/secrets/age-key.txt secrets/keys/ # Fallback using kit copy
chmod 600 secrets/keys/age-key.txt
echo "Age key restored. Verify permissions (600) and ownership."

# Restore SOPS config
echo "Restoring SOPS config..."
cp /path/to/extracted/kit/configuration/.sops.yaml .sops.yaml
chmod 644 .sops.yaml
echo "SOPS config restored."

# Restore Decrypted Secrets (temporary)
echo "Preparing secrets file..."
cp /path/to/extracted/kit/secrets/secrets.decrypted.yaml secrets/secrets-temp.yaml
chmod 600 secrets/secrets-temp.yaml # Secure temp file

# Re-encrypt secrets using the restored Age key
echo "Re-encrypting secrets..."
# Verify age-keygen command works with the restored key
if ! age-keygen -y secrets/keys/age-key.txt > /dev/null; then
    echo "ERROR: Restored Age key appears invalid or inaccessible! Cannot re-encrypt secrets."
    echo "Ensure 'secrets/keys/age-key.txt' is correct and has 600 permissions."
    # Securely delete temp file before exiting
    shred -u secrets/secrets-temp.yaml 2>/dev/null || rm -f secrets/secrets-temp.yaml
    exit 1
fi
# Use sops to re-encrypt based on .sops.yaml rules
if ! sops --encrypt --in-place secrets/secrets-temp.yaml; then
    echo "ERROR: SOPS encryption failed. Check .sops.yaml and key."
    shred -u secrets/secrets-temp.yaml 2>/dev/null || rm -f secrets/secrets-temp.yaml
    exit 1
fi
# Rename temp file to final secrets file
mv secrets/secrets-temp.yaml secrets/secrets.yaml
chmod 640 secrets/secrets.yaml # Set final permissions

# Securely remove the temporary decrypted file (already renamed or shredded on error)
echo "Secrets re-encrypted successfully."

# Restore other configuration files (.env, docker-compose, Caddyfile etc.)
echo "Restoring configuration files..."
# Use rsync for safe copy, overwriting existing template files from git clone
rsync -a /path/to/extracted/kit/configuration/ ./
chmod 640 .env # Ensure .env has correct permissions
echo "Configuration files restored."

# Set script permissions (crucial!)
chmod +x startup.sh tools/*.sh lib/*.sh
\`\`\`

## 4. Install Dependencies
\`\`\`bash
echo "Installing system dependencies..."
# Use sudo, run non-interactively
sudo ./tools/install-deps.sh --auto
\`\`\`

## 5. Initialize System (Non-destructively)
This ensures directories, firewall etc., are set up based on restored config.
Use \`--restore-mode\` to skip key/config generation if files exist. Domain/email needed if .env restore failed.
\`\`\`bash
echo "Running initial setup (restore mode)..."
# Use domain/email from restored .env if possible
restored_domain=\$(grep '^DOMAIN=' .env 2>/dev/null | cut -d= -f2 || echo '${clean_domain_val}')
restored_email=\$(grep '^ADMIN_EMAIL=' .env 2>/dev/null | cut -d= -f2 || echo '${admin_email_val}')
# Requires sudo
sudo ./tools/init-setup.sh --restore-mode --domain "\$restored_domain" --email "\$restored_email"
# Expect warnings about existing files/keys - this is normal in restore mode.
\`\`\`

## 6. Start Services
\`\`\`bash
echo "Starting VaultWarden stack..."
# Run as your user (assuming user is in docker group from install-deps)
./startup.sh
# This should succeed if all previous steps worked
\`\`\`

## 7. Validate Recovery
\`\`\`bash
echo "Running health check (wait ~30-60s first for services to start)..."
sleep 60
./tools/check-health.sh --comprehensive

# Access your Vaultwarden instance via browser at: https://${clean_domain_val}
# Log in with your previous credentials and verify data.
# Check the admin panel at: https://${clean_domain_val}/admin (using ADMIN_TOKEN/password from restored secrets)
\`\`\`

## 8. Post-Recovery Steps (HIGHLY Recommended)
* **Generate a NEW Emergency Kit:** \`./tools/create-emergency-kit.sh\` (Use a NEW password). Store it securely offline.
* **Securely Backup the NEW Age Key:** Manually copy the new \`secrets/keys/age-key.txt\` to your secure offline locations. **Delete the old key backup.**
* **Test Backup Creation:** \`./tools/backup-monitor.sh --db-only\`
* **Verify Cron Jobs:** \`sudo crontab -l\` (If missing/incorrect, re-run \`sudo ./tools/init-setup.sh --restore-mode ...\` or manually setup via \`lib/cron.sh\`).
* **Rotate Sensitive Secrets:** Consider changing ADMIN\_TOKEN and possibly SMTP password using \`./tools/edit-secrets.sh\`.

## Troubleshooting
* **Decryption Fails (Step 3 - age command):** Ensure you restored the correct \`age-key.txt\` from your secure backup and it has correct permissions (600).
* **Encryption Fails (Step 3 - sops command):** Check \`.sops.yaml\` is present and correct. Verify the Age key again.
* **Services Fail to Start (Step 6):** Check logs: \`docker compose logs\`, \`${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs/system.log\`. Ensure secrets re-encrypted correctly. Check Docker status: \`sudo systemctl status docker\`. Ensure correct ownership/permissions on \`${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/data\`.
* **Cannot Access Web UI (Step 7):** Verify DNS points to the new server's IP. Check firewall: \`sudo ufw status\`. Check Caddy logs: \`docker compose logs caddy\`.
* **Data Missing:** Ensure the kit was generated *after* the data was last saved. If data loss occurred before the kit, you may need to restore from a standard backup (\`.tar.gz.age\` or \`.sqlite3.gz.age\`) instead using \`./tools/backup-recovery.sh\`.

EOF
    if [[ $? -eq 0 ]]; then log_success "Recovery guide generated."; else log_error "Failed to generate recovery guide."; ((errors++)); fi


    # Generate network configuration summary
    log_info "Generating network-config.txt..."
    # Use subshell to capture output, handle errors gracefully
    network_config_content=$(
        echo "# Network Configuration Summary (at time of kit creation)"
        echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo
        echo "## VaultWarden Configuration (from loaded config)"
        echo "Domain (from .env): ${domain_val:-Not configured}"
        echo "Clean Domain (for Caddy): ${clean_domain_val:-Not set}"
        echo "Admin Email (from .env): ${admin_email_val:-Not configured}"
        echo
        echo "## System Information (Source Server)"
        echo "Hostname: $(hostname -f 2>/dev/null || hostname)"
        local public_ip="Unavailable" private_ips="Unavailable"
        # Check for curl before attempting public IP fetch
        if command -v curl >/dev/null; then
             public_ip=$(curl -fsSL --max-time 5 https://ifconfig.me/ip 2>/dev/null || curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || echo "Unavailable")
        fi
        echo "Detected Public IP: $public_ip"
        # Check for ip command before attempting private IP fetch
        if command -v ip >/dev/null; then
             private_ips=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | tr '\n' ' ' | sed 's/ $//' || echo "Unavailable") # Remove trailing space
        fi
        echo "Detected Private IP(s): $private_ips"
        echo
        echo "## UFW Firewall Status (Snapshot - Requires sudo)"
        # Check for ufw and sudo before attempting status
        if command -v ufw >/dev/null && [[ $EUID -eq 0 || -n "${SUDO_USER:-}" ]]; then
             # Try running with sudo if not already root
             local sudo_cmd=""
             [[ $EUID -ne 0 ]] && sudo_cmd="sudo "
             ${sudo_cmd}ufw status verbose || echo "# UFW status command failed."
        else
             echo "# UFW status requires 'ufw' command and root/sudo privileges."
        fi
    )
    if echo "$network_config_content" > "$recovery_dir/network-config.txt"; then
        log_success "Network summary generated.";
    else
         log_error "Failed to generate network summary."; ((errors++));
    fi

    return $errors
}

generate_verification_content() {
    _log_section "Generating Verification Content"
    local verification_dir="$EMERGENCY_KIT_STAGING_DIR/verification" errors=0

    # Generate checksums
    log_info "Generating SHA256 checksums for kit contents..."
    # Use subshell and cd for relative paths, handle find errors
    # Exclude the verification directory itself from checksums
    if ! ( cd "$EMERGENCY_KIT_STAGING_DIR" && find . -type f ! -path "./verification/*" -exec sha256sum {} + > "$verification_dir/checksums.sha256" ); then
        log_error "Failed to generate checksums."
        ((errors++))
    else
        log_success "Checksums generated: $verification_dir/checksums.sha256"
    fi

    # Generate metadata
     log_info "Generating metadata file..."
     local commit_hash="N/A"
     # Check for git command and .git directory
     if [[ -d "$PROJECT_ROOT/.git" ]] && command -v git >/dev/null; then
         commit_hash=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "N/A")
     fi
     metadata_content=$(printf "Emergency Access Kit Creation Details\n-------------------------------------\nTimestamp: %s\nSource Server: %s\nProject Git Commit: %s\nCreated By: %s\nKit Version: 1.2\n" \
         "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" \
         "$(hostname -f 2>/dev/null || hostname)" \
         "$commit_hash" \
         "$(basename "$0")" # Script name
     )
     if echo "$metadata_content" > "$verification_dir/metadata.txt"; then
        log_success "Metadata file generated: $verification_dir/metadata.txt"
     else
          log_error "Failed to generate metadata file."; ((errors++));
     fi

    return $errors
}


# --- Encryption and Packaging ---

get_encryption_password() {
    # If OUTPUT_FILE is set, prompt even in auto-password mode for safety? No, respect flag.
    if [[ "$AUTO_PASSWORD" == "true" ]]; then
        log_info "Auto-generating secure password for kit encryption..."
        # Use generate_secure_token if security lib is sourced, otherwise openssl fallback
        if declare -f generate_secure_token > /dev/null; then
             KIT_PASSWORD=$(generate_secure_token 32)
        elif command -v openssl >/dev/null; then
             log_warn "Using openssl rand fallback for password generation."
             KIT_PASSWORD=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
        else
             log_error "Cannot auto-generate password: secure generator (openssl or lib/security) not found."
             return 1 # Indicate failure
        fi
        # Check if password generation succeeded
        if [[ -z "$KIT_PASSWORD" ]]; then
             log_error "Password generation failed."
             return 1
        fi

        log_success "Auto-generated password obtained."
        # If saving locally, WARN the user about the password
        if [[ -n "$OUTPUT_FILE" ]]; then
             log_warn "AUTO-PASSWORD used with --output-file. Password is: $KIT_PASSWORD"
             log_warn "STORE THIS PASSWORD SECURELY along with the kit file '$OUTPUT_FILE'!"
        fi
    else
        _log_section "Set Kit Encryption Password"
        log_warn "Choose a STRONG, UNIQUE password to encrypt the Emergency Kit."
        log_warn "You WILL need this password for disaster recovery. Store it safely and securely offline!"
        while true; do
            # Prompt twice for confirmation, use -s for silent input
            read -s -p "Enter encryption password (min 12 chars recommended): " KIT_PASSWORD
            echo
            read -s -p "Confirm password: " KIT_PASSWORD_CONFIRM
            echo

            if [[ "$KIT_PASSWORD" != "$KIT_PASSWORD_CONFIRM" ]]; then
                 log_error "Passwords do not match. Please try again."
                 continue
            fi
            if [[ ${#KIT_PASSWORD} -lt 12 ]]; then
                 log_warn "Password is short (less than 12 characters). Using short passwords increases risk."
                 # Ask to confirm short password usage
                 read -p "Use this short password anyway? (y/N): " confirm_short
                 if [[ ! "$confirm_short" =~ ^[Yy]$ ]]; then
                     log_info "Password rejected due to length. Please choose a longer password."
                     continue # Ask again
                 fi
            fi
            # Add basic complexity check? (Optional, might annoy users)
            # Example: check for digits, upper/lower case
            # if ! [[ "$KIT_PASSWORD" =~ [0-9] && "$KIT_PASSWORD" =~ [a-z] && "$KIT_PASSWORD" =~ [A-Z] ]]; then log_warn "Consider adding numbers, lowercase, and uppercase letters for strength."; fi

            log_success "Password confirmed."
            break # Exit loop once passwords match and meet criteria (or override)
        done
    fi
     # Ensure variable is available globally within this script run
     export KIT_PASSWORD
     return 0 # Success
}

create_encrypted_kit() {
    local timestamp kit_archive_base kit_archive_path tar_cmd age_cmd kit_size exit_code=0 final_kit_path=""

    timestamp=$(date +%Y%m%d-%H%M%S)
    kit_archive_base="emergency-access-kit-${timestamp}"

    # Determine final output path based on OUTPUT_FILE flag
     if [[ -n "$OUTPUT_FILE" ]]; then
         # Use the path provided by the user (already resolved in parse_arguments)
         kit_archive_path="$OUTPUT_FILE"
     else
          # Default to a temporary location for emailing
          kit_archive_path="/tmp/${kit_archive_base}.tar.gz.age"
     fi

    log_info "Creating compressed tarball and encrypting with Age password..."
    log_info "Output target: $kit_archive_path"

    # Define commands
    # Use tar flags: c=create, z=gzip, f=file (use '-' for stdout), -C=change dir
    # Exclude leading './' from paths in tar archive for cleaner structure
    tar_cmd=(tar -czf - -C "$EMERGENCY_KIT_STAGING_DIR" --transform='s,^\./,,' .)
    # Use age -p for password encryption, redirect password via stdin
    age_cmd=(age -p -o "$kit_archive_path")

    # Execute pipeline, capture age exit code
    # Pass KIT_PASSWORD via stdin to age -p
    echo "$KIT_PASSWORD" | "${tar_cmd[@]}" | "${age_cmd[@]}"
    exit_code=$?

    # Check age exit code
    if [[ $exit_code -eq 0 ]]; then
         # Verify file exists and has size
         if [[ -s "$kit_archive_path" ]]; then
             chmod 600 "$kit_archive_path" # Secure final kit file (owner read/write)
             kit_size=$(du -h "$kit_archive_path" | cut -f1)
             log_success "Encrypted kit created successfully: $kit_archive_path (Size: $kit_size)"
             final_kit_path="$kit_archive_path" # Store path for return
         else
              log_error "Age command succeeded but output file is empty or missing: $kit_archive_path"
              rm -f "$kit_archive_path" # Clean up empty file
              exit_code=1 # Mark failure
         fi
    else
        log_error "Failed to create encrypted kit archive (Exit code: $exit_code)."
        log_error "Check tar or age command output if available, or permissions on output path."
        rm -f "$kit_archive_path" # Clean up potentially incomplete file
        # exit_code already set
    fi

    # Return the path on success, empty on failure. Use echo.
    echo "$final_kit_path"
    return $exit_code
}


# --- Email Notification ---

send_emergency_kit_email() {
    local kit_file_path="$1"
    local kit_filename kit_size subject email_body recipients

    kit_filename=$(basename "$kit_file_path")
    kit_size=$(du -h "$kit_file_path" | cut -f1)
    subject="🚨 VaultWarden Emergency Access Kit - $(date '+%Y-%m-%d %H:%M')" # Slightly shorter subject

    # Check if notification library was sourced successfully
    if [[ "$NOTIFICATIONS_AVAILABLE" != "true" ]]; then
         log_error "Notification library not available. Cannot send kit via email."
         log_warn "The encrypted kit is saved locally at: $kit_file_path"
         log_warn "You MUST manually copy this file to a secure offline location and delete the local copy using 'shred -u $kit_file_path'."
         return 1 # Indicate failure to email
    fi
     # Check if required function exists
      if ! declare -f send_notification_with_attachment > /dev/null; then
          log_error "'send_notification_with_attachment' function not found in sourced library."
          log_warn "The encrypted kit is saved locally at: $kit_file_path"
          log_warn "Manually secure this file offline and delete the local copy."
          return 1
      fi


    log_info "Preparing to send emergency kit via email..."

    # Prepare email body, including password if auto-generated
    local password_info=""
    if [[ "$AUTO_PASSWORD" == "true" ]]; then
         # Ensure KIT_PASSWORD is still set (should be exported or available)
         if [[ -z "${KIT_PASSWORD:-}" ]]; then
              log_error "Auto-generated password is missing. Cannot include in email body."
              password_info="Password: [ERROR - Password was auto-generated but is missing now. Check script logs.]"
         else
              password_info=$(printf "\n**Auto-Generated Password:** %s\n(Store this password securely, separately from this email, and delete this email!)" "$KIT_PASSWORD")
         fi
    else
          password_info="Password: [You provided this password during kit creation]"
    fi

    email_body=$(cat <<-EOF
	VaultWarden-OCI-NG Emergency Access Kit

	Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
	Source Server: $(hostname -f 2>/dev/null || hostname)
	Attached Kit: $kit_filename ($kit_size)

	⚠️  CRITICAL SECURITY ATTACHMENT ⚠️

	This email contains your encrypted Emergency Access Kit. It includes secrets
	and configuration needed to fully restore your VaultWarden server in a disaster.

	**TREAT THIS EMAIL AND ATTACHMENT WITH EXTREME CARE.**

	**Password Required:**
	You need the password set during kit creation to decrypt the attached \`.age\` file.
	${password_info}

	**Security Recommendations:**
	1.  **Download** the attached \`$kit_filename\` immediately.
	2.  **Verify** the download is complete and the file size matches ($kit_size).
	3.  **Store** the file in multiple, secure, **OFFLINE** locations (e.g., encrypted USB drive, password manager secure note).
	4.  **Delete** this email permanently after confirming offline storage.
	5.  **Document** the storage location and password securely (e.g., in a separate password manager entry).

	**Recovery:**
	Follow instructions in \`recovery-guide.md\` inside the decrypted kit archive.

	---
	Generated by VaultWarden-OCI-NG Emergency Access Kit system
	EOF
    )

    if [[ "$TEST_MODE" == "true" ]]; then
        log_warn "[TEST MODE] Email would be sent with kit attachment '$kit_filename'."
        log_info "Kit file remains locally at: $kit_file_path"
        return 0 # Success for test mode
    fi

    # Attempt to send using the notification library function
    log_info "Attempting to send kit to admin email (defined in config)..."
    # 'emergency' category typically implies high priority in notifications.sh
    if send_notification_with_attachment "emergency" "$subject" "$email_body" "$kit_file_path"; then
        log_success "Emergency access kit email sent successfully."
        # Securely delete the local copy *after* successful email sending
        log_info "Securely deleting local temporary kit file: $kit_file_path"
        if command -v shred >/dev/null 2>&1; then
            shred -uzn 3 "$kit_file_path" || rm -f "$kit_file_path" # Fallback rm if shred fails
        else
            log_warn "shred command not found. Using rm (less secure deletion)."
            rm -f "$kit_file_path"
        fi
        return 0 # Success
    else
        log_error "Failed to send emergency access kit via email. Check notification logs."
        log_warn "The encrypted kit is saved locally at: $kit_file_path"
        log_warn "You MUST manually copy this file to a secure offline location and delete the local copy using 'shred -u $kit_file_path'."
        return 1 # Indicate failure
    fi
}

# --- Main Execution ---
main() {
    log_header "VaultWarden Emergency Access Kit Creation"
    parse_arguments "$@"
    _log_debug "Arguments parsed. AutoPW=$AUTO_PASSWORD, TestMode=$TEST_MODE, OutputFile=$OUTPUT_FILE"


    # Validate prerequisites first
    validate_prerequisites || { log_error "Prerequisites not met. Aborting."; exit 1; }

    # Set up staging area (cleaned up by trap)
    create_staging_structure || { log_error "Failed to set up staging area. Aborting."; exit 1; }

    # Generate content (handle failures)
    # Use || { ...; exit 1; } to exit script if a generation step fails critically
    generate_secrets_content || { log_error "Critical error generating secrets content. Aborting."; exit 1; }
    generate_configuration_content || { log_error "Critical error generating configuration content. Aborting."; exit 1; }
    generate_recovery_content || { log_warn "Error generating some recovery documentation."; } # Continue if non-critical docs fail
    generate_verification_content || { log_warn "Error generating verification content."; } # Continue if non-critical verification fails

    # Get encryption password (exits on failure)
    get_encryption_password || { log_error "Failed to obtain encryption password. Aborting."; exit 1; }

    # Create encrypted kit archive (function returns path on success, empty on failure)
    local kit_file_path exit_code
    kit_file_path=$(create_encrypted_kit)
    exit_code=$? # Capture exit code of create_encrypted_kit
    if [[ $exit_code -ne 0 || -z "$kit_file_path" ]]; then
         log_error "Failed to create encrypted kit file. Aborting."; exit 1;
    fi

    # Send kit via email or handle local file output
     local final_status=0
     if [[ -n "$OUTPUT_FILE" ]]; then
          # If output file specified, the kit is already there. Just log.
          log_success "Emergency kit saved locally to: $kit_file_path"
          log_warn "Email sending skipped due to --output-file option."
          log_warn "You MUST manually copy this file to a secure offline location."
          # Do not delete if saved locally via --output-file
     else
         # If no output file, attempt to email the temporary kit file
         send_emergency_kit_email "$kit_file_path" || final_status=$? # Send and capture status
         # Local temporary file deleted by send_emergency_kit_email on success
     fi

    # Final cleanup (password var, trap handles staging dir)
    unset KIT_PASSWORD KIT_PASSWORD_CONFIRM

    if [[ $final_status -eq 0 ]]; then
         log_success "Emergency Access Kit process finished successfully."
    else
         # Specific error already logged by send_emergency_kit_email or other steps
         log_error "Emergency Access Kit process finished with errors."
    fi

    exit $final_status
}

# --- Script Entry Point ---
# Run main if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Optional: Add ERR trap for better debugging
    # trap 'log_error "Unhandled error occurred at line $LINENO in $(basename ${BASH_SOURCE[0]})"; exit 1' ERR
    main "$@"
fi
