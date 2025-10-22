#!/usr/bin/env bash
# lib/security.sh - Security utilities with Cloudflare allowlisting and basic hardening

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Library Directory Resolution ---
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$LIB_DIR/.." && pwd)"

# --- Inter-library sourcing ---
# Source logging with fallback
if [[ -f "$LIB_DIR/logging.sh" ]]; then
    # shellcheck source=/dev/null
    source "$LIB_DIR/logging.sh"
else
    # Fallback logging functions
    log_info() { echo "[security.sh][INFO] $*"; }
    log_warn() { echo "[security.sh][WARN] $*"; }
    log_error() { echo "[security.sh][ERROR] $*" >&2; }
    log_success() { echo "[security.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
fi

# Source system library (needed for _have_cmd)
if [[ ! -f "$LIB_DIR/system.sh" ]]; then
    log_error "Critical library not found: lib/system.sh"
    exit 1 # Or handle error differently depending on how critical system.sh is
fi
source "$LIB_DIR/system.sh"

# Source config library (needed for PROJECT_STATE_DIR in secure_project_permissions)
# Load config explicitly if needed within this library's functions
if [[ ! -f "$LIB_DIR/config.sh" ]]; then
    log_error "Critical library not found: lib/config.sh"
    exit 1
fi
source "$LIB_DIR/config.sh"

# Source constants library (needed for URLs)
if [[ ! -f "$LIB_DIR/constants.sh" ]]; then
    log_error "Critical library not found: lib/constants.sh"
    exit 1
fi
source "$LIB_DIR/constants.sh"

# --- Library functions follow ---

_set_log_prefix "security" # Use internal function from logging.sh

# --- P2 FIX: DRY Cloudflare IP Fetching Function ---

# P2 ADDITION: Centralized Cloudflare IP fetching with retry logic
# fetch_cloudflare_ips <out_file> [ipv4_url] [ipv6_url]
fetch_cloudflare_ips() {
    local out_file="${1:?Output file path required}"
    # Use constants defined in constants.sh, provide defaults
    local ipv4_url="${2:-${CF_IPV4_URL:-https://www.cloudflare.com/ips-v4}}"
    local ipv6_url="${3:-${CF_IPV6_URL:-https://www.cloudflare.com/ips-v6}}"

    log_info "Fetching Cloudflare IP ranges from official sources..."

    local ipv4_ranges="" ipv6_ranges=""
    local max_attempts=3

    # Check for curl command
    if ! _have_cmd curl; then
        log_error "curl command is required to fetch Cloudflare IPs."
        return 1
    fi

    # Retry mechanism for robust IP fetching
    for attempt in $(seq 1 $max_attempts); do
        _log_debug "Attempt $attempt of $max_attempts to fetch Cloudflare IPs..."

        ipv4_ranges=$(curl -fsSL --connect-timeout 10 --max-time 15 "$ipv4_url" 2>/dev/null || true)
        ipv6_ranges=$(curl -fsSL --connect-timeout 10 --max-time 15 "$ipv6_url" 2>/dev/null || true)

        if [[ -n "$ipv4_ranges" && -n "$ipv6_ranges" ]]; then
            _log_debug "Successfully fetched IP ranges on attempt $attempt"
            break
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            log_warn "Attempt $attempt failed to fetch complete IP ranges, retrying in 2 seconds..."
            sleep 2
        fi
    done

    # Validate we got both IPv4 and IPv6 ranges
    if [[ -z "$ipv4_ranges" || -z "$ipv6_ranges" ]]; then
        log_error "Failed to fetch Cloudflare IP ranges after $max_attempts attempts"
        log_error "IPv4 URL: $ipv4_url"
        log_error "IPv6 URL: $ipv6_url"
        # Log partial results if any
        [[ -n "$ipv4_ranges" ]] && log_error "IPv4 Result (partial): ${ipv4_ranges:0:100}..."
        [[ -n "$ipv6_ranges" ]] && log_error "IPv6 Result (partial): ${ipv6_ranges:0:100}..."
        return 1
    fi

    # Write combined IP ranges to output file
    # Use temporary file first, then move, for atomicity
    local temp_out_file="${out_file}.tmp.$$"
    {
        echo "$ipv4_ranges"
        echo "$ipv6_ranges"
    } > "$temp_out_file" || { log_error "Failed to write IPs to temporary file $temp_out_file"; rm -f "$temp_out_file"; return 1; }

    # Validate content looks like IPs/CIDRs before moving
    if grep -qE '^[0-9.:/]+$' "$temp_out_file"; then
        mv "$temp_out_file" "$out_file" || { log_error "Failed to move temporary IP file to $out_file"; rm -f "$temp_out_file"; return 1; }
    else
        log_error "Fetched content does not look like valid IP ranges. Aborting update."
        rm -f "$temp_out_file"
        return 1
    fi


    local ip_count
    ip_count=$(wc -l < "$out_file")
    log_success "Cloudflare IP ranges saved to $out_file ($ip_count ranges)"
    return 0
}

# --- Existing Functions ---

# Update UFW to allow only Cloudflare IP ranges on ports 80/443.
update_cloudflare_ufw_allowlist() {
    log_info "Updating UFW rules to allow Cloudflare IPs..."

    if ! _have_cmd ufw; then log_error "UFW command not found."; return 1; fi
    # Ensure root privileges for UFW operations
    if [[ $EUID -ne 0 ]]; then
         # Try using sudo if available
         if _have_cmd sudo; then
             log_info "Attempting UFW operations with sudo..."
             SUDO_CMD="sudo"
         else
             log_error "Root privileges required for UFW, and sudo not found."; return 1;
         fi
    else
         SUDO_CMD="" # Already root
    fi


    if ! $SUDO_CMD ufw status | grep -qE '^(22|ssh)\s+(ALLOW|LIMIT)\s+Anywhere'; then
        log_warn "No SSH rule detected. Adding '$SUDO_CMD ufw allow ssh' for safety."
        $SUDO_CMD ufw allow ssh >/dev/null || { log_error "Failed to add SSH allow rule. Aborting firewall update for safety."; return 1; }
    fi

    # P2 ENHANCEMENT: Use the new DRY fetch function with retry logic
    log_info "Fetching Cloudflare IP ranges using centralized fetch function..."
    local temp_ip_file="/tmp/cloudflare-ips.$$.txt"
    # Ensure temp file is removed on exit/error
    trap 'rm -f "$temp_ip_file"' RETURN

    if ! fetch_cloudflare_ips "$temp_ip_file"; then
        log_error "Failed to fetch Cloudflare IP ranges. Aborting firewall update."
        return 1
    fi

    log_info "Removing existing UFW rules commented as 'Cloudflare'..."
    # Loop to delete rules one by one, using sudo
    while true; do
        # Need sudo to get status reliably
        local rule_line rule_num
        rule_line=$($SUDO_CMD ufw status numbered | grep -i 'Cloudflare' | head -n 1)
        [[ -z "$rule_line" ]] && break # Exit loop if no more Cloudflare rules found
        # Extract rule number (handle potential leading spaces)
        rule_num=$(echo "$rule_line" | awk -F'[][]' '{print $2}' | sed 's/ //g')
        if [[ "$rule_num" =~ ^[0-9]+$ ]]; then
            log_debug "Deleting UFW rule number $rule_num..."
            # Use 'yes' piped to ufw delete, with sudo
            yes | $SUDO_CMD ufw delete "$rule_num" >/dev/null || { log_error "Failed to delete UFW rule $rule_num. Manual cleanup might be needed."; break; } # Exit loop on delete error
        else
            log_warn "Could not parse rule number from line: $rule_line. Stopping rule deletion."
            break
        fi
    done
    log_info "Finished removing old Cloudflare rules."


    log_info "Adding new UFW rules for Cloudflare IPs..."
    local add_errors=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        # Basic validation of IP/CIDR format
        if [[ ! "$ip" =~ ^([0-9.:/]+)$ ]]; then
             log_warn "Skipping invalid IP/CIDR format: $ip"
             continue
        fi
        local comment="Cloudflare"
        [[ "$ip" == *":"* ]] && comment="Cloudflare IPv6" || comment="Cloudflare IPv4"
        # Add rule using sudo
        $SUDO_CMD ufw allow from "$ip" to any port 80,443 proto tcp comment "$comment" >/dev/null || { log_error "Failed to add rule for $ip"; ((add_errors++)); }
    done < "$temp_ip_file"

    # Cleanup temp file handled by trap

     if [[ $add_errors -gt 0 ]]; then
         log_error "$add_errors error(s) occurred while adding new UFW rules."
     else
          log_success "New Cloudflare UFW rules added."
     fi

     log_info "Reloading UFW firewall..."
     if $SUDO_CMD ufw reload >/dev/null; then
         log_success "UFW updated and reloaded with new Cloudflare rules."
         return 0 # Success
     else
          log_error "Failed to reload UFW after adding rules."
          return 1 # Failure
     fi
}


# Configure system security during initial setup.
configure_system_security() {
    local auto_mode="${1:-false}"
    _log_section "Configuring Basic System Security"
    # Requires root
    if [[ $EUID -ne 0 ]]; then log_error "Root privileges required."; return 1; fi

    if _have_cmd ufw; then
        log_info "Configuring UFW firewall..."
        # Check if UFW is already active to avoid unnecessary reset
        if ! ufw status | grep -q "Status: active"; then
            log_info "UFW is inactive. Setting defaults and enabling..."
            ufw --force reset >/dev/null # Reset to known state first
            ufw default deny incoming >/dev/null
            ufw default allow outgoing >/dev/null
            ufw allow ssh >/dev/null # Ensure SSH is allowed
            log_info "UFW reset to defaults (deny incoming, allow outgoing, allow ssh)."
            log_info "Enabling UFW firewall..."
            ufw --force enable || { log_error "Failed to enable UFW."; return 1; }
            log_success "UFW enabled."
        else
             log_info "UFW is already active. Ensuring SSH is allowed..."
             ufw allow ssh >/dev/null # Ensure SSH rule exists
             log_success "UFW active and SSH allowed."
        fi
    else
        log_warn "UFW command not found. Skipping firewall configuration."
    fi

    if _have_cmd fail2ban-client; then
        log_info "Ensuring fail2ban service is enabled and active..."
        # Use systemctl from system.sh if available, otherwise direct call
        if declare -f _enable_service >/dev/null && declare -f _start_service >/dev/null && declare -f _get_service_status >/dev/null; then
             if [[ $(_get_service_status "fail2ban") != "active" ]]; then
                 _enable_service "fail2ban" && _start_service "fail2ban" || log_warn "Failed to start/enable fail2ban service via library."
             else
                 log_success "fail2ban service is active."
             fi
        elif _have_cmd systemctl; then
             if ! systemctl is-active --quiet fail2ban; then
                 systemctl enable --now fail2ban || log_warn "Failed to start/enable fail2ban service via systemctl."
             else
                 log_success "fail2ban service is active."
             fi
        else
             log_warn "Cannot manage fail2ban service: systemctl not found."
        fi
    else
        log_warn "fail2ban-client command not found. Intrusion prevention disabled."
    fi
    log_success "Security configuration checks completed."
}

# Secure file and directory permissions for the project
secure_project_permissions() {
    _log_section "Securing Project File Permissions"
    local errors=0 sudo_prefix=""
    # Use sudo if not already root
    [[ $EUID -ne 0 ]] && sudo_prefix="sudo "

    # Load config to get PROJECT_STATE_DIR reliably
    # Assume load_config has been called previously by the sourcing script
    local state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}" # Default if config failed

    log_info "Securing permissions within project root '$PROJECT_ROOT'..."

    # Secure directories first
    local dirs_to_secure=("secrets" "secrets/keys" "caddy" "fail2ban" "templates" "ddclient")
    for dir in "${dirs_to_secure[@]}"; do
        local full_path="$PROJECT_ROOT/$dir"
        if [[ -d "$full_path" ]]; then
            local perm="750" # Default restricted perm
            [[ "$dir" == "secrets/keys" ]] && perm="700" # Keys directory needs owner-only
            _log_debug("Setting permissions $perm on $dir...")
            ${sudo_prefix}chmod "$perm" "$full_path" || { log_warn "Failed chmod $perm on $dir"; ((errors++)); }
        fi
    done

    # Secure specific file types or individual files
    log_info "Securing file permissions..."
    # Config files (readable by group)
    find "$PROJECT_ROOT" -maxdepth 1 \( -name ".env" -o -name ".sops.yaml" -o -name "settings.env.example" \) -print0 | xargs -0 -r ${sudo_prefix}chmod 640 || ((errors++))
    # YAML secrets (encrypted, readable by group okay, but be stricter?)
    find "$PROJECT_ROOT/secrets" -maxdepth 1 -name "*.yaml" -print0 | xargs -0 -r ${sudo_prefix}chmod 640 || ((errors++))
    find "$PROJECT_ROOT/secrets" -maxdepth 1 -name "*.yaml.example" -print0 | xargs -0 -r ${sudo_prefix}chmod 644 || ((errors++))
    # Age Keys (critical)
    [[ -f "$PROJECT_ROOT/secrets/keys/age-key.txt" ]] && ${sudo_prefix}chmod 600 "$PROJECT_ROOT/secrets/keys/age-key.txt" || ((errors++))
    [[ -f "$PROJECT_ROOT/secrets/keys/age-public-key.txt" ]] && ${sudo_prefix}chmod 644 "$PROJECT_ROOT/secrets/keys/age-public-key.txt" || ((errors++))
    # Caddy files (readable by group)
    find "$PROJECT_ROOT/caddy" -type f -print0 | xargs -0 -r ${sudo_prefix}chmod 644 || ((errors++))
    # Fail2ban config (readable by group)
    find "$PROJECT_ROOT/fail2ban" -type f -print0 | xargs -0 -r ${sudo_prefix}chmod 644 || ((errors++))
    # Templates (readable by group)
    find "$PROJECT_ROOT/templates" -type f -print0 | xargs -0 -r ${sudo_prefix}chmod 644 || ((errors++))
    # Rendered ddclient conf (sensitive, owner only)
    [[ -f "$PROJECT_ROOT/ddclient/ddclient.conf" ]] && ${sudo_prefix}chmod 600 "$PROJECT_ROOT/ddclient/ddclient.conf" || true # Don't error if file doesn't exist yet
    # Docker secrets dir (owner only)
    [[ -d "$PROJECT_ROOT/secrets/.docker_secrets" ]] && ${sudo_prefix}chmod 700 "$PROJECT_ROOT/secrets/.docker_secrets" || true
    [[ -d "$PROJECT_ROOT/secrets/.docker_secrets" ]] && find "$PROJECT_ROOT/secrets/.docker_secrets" -type f -print0 | xargs -0 -r ${sudo_prefix}chmod 600 || ((errors++))

    log_info "Ensuring scripts are executable..."
    # Scripts should be executable by owner/group
    find "$PROJECT_ROOT/tools" "$PROJECT_ROOT/lib" -name "*.sh" -print0 | xargs -0 -r ${sudo_prefix}chmod 750 || ((errors++))
    [[ -f "$PROJECT_ROOT/startup.sh" ]] && ${sudo_prefix}chmod 750 "$PROJECT_ROOT/startup.sh" || ((errors++))

    # Secure state directory (assuming it exists)
    if [[ -d "$state_dir" ]]; then
        log_info "Securing permissions within state directory '$state_dir'..."
        # Set directory permissions (e.g., 750 or stricter if needed)
        # Find directories and set permissions
        find "$state_dir" -type d -print0 | xargs -0 -r ${sudo_prefix}chmod 750 || ((errors++))
        # Find files and set permissions (e.g., 640)
        find "$state_dir" -type f -print0 | xargs -0 -r ${sudo_prefix}chmod 640 || ((errors++))
        # Special handling for DB file? Vaultwarden container needs access.
        # Permissions handled by volume mount ownership (1000:1000) usually.
    fi


    if [[ $errors -eq 0 ]]; then
         log_success "Project file permissions secured."
         return 0
    else
         log_error "Failed to set some project permissions ($errors errors)."
         return 1
    fi
}


# Generate a secure random string
generate_secure_token() {
    local length="${1:-32}" # Default length 32
    local bytes # Calculate bytes needed for base64
    bytes=$(( (length * 3 + 3) / 4 )) # Formula to get enough bytes for base64 encoding

    # Check for openssl command
    if ! _have_cmd openssl; then
        log_error "openssl command not found. Cannot generate secure token."
        return 1
    fi

    # Generate random bytes, base64 encode, remove non-alphanumeric, take first 'length' chars
    openssl rand -base64 "$bytes" | tr -d '+/=' | head -c "$length" || {
        log_error "openssl command failed during token generation."
        return 1
    }
    return 0 # Success, token printed to stdout
}

# --- Library Initialization / Self-Test ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _log_warning "lib/security.sh is a library and should be sourced, not executed directly."
    _log_info "Running self-tests..."
    export DEBUG=true # Enable debug logs for testing

    # Test Cloudflare IP fetch
    _log_section "Testing Cloudflare IP Fetch"
    fetch_cloudflare_ips "/tmp/test_cf_ips.txt" && cat "/tmp/test_cf_ips.txt" && rm "/tmp/test_cf_ips.txt"

    # Test UFW update (requires root, simulate)
    _log_section "Testing UFW Update (Dry Run)"
    # update_cloudflare_ufw_allowlist # Requires root, skip in basic test

    # Test secure permissions (simulate)
    _log_section "Testing Secure Permissions (Dry Run)"
    # secure_project_permissions # Requires root/sudo access, skip in basic test

    # Test token generation
    _log_section "Testing Token Generation"
    log_info "Generated Token (32 chars): $(generate_secure_token 32)"
    log_info "Generated Token (64 chars): $(generate_secure_token 64)"

    _log_info "Self-tests complete."
fi
