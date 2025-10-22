#!/usr/bin/env bash
# tools/add-console-admin.sh - Interactively adds a new administrative user for console/emergency access.

# Ensure strict mode and error handling
set -euo pipefail

# --- Standardized Project Root Resolution ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# No cd needed as this script primarily interacts with system utilities

# --- Standardized Library Sourcing ---
# This script is designed to be relatively standalone for emergency use,
# so it avoids sourcing most libraries except for basic logging if available.
if [[ -f "$PROJECT_ROOT/lib/logging.sh" ]]; then
    source "$PROJECT_ROOT/lib/logging.sh"
else
    # Minimal logging functions if library missing
    # Colors defined below
    log_info() { echo -e "${GREEN:-}✓${NC:-} $1"; }
    log_warn() { echo -e "${YELLOW:-}⚠️${NC:-} $1"; }
    log_error() { echo -e "${RED:-}✗${NC:-} $1" >&2; } # Errors to stderr
    log_success() { log_info "$@"; } # Alias success to info
    _log_debug() { if [[ "${DEBUG:-false}" == "true" ]]; then echo "[DEBUG] $*"; fi }
    log_header() { echo "=== $* ==="; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi
# Set script-specific log prefix (best effort)
_set_log_prefix "$(basename "$0" .sh)"

# --- Color and formatting definitions ---
# Use standard colors if available, otherwise empty strings
if [[ -t 1 ]]; then
    readonly BOLD='\033[1m'
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m' # Bold Yellow for Warn
    readonly NC='\033[0m' # No Color
else
    # Assign empty strings if not a terminal
    readonly BOLD='' RED='' GREEN='' YELLOW='' NC=''
fi


# --- Check for root privileges ---
check_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        log_error "This script must be run with sudo privileges."
        log_info "Try: sudo $0 $*"
        exit 1
    fi
}

# --- Check for required commands ---
check_commands() {
    local missing=0
    # Add head, tr, fold for password complexity checks and generation
    local cmds=("useradd" "chpasswd" "usermod" "id" "grep" "sed" "read" "hostname" "awk" "date" "mv" "head" "tr" "fold" "stat")
    # SSH related commands only checked if SSH modification is attempted
    # cmds+=("sshd" "systemctl" "cp") # cp already included via coreutils essentially
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required system command not found: $cmd"
            ((missing++))
        fi
    done
    if [[ $missing -gt 0 ]]; then
        log_error "Please install the missing commands (e.g., via 'sudo apt install coreutils passwd openssh-server systemd ...') and try again."
        exit 1
    fi
}

# --- Main Logic ---
main() {
    check_root "$@" # Pass all arguments to check_root, though it doesn't use them
    check_commands

    echo -e "${BOLD}Create a New Admin User for Console/Emergency Access${NC}"
    echo "This script guides you through creating a new user with sudo privileges."
    echo "Intended for emergency console access or SSH from trusted internal networks."
    echo "------------------------------------------------------------------"

    # --- 1. Get Username ---
    local username=""
    while true; do
        read -p "Enter the username for the new admin (lowercase, no spaces): " username
        if [[ -z "$username" ]]; then
            log_error "Username cannot be empty."
        # Use POSIX compliant check for username validity
        elif ! [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
            log_error "Invalid username format."
            log_info "Must start with a lowercase letter or underscore, followed by lowercase letters, numbers, underscores, or hyphens."
        elif id "$username" &>/dev/null; then
            log_error "User '$username' already exists. Please choose a different name."
        else
            _log_debug "Username '$username' is valid."
            break
        fi
    done

    # --- 2. Get and Validate Password ---
    local password="" password_confirm="" use_anyway="" complexity_ok=false
    while true; do
        read -s -p "Enter a complex password for '$username': " password
        echo
        read -s -p "Confirm the password: " password_confirm
        echo

        if [[ "$password" != "$password_confirm" ]]; then
            log_error "Passwords do not match. Please try again."
            continue
        fi

        # Password Policy Checks
        local min_len=12
        local complexity_issues=()

        # Length check
        if [[ ${#password} -lt $min_len ]]; then
            complexity_issues+=("too short (min $min_len chars)")
        fi

        # Complexity checks (require at least 3 of 4 categories)
        local has_upper=false has_lower=false has_digit=false has_special=false categories_met=0
        [[ "$password" =~ [[:upper:]] ]] && has_upper=true && ((categories_met++))
        [[ "$password" =~ [[:lower:]] ]] && has_lower=true && ((categories_met++))
        [[ "$password" =~ [[:digit:]] ]] && has_digit=true && ((categories_met++))
        # Use POSIX character class for special characters
        [[ "$password" =~ [^[:alnum:]] ]] && has_special=true && ((categories_met++))

        if [[ "$categories_met" -lt 3 ]]; then
             local missing_types=()
             [[ "$has_upper" == false ]] && missing_types+=("uppercase letter")
             [[ "$has_lower" == false ]] && missing_types+=("lowercase letter")
             [[ "$has_digit" == false ]] && missing_types+=("number")
             [[ "$has_special" == false ]] && missing_types+=("special character")
             complexity_issues+=("lacks complexity (needs at least 3 of: ${missing_types[*]})")
        fi

        # Report issues
        if [[ ${#complexity_issues[@]} -gt 0 ]]; then
            log_error "Password issue(s): ${complexity_issues[*]}. "
            # Allow override? For emergency user, maybe enforce strictness.
            # read -p "Do you want to use this password anyway? (y/N): " use_anyway
            # if [[ ! "$use_anyway" =~ ^[Yy]$ ]]; then
            #     continue # Ask for password again
            # fi
            # Make it strict - force compliance
            log_error "Please choose a stronger password that meets the criteria."
            continue # Ask for password again
        fi

        # Password accepted
        complexity_ok=true
        break
    done

    # --- 3. Create User and Grant Privileges ---
    log_info "Creating user '$username'..."
    # Create user with home directory (-m), bash shell (-s), and add to default group (usually user's name)
    # Add -U to create a group with the same name as the user (common practice)
    if ! useradd -m -s /bin/bash -U "$username"; then
        log_error "Failed to create user '$username'."
        exit 1
    fi
    log_success "User '$username' created successfully."

    log_info "Setting password for '$username'..."
    # Pipe password to chpasswd (more secure than command line arg)
    if ! echo "$username:$password" | chpasswd; then
         log_error "Failed to set password for '$username'. Manual intervention needed: sudo passwd $username"
         # Continue with sudo group addition? Yes, proceed but warn user.
         local passwd_set_failed=true
    else
         log_success "Password set successfully."
         local passwd_set_failed=false
    fi
    # Clear password variable from memory (bash doesn't guarantee, but good practice)
    unset password password_confirm use_anyway

    log_info "Adding '$username' to the 'sudo' group for root privileges..."
    # Add user to sudo group (Debian/Ubuntu specific). Use 'wheel' for CentOS/RHEL.
    local sudo_group="sudo"
    # Basic check for RHEL family
    if [[ -f /etc/redhat-release ]]; then sudo_group="wheel"; fi
    log_info "(Using group '$sudo_group' for sudo privileges on this system)"

    if ! usermod -aG "$sudo_group" "$username"; then
        log_error "Failed to grant sudo privileges to '$username'."
        log_info "Manual step required: sudo usermod -aG $sudo_group $username"
        local sudo_add_failed=true
    else
        log_success "User '$username' added to '$sudo_group' group."
        local sudo_add_failed=false
    fi

    # --- 4. (Optional) Allow Internal SSH with Password ---
    echo "------------------------------------------------------------------"
    log_warn "Standard security practice is to disable password-based SSH logins globally."
    log_warn "VaultWarden-OCI-NG typically hardens SSH this way in its setup/maintenance."
    read -p "Allow password login for '$username' ONLY from a trusted IP range (e.g., internal network)? (y/N): " allow_ssh

    local ssh_modified=false trusted_range="" # Track if SSH was modified

    if [[ "$allow_ssh" =~ ^[Yy]$ ]]; then
         # Check SSH-related commands needed for this section
         local ssh_cmds_missing=0
         for cmd in sshd systemctl cp mv grep sed; do
            if ! command -v "$cmd" >/dev/null 2>&1; then log_error "SSH modification needs command: $cmd"; ((ssh_cmds_missing++)); fi
         done
         if [[ $ssh_cmds_missing -gt 0 ]]; then
              log_error "Cannot modify SSH config due to missing commands. Skipping SSH step."
              allow_ssh="N" # Force skip
         fi
    fi


    if [[ "$allow_ssh" =~ ^[Yy]$ ]]; then
        local detected_ip suggested_subnet
        # Try to get primary private IP robustly
        detected_ip=$(ip -4 route get 1.1.1.1 | awk '/src/ {print $7}' 2>/dev/null || hostname -I | awk '{print $1}' 2>/dev/null || echo "?.?.?.?")
        # Suggest /24 subnet based on detected IP if possible
        if [[ "$detected_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
             suggested_subnet="${detected_ip%.*}.0/24"
        else
             suggested_subnet="YOUR_TRUSTED_IP/NETMASK" # Placeholder if IP detection failed
        fi


        echo "This VM's primary detected IP is: ${BOLD}${detected_ip}${NC}"
        read -p "Enter the trusted source IP address or CIDR range (e.g., 10.0.1.0/24, 192.168.1.15) [default: $suggested_subnet]: " trusted_range
        trusted_range=${trusted_range:-$suggested_subnet}

        # Validate CIDR/IP format loosely (digit(s).digit(s).digit(s).digit(s)[/digit(s)])
        # Improve regex slightly
        if [[ ! "$trusted_range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            log_error "Invalid IP/CIDR format '$trusted_range'. Aborting SSH modification."
        else
            local SSHD_CONFIG="/etc/ssh/sshd_config"
            local MATCH_BLOCK SSHD_BACKUP SSHD_BACKUP_TIMESTAMP

            # Check if config file exists and is readable
             if [[ ! -r "$SSHD_CONFIG" ]]; then
                  log_error "SSH configuration file '$SSHD_CONFIG' not found or not readable. Cannot modify SSH settings."
             else
                  SSHD_BACKUP_TIMESTAMP=$(date +%Y%m%d%H%M%S)
                  SSHD_BACKUP="${SSHD_CONFIG}.bak.${SSHD_BACKUP_TIMESTAMP}"

                  log_info "Backing up current SSH configuration to ${SSHD_BACKUP}..."
                  if ! cp "$SSHD_CONFIG" "$SSHD_BACKUP"; then
                       log_error "Failed to create SSH config backup. Aborting modification."
                  else
                       log_success "SSH config backed up to $SSHD_BACKUP."

                       log_info "Modifying '$SSHD_CONFIG' to allow password login for '$username' from '$trusted_range'..."

                       # Remove any *exact* previous block added by this script for this user/range combo
                       # Use sed with explicit start/end markers
                       local start_marker="# START VAULTWARDEN_ADMIN_SSH $username $trusted_range"
                       local end_marker="# END VAULTWARDEN_ADMIN_SSH $username $trusted_range"
                       # Delete lines between markers (inclusive)
                       sed -i -e "\:^${start_marker}$:,\:^${end_marker}$: d" "$SSHD_CONFIG"
                       _log_debug("Removed any previous matching SSH block for $username from $trusted_range.")

                       # Define the new block with markers
                       # Ensure newline before start marker if file doesn't end with one
                       MATCH_BLOCK="\n${start_marker}\nMatch User $username Address $trusted_range\n    PasswordAuthentication yes\n${end_marker}"

                       # Add the new Match block at the end of the file
                       echo -e "$MATCH_BLOCK" >> "$SSHD_CONFIG"
                       log_info "Match block added to the end of '$SSHD_CONFIG'."

                       log_info "Validating new SSH configuration ('sshd -t')..."
                       if sshd -t; then
                           log_success "SSH configuration syntax is valid."
                           log_info "Reloading SSH service (systemctl reload sshd)..."
                           if systemctl reload sshd; then
                               log_success "SSH service reloaded. '$username' can now log in with password from '$trusted_range'."
                               ssh_modified=true # Mark SSH as successfully modified
                           else
                                log_error "Failed to reload SSH service. Configuration added but not active."
                                log_info "Manual reload needed: sudo systemctl reload sshd"
                                # Configuration file was changed but service not reloaded - attempt rollback?
                                log_warn "Attempting to rollback SSH configuration change due to reload failure..."
                                if mv "$SSHD_BACKUP" "$SSHD_CONFIG"; then
                                     log_success "SSH configuration rolled back."
                                else
                                     log_error "CRITICAL: Failed to rollback SSH configuration! Manual check needed: $SSHD_CONFIG"
                                fi
                           fi
                       else
                           log_error "SSH configuration validation FAILED after modification!"
                           log_error "Restoring SSH configuration from backup: $SSHD_BACKUP"
                           if ! mv "$SSHD_BACKUP" "$SSHD_CONFIG"; then
                               log_error "CRITICAL: Failed to restore SSH backup automatically!"
                               log_error "Your SSH configuration might be broken. Restore manually from a .bak file."
                           else
                                log_success "SSH configuration restored from backup. No changes were applied."
                           fi
                       fi # End sshd -t check
                  fi # End backup success block
             fi # End sshd_config readable check
        fi # End CIDR format valid block
    else
        log_info "Skipping SSH modification. User '$username' intended for console access only."
    fi # End allow_ssh block

    # --- 5. Final Summary ---
    echo "------------------------------------------------------------------"
    log_success "${BOLD}Setup Complete!${NC}"
    log_info "User '$username' created."

    # Verify outcomes
    if [[ "$passwd_set_failed" == true ]]; then
         log_error "Password setting FAILED. Set manually: sudo passwd $username"
    else
         log_info "Password set for '$username'."
    fi
    if [[ "$sudo_add_failed" == true ]]; then
        log_error "Granting sudo privileges FAILED. Add manually: sudo usermod -aG $sudo_group $username"
    else
         log_info "User '$username' has sudo privileges (member of '$sudo_group')."
    fi

    log_info "Use this user for OCI Cloud Console access or SSH (if enabled)."
    if [[ "$ssh_modified" == true ]]; then
        log_success "Password SSH for '$username' is enabled ONLY from '$trusted_range'."
    else
         log_info "Password SSH for '$username' remains disabled or was not modified by this script."
         log_info "(Global setting 'PasswordAuthentication no' in $SSHD_CONFIG likely still applies)."
    fi
    echo "------------------------------------------------------------------"
}

# --- Script Entry Point ---
# Run main function, passing all script arguments
main "$@"
