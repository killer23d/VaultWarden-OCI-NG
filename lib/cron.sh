#!/usr/bin/env bash
# lib/cron.sh - Cron job management library for VaultWarden-OCI-NG

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
    log_info() { echo "[cron.sh][INFO] $*"; }
    log_warn() { echo "[cron.sh][WARN] $*"; }
    log_error() { echo "[cron.sh][ERROR] $*" >&2; }
    log_success() { echo "[cron.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    # Define dummy _set_log_prefix
    _set_log_prefix() { :; }
fi
# Source system library (optional, for service management)
SYSTEM_LIB_AVAILABLE=false
if [[ -f "$LIB_DIR/system.sh" ]]; then
    source "$LIB_DIR/system.sh"
    SYSTEM_LIB_AVAILABLE=true
else
    log_warn "System library (lib/system.sh) not found. Service management functions unavailable."
    # Define dummy functions to prevent hard failures if system.sh is missing
    _get_service_status() { echo "unknown"; }
    _start_service() { log_warn "Cannot start service: system.sh missing."; return 1; }
    _enable_service() { log_warn "Cannot enable service: system.sh missing."; return 1; }
fi
# Source config library (needed for PROJECT_ROOT, PROJECT_STATE_DIR etc in job commands)
CONFIG_LOADED_SUCCESS=false
if [[ -f "$LIB_DIR/config.sh" ]]; then
    source "$LIB_DIR/config.sh"
    if ! load_config > /dev/null 2>&1; then
         log_error "Failed to load project configuration. Cron jobs might use incorrect paths."
         # Define fallback paths if config load fails
         PROJECT_STATE_DIR="/var/lib/vaultwarden" # Default path
    else
         CONFIG_LOADED_SUCCESS=true
         # PROJECT_ROOT should already be defined correctly
         # PROJECT_STATE_DIR is exported by load_config
    fi
else
     log_error "Config library (lib/config.sh) not found. Cron jobs might use incorrect paths."
     PROJECT_STATE_DIR="/var/lib/vaultwarden" # Default path
fi


# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "cron"

# --- Helper Functions ---

# Check if crontab command is available
_check_crontab_cmd() {
    # Use _have_cmd from system.sh if available
    local check_func="_have_cmd"
    if ! declare -f "$check_func" >/dev/null; then check_func="command -v"; fi

    if ! "$check_func" crontab >/dev/null 2>&1; then
        log_error "crontab command not found. Cannot manage cron jobs."
        log_info "On Debian/Ubuntu, install via: sudo apt install cron"
        return 1
    fi
    _log_debug("crontab command found.")
    return 0
}

# Safely get crontab content for a user, returns empty string on error or if none exists
_get_crontab_content() {
    local user="$1"
    # Execute crontab command, capture output, ignore stderr if crontab is empty (rc=1)
    local output rc=0
    output=$(crontab -u "$user" -l 2>/dev/null) || rc=$?
    # Only return output if rc is 0 (crontab exists)
    if [[ $rc -eq 0 ]]; then
        echo "$output"
    else
        # If rc is not 0, it means crontab doesn't exist or another error occurred.
        # Check if the error was simply "no crontab" - this is not an error state.
         if crontab -u "$user" -l 2>&1 | grep -q 'no crontab for'; then
              _log_debug("No crontab found for user '$user'.")
         else
              log_warn("Error reading crontab for user '$user' (rc=$rc). Assuming empty.")
         fi
        echo "" # Return empty string
    fi
}

# Safely update crontab content for a user using a temporary file
_update_crontab_content() {
    local user="$1"
    local content="$2"
    local temp_cronfile rc=0

    temp_cronfile=$(mktemp) || { log_error "Failed to create temporary file for crontab update."; return 1; }
    trap 'rm -f "$temp_cronfile"' RETURN # Ensure temp file cleanup

    # Write new content to temp file
    echo "$content" > "$temp_cronfile"

    # Use crontab command to replace the user's crontab with the temp file content
    _log_debug("Updating crontab for user '$user' using temp file: $temp_cronfile")
    crontab -u "$user" "$temp_cronfile" || rc=$? # Capture exit code

    if [[ $rc -ne 0 ]]; then
        log_error "Failed to update crontab for user '$user' (rc=$rc). Check permissions or crontab syntax."
        # Optionally log the content that failed:
        _log_debug "Failed crontab content:\n$content"
        return 1
    fi
    # Cleanup handled by trap
    return 0
}


# --- Public Functions ---

# Add or update a cron job for a specific user (idempotent).
# Uses a unique comment marker to identify and manage the job.
# Usage: add_cron_job <user> <schedule> <command> <description>
add_cron_job() {
    local user="$1"
    local schedule="$2"
    local command="$3"
    local description="$4" # Now mandatory for a clear ID

    if ! _check_crontab_cmd; then return 1; fi
    if [[ -z "$description" ]]; then
        log_error "Job description is required for add_cron_job."
        return 1
    fi

    # Create a unique identifier comment for this job
    # Use a standardized marker format for easier parsing/removal
    local job_id_comment="# VaultWarden-NG Job: ${description}"
    local job_line="$schedule $command"

    _log_debug("Checking for existing cron job: $description")
    local current_crontab
    current_crontab=$(_get_crontab_content "$user")

    # Check if job already exists (match comment and exact command line)
    # Use grep -F for fixed string matching, handle potential regex chars in command
    # Need to handle potential leading/trailing whitespace around command? Maybe not needed if we manage it.
    local job_exists=false
    if grep -Fxq "$job_id_comment" <<< "$current_crontab" && \
       grep -Fq "$job_line" <<< "$current_crontab"; then
        # Check if the line following the comment *is* the job line (more robust)
        if grep -A 1 -Fxq "$job_id_comment" <<< "$current_crontab" | tail -n 1 | grep -Fq "$job_line"; then
             log_info "Cron job already exists and is up-to-date for '$user': $description"
             return 0 # Job exists and matches, nothing to do
        else
             log_warn("Cron job comment found but command line differs for '$user': $description. Updating.")
        fi
    elif grep -Fxq "$job_id_comment" <<< "$current_crontab"; then
         log_warn("Cron job comment found but command line missing/differs for '$user': $description. Updating.")
    else
         _log_debug("Cron job not found for '$user': $description. Adding.")
    fi

    # --- Add/Update Logic ---
    log_info "Adding/Updating cron job for '$user': $description"

    # Remove potential old versions first based ONLY on the unique comment marker
    # This ensures that if the schedule or command changes, the old entry is removed.
    local updated_crontab
    # Use sed to delete the block: from the comment line up to the next empty line OR end of file.
    # Regex breakdown:
    # \:^${job_id_comment}$:       Start range at the exact comment line
    # ,                            To
    # /^\s*$/                      End range at the next line containing only whitespace (or empty)
    # {//!p}                       If end range pattern not found, print lines (GNU sed extension for EOF)
    # d                            Delete the lines within the range
    # Need a robust way to handle EOF - maybe process line by line?
    # Simpler sed: Delete the comment line and the line immediately following it. Assumes structure.
    updated_crontab=$(echo "$current_crontab" | sed -e "\:^${job_id_comment}$: { N; d; }" -e "\:^${job_id_comment}$: d")

    # Append the new job (comment, command, empty line for separation)
    # Ensure updated_crontab doesn't have trailing newlines before appending
    updated_crontab=$(echo -n "$updated_crontab"; printf '\n%s\n%s\n\n' "$job_id_comment" "$job_line")
    # Remove leading blank lines potentially added if original crontab was empty
    updated_crontab=$(echo "$updated_crontab" | sed '/./,$!d')

    # Apply the updated crontab
    if _update_crontab_content "$user" "$updated_crontab"; then
        log_success "Successfully added/updated cron job for '$user': $description"
        return 0
    else
        # Error logged by _update_crontab_content
        return 1
    fi
}

# Setup all standard VaultWarden maintenance cron jobs for root user.
# Usage: setup_cron_jobs [auto_mode]
setup_cron_jobs() {
    local auto_mode="${1:-false}" # Default to interactive (prompt user)
    local cron_user="root" # Maintenance tasks typically need root

    if ! _check_crontab_cmd; then return 1; fi

    _log_section "Setting Up Automated Maintenance Cron Jobs for User '$cron_user'"

    # Define the jobs to be added/managed
    # Structure: schedule|command|description
    # Use $PROJECT_ROOT and $PROJECT_STATE_DIR vars which should be set
    local log_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}/logs" # Use default if state dir not loaded
    local jobs=(
        # Health monitoring every 5 minutes (adjust schedule if too frequent)
        "*/5 * * * *|cd $PROJECT_ROOT && ./tools/monitor.sh --auto-heal >> ${log_dir}/monitor-cron.log 2>&1|Health monitor & auto-heal"
        # Daily database backup at 2 AM
        "0 2 * * *|cd $PROJECT_ROOT && ./tools/backup-monitor.sh --db-only >> ${log_dir}/backup-cron.log 2>&1|Daily database backup"
        # Weekly full backup + Emergency Kit (triggered by backup-monitor) on Sunday at 1 AM
        "0 1 * * 0|cd $PROJECT_ROOT && ./tools/backup-monitor.sh --full >> ${log_dir}/backup-cron.log 2>&1|Weekly full system backup & kit"
        # Weekly host OS maintenance on Sunday at 3 AM
        "0 3 * * 0|cd $PROJECT_ROOT && ./tools/host-maintenance.sh --auto >> ${log_dir}/maintenance-cron.log 2>&1|Weekly host OS updates & cleanup"
        # Daily Cloudflare IP updates at 6 AM (needs root for UFW)
        # Note: update-firewall-rules internally calls update-cloudflare-ips
        "0 6 * * *|cd $PROJECT_ROOT && ./tools/update-firewall-rules.sh >> ${log_dir}/firewall-update-cron.log 2>&1|Daily Cloudflare IP update (UFW/Caddy)"
        # Weekly database optimization on Monday at 4 AM
        "0 4 * * 1|cd $PROJECT_ROOT && ./tools/sqlite-maintenance.sh -t full >> ${log_dir}/sqlite-maint-cron.log 2>&1|Weekly database optimization (full)"
         # Daily check for container updates (using Watchtower run-once) at 5 AM
         "0 5 * * *|cd $PROJECT_ROOT && docker compose run --rm watchtower >> ${log_dir}/watchtower-cron.log 2>&1|Daily container update check (notify only)"
    )

    # Confirmation prompt if not in auto mode
    if [[ "$auto_mode" != "true" ]]; then
        log_info "The following automated maintenance jobs will be scheduled for user '$cron_user':"
        local i=1 schedule command desc
        for job_def in "${jobs[@]}"; do
            IFS='|' read -r schedule command desc <<< "$job_def"
            printf "  %d. [%s] %s (%s)\n" "$i" "$schedule" "$desc" "$command"
            ((i++))
        done
        # Use log_confirm if available (needs interaction support), otherwise simple read
         local response="Y" # Default to Yes
         if declare -f _log_confirm >/dev/null; then
             _log_confirm "Enable/Update these automated maintenance jobs?" "Y" || response="N"
         else
             read -p "Enable/Update these automated maintenance jobs? [Y/n]: " -r response_raw
             response=${response_raw:-Y} # Default to Yes if empty
         fi

        if [[ ! "$response" =~ ^[yY]([eE][sS])?$ ]]; then
            log_info "Skipping automated cron job setup as requested by user."
            return 0
        fi
    else
         log_info "Auto mode enabled. Setting up cron jobs non-interactively."
    fi

    # Add/Update each job using the add_cron_job function
    local schedule command desc job_def errors=0
    for job_def in "${jobs[@]}"; do
        IFS='|' read -r schedule command desc <<< "$job_def"
        if ! add_cron_job "$cron_user" "$schedule" "$command" "$desc"; then
             ((errors++))
        fi
    done

    # Ensure cron service is running and enabled (using system.sh functions)
    local cron_service_name="cron" # Default for Debian/Ubuntu
     # Add detection for other systems if needed (e.g., crond on CentOS)
     if [[ "$DETECTED_OS" =~ ^(centos|rhel|fedora|rocky|almalinux)$ ]]; then cron_service_name="crond"; fi

    if [[ "$SYSTEM_LIB_AVAILABLE" == "true" ]]; then
        local current_status
        current_status=$(_get_service_status "$cron_service_name")
        _log_debug("Cron service ($cron_service_name) status: $current_status")
        if [[ "$current_status" != "active" ]]; then
             log_info "Attempting to start and enable '$cron_service_name' service..."
             # Need to run systemctl with sudo if we are not root
             local sudo_prefix=""
             [[ $EUID -ne 0 ]] && sudo_prefix="sudo "

             # Use direct systemctl calls or _run_command if preferred
             if ! ${sudo_prefix}systemctl is-enabled --quiet "$cron_service_name"; then
                  ${sudo_prefix}systemctl enable "$cron_service_name" || log_warn "Failed to enable $cron_service_name service."
             fi
             if ! ${sudo_prefix}systemctl is-active --quiet "$cron_service_name"; then
                  ${sudo_prefix}systemctl start "$cron_service_name" || log_warn "Failed to start $cron_service_name service."
             fi
             # Re-check status
              current_status=$(_get_service_status "$cron_service_name")
              if [[ "$current_status" == "active" ]]; then log_success("Cron service '$cron_service_name' is active."); else log_error("Cron service '$cron_service_name' failed to start."); fi
        else
             log_info("Cron service '$cron_service_name' is already active.")
        fi
    else
         log_warn "Cannot verify cron service status: system.sh missing or failed to load. Ensure cron service ('$cron_service_name') is running and enabled manually."
    fi


    # Report final status
    if [[ $errors -eq 0 ]]; then
        log_success "All automated maintenance jobs scheduled successfully for user '$cron_user'."
    else
        log_error "$errors error(s) occurred while scheduling cron jobs."
        return 1
    fi
    log_info "View current jobs for user '$cron_user' with: sudo crontab -u $cron_user -l"
    return 0
}

# Remove all VaultWarden-NG managed cron jobs for a specific user.
# Usage: remove_cron_jobs [user]
remove_cron_jobs() {
    local user="${1:-root}" # Default to root user

    if ! _check_crontab_cmd; then return 1; fi

    _log_section "Removing VaultWarden-NG Cron Jobs for user '$user'"

    local current_crontab updated_crontab removed_count=0
    current_crontab=$(_get_crontab_content "$user")

    # Use sed to filter out lines matching the comment pattern and the line immediately following it
    # Assumes the structure: Comment \n Job \n \n (or EOF)
    # Regex: Match comment, read next line into pattern space (N), delete both (d)
    updated_crontab=$(echo "$current_crontab" | sed -e '/^# VaultWarden-NG Job:/ { N; d; }' -e '/^# VaultWarden-NG Job:/d')
    # Count removed lines (approximate, counts pairs of lines removed)
    removed_count=$(( ($(echo "$current_crontab" | wc -l) - $(echo "$updated_crontab" | wc -l)) / 2 ))


    if [[ "$current_crontab" == "$updated_crontab" ]]; then
        log_info "No VaultWarden-NG managed cron jobs found to remove for user '$user'."
        return 0
    fi

    log_info "Removing $removed_count VaultWarden-NG cron job(s) for user '$user'..."
    if _update_crontab_content "$user" "$updated_crontab"; then
        log_success "VaultWarden-NG cron jobs removed successfully for user '$user'."
        return 0
    else
        # Error logged by _update_crontab_content
        return 1
    fi
}

# List current VaultWarden-NG managed cron jobs for a user.
# Usage: list_cron_jobs [user]
list_cron_jobs() {
    local user="${1:-root}" # Default to root user

    if ! _check_crontab_cmd; then return 1; fi

    _log_section "Current VaultWarden-NG Cron Jobs for user '$user'"

    local current_crontab job_blocks
    current_crontab=$(_get_crontab_content "$user")

    # Extract blocks starting with the comment (comment line + next line)
    # Use grep -A 1 to get the comment and the line after it
    job_blocks=$(echo "$current_crontab" | grep -A 1 "^# VaultWarden-NG Job:")

    if [[ -n "$job_blocks" ]]; then
        echo "--- Found Jobs ---"
        # Print the blocks, remove grep's "--" separator lines
        echo "$job_blocks" | grep -v "^--$"
        echo "------------------"
        return 0
    else
        log_info "No VaultWarden-NG managed cron jobs found for user '$user'."
        return 1 # Indicate none found (use return code, not output)
    fi
}

# --- Self-Test / Source Guard ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/cron.sh is a library and should be sourced, not executed directly."
     _log_info "Running self-test..."
     export DEBUG=true # Enable debug for test
     # Example usage (requires root or user with crontab permissions)
     _log_section "Self-Test: Current User ($USER)"
     add_cron_job "$USER" "* * * * *" "echo 'Test cron job' >> /tmp/cron_test.log" "Test Job"
     list_cron_jobs "$USER"
     remove_cron_jobs "$USER"
     list_cron_jobs "$USER"

     _log_section "Self-Test: Root User (requires sudo)"
     if [[ $EUID -eq 0 ]]; then
         echo "Testing root cron jobs..."
         setup_cron_jobs true # Auto mode for testing
         list_cron_jobs root
         remove_cron_jobs root
         list_cron_jobs root
         echo "Root cron job test complete."
     else
          echo "Run as root (sudo ./lib/cron.sh) to test setup/removal of root cron jobs."
     fi
     _log_info "Self-test finished."
     exit 0
else
     _log_debug "lib/cron.sh loaded successfully as a library."
fi
