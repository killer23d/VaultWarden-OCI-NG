#!/usr/bin/env bash
# lib/system.sh - System operations and utilities library

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
    log_info() { echo "[system.sh][INFO] $*"; }
    log_warn() { echo "[system.sh][WARN] $*"; }
    log_error() { echo "[system.sh][ERROR] $*" >&2; }
    log_success() { echo "[system.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    _print_key_value() { printf "%-15s: %s\n" "$1" "$2"; }
fi
# Source constants if available (needed for permissions)
if [[ -f "$LIB_DIR/constants.sh" ]]; then source "$LIB_DIR/constants.sh"; fi


# --- Library functions follow ---

# Set prefix after sourcing logging
_set_log_prefix "system-lib"

# --- Global Variables ---
DETECTED_OS=""            # e.g., ubuntu, centos
DETECTED_OS_VERSION=""    # e.g., 22.04, 24.04
PACKAGE_MANAGER=""        # e.g., apt, dnf
SERVICE_MANAGER="unknown" # Default to unknown, detect later

# --- Helper Functions ---

# Check if a command exists in PATH (more robust than command -v)
# Checks executable flag as well.
_have_cmd() {
    # Check if command exists and is executable
    command -v "$1" >/dev/null 2>&1 && [[ -x "$(command -v "$1")" ]]
}

# Run a command, log start/success/failure, show output only on failure
# Usage: _run_command "description" command arg1 arg2 ...
# Returns: Exit code of the command
_run_command() {
    # Validate input
    [[ $# -lt 2 ]] && { log_error "_run_command: Requires description and command."; return 127; }

    local description="$1"
    shift # Remove description from args
    local output rc

    log_info "Running: $description..."
    _log_debug "Executing: $*"

    # Execute command, capture combined stdout/stderr and return code
    # Use eval for complex commands? Prefer "$@" for safety.
    # Use script to capture output and rc simultaneously reliably
    output=$( ( "$@" ) 2>&1 )
    rc=$?

    if [[ $rc -eq 0 ]]; then
        log_success "Success: $description"
        # Log output on success only in debug mode and if output is not excessively long
        if [[ "${DEBUG:-false}" == "true" && ${#output} -lt 2048 ]]; then
             _log_debug "Output (Success):\n$output"
        elif [[ "${DEBUG:-false}" == "true" ]]; then
              _log_debug "Output (Success) too long, truncated:\n$(echo "$output" | head -n 10)\n..."
        fi
        return 0
    else
        log_error "Failed: $description (Exit Code: $rc)"
        # Log output on failure (limit length?)
        if [[ ${#output} -lt 4096 ]]; then
             log_error "Output (Failure):\n$output"
        else
              log_error "Output (Failure) too long, truncated:\n$(echo "$output" | head -n 20)\n..."
        fi
        return $rc
    fi
}

# Detect OS and package manager
_detect_system() {
    # Only run detection once
    if [[ -n "$DETECTED_OS" ]]; then
        _log_debug "System already detected: OS=$DETECTED_OS, PM=$PACKAGE_MANAGER, SM=$SERVICE_MANAGER"
        return 0
    fi

    _log_debug "Detecting operating system..."
    if [[ -f /etc/os-release ]]; then
        # Use a subshell to source without polluting the main script's env
        # Capture ID, VERSION_ID, PRETTY_NAME
        local os_info_raw id version_id pretty_name
        os_info_raw=$( ( ID=""; VERSION_ID=""; PRETTY_NAME=""; . /etc/os-release && printf "%s|%s|%s" "$ID" "$VERSION_ID" "$PRETTY_NAME" ) ) || { log_error "Failed to source /etc/os-release"; return 1; }

        # Parse the output
        IFS='|' read -r id version_id pretty_name <<< "$os_info_raw"
        DETECTED_OS="${id:-unknown}"
        DETECTED_OS_VERSION="${version_id:-unknown}"

        _log_debug "Detected OS: '$DETECTED_OS', Version: '$DETECTED_OS_VERSION', Name: '$pretty_name'"

        # Determine package manager based on OS ID
        case "$DETECTED_OS" in
            ubuntu|debian|raspbian|pop|linuxmint) PACKAGE_MANAGER="apt" ;;
            centos|rhel|fedora|rocky|almalinux)
                # Prefer dnf if available
                if _have_cmd dnf; then PACKAGE_MANAGER="dnf";
                elif _have_cmd yum; then PACKAGE_MANAGER="yum";
                else PACKAGE_MANAGER="unknown"; fi
                ;;
            arch|manjaro|endeavouros) PACKAGE_MANAGER="pacman" ;;
            alpine) PACKAGE_MANAGER="apk" ;;
            *)
                log_warn "Unknown Linux distribution detected: '$DETECTED_OS'. Attempting package manager fallback."
                if _have_cmd apt; then PACKAGE_MANAGER="apt"
                elif _have_cmd dnf; then PACKAGE_MANAGER="dnf"
                elif _have_cmd yum; then PACKAGE_MANAGER="yum"
                elif _have_cmd pacman; then PACKAGE_MANAGER="pacman"
                elif _have_cmd apk; then PACKAGE_MANAGER="apk"
                else
                    log_error "Could not determine package manager for unknown OS '$DETECTED_OS'."
                    PACKAGE_MANAGER="unknown"
                    # Return failure if package manager unknown? Or just warn? Warn for now.
                    # return 1
                fi
                log_warn "Guessed package manager: '$PACKAGE_MANAGER'"
                ;;
        esac
    else
        log_error "Cannot detect operating system: /etc/os-release not found."
        DETECTED_OS="unknown"
        PACKAGE_MANAGER="unknown"
        return 1
    fi

    # Determine service manager (systemd vs other)
    if _have_cmd systemctl && [[ "$(readlink /proc/1/exe || echo "")" == */systemd ]]; then
         SERVICE_MANAGER="systemctl"
         _log_debug "Service manager: systemd (systemctl)"
    elif _have_cmd service && _have_cmd update-rc.d; then # Basic SysV check (Debian style)
         SERVICE_MANAGER="sysv"
         log_warn "Detected SysV init system. Service management functions may be limited."
    elif _have_cmd rc-service && _have_cmd rc-update; then # OpenRC check (Alpine/Gentoo)
          SERVICE_MANAGER="openrc"
          log_warn "Detected OpenRC init system. Service management functions may be limited."
    else
         SERVICE_MANAGER="unknown"
         log_warn "Could not reliably determine service manager. Service functions disabled."
    fi


    log_info "Detected System: OS='$DETECTED_OS', Version='$DETECTED_OS_VERSION', PM='$PACKAGE_MANAGER', SM='$SERVICE_MANAGER'"
    return 0
}


# --- Package Management ---

# Updates the package index (e.g., apt update)
_update_package_index() {
    _detect_system || return 1 # Ensure system detected
    if [[ "$PACKAGE_MANAGER" == "unknown" ]]; then log_error "Unknown package manager. Cannot update index."; return 1; fi

    log_info "Updating package index using '$PACKAGE_MANAGER'..."
    local cmd_args=() desc="" rc=0

    case "$PACKAGE_MANAGER" in
        apt) cmd_args=("apt-get" "update" "-qq"); desc="APT package index" ;;
        dnf) cmd_args=("dnf" "check-update" "--quiet"); desc="DNF metadata" ;; # check-update updates cache
        yum) cmd_args=("yum" "makecache" "--quiet"); desc="YUM cache" ;; # makecache faster than check-update
        pacman) cmd_args=("pacman" "-Sy" "--noconfirm"); desc="Pacman package database" ;; # -Sy updates repos
        apk) cmd_args=("apk" "update"); desc="APK package index" ;;
        *) log_error "Unsupported package manager: '$PACKAGE_MANAGER'"; return 1 ;;
    esac

    # Run with sudo if not root
    local sudo_prefix=""
    [[ $EUID -ne 0 ]] && _have_cmd sudo && sudo_prefix="sudo "

    # Use _run_command for logging and error handling
    if ! _run_command "$desc" $sudo_prefix "${cmd_args[@]}"; then
         rc=$?
         # Special handling for yum/dnf exit code 100 (updates available, but index updated ok)
         if [[ ("$PACKAGE_MANAGER" == "yum" || "$PACKAGE_MANAGER" == "dnf") && $rc -eq 100 ]]; then
             log_success "Success: $desc (Updates available)"
             return 0
         elif [[ "$PACKAGE_MANAGER" == "pacman" && $rc -eq 0 ]]; then
              # Pacman returns 0 even if no updates, ensure success log
              log_success "Success: $desc"
              return 0
         else
             log_error "Failed to update package index." # Error logged by _run_command
             return $rc
         fi
    fi
     # _run_command logs success on rc=0
    return 0
}

# Installs a package if not already installed
# Usage: _install_package <package_name> [description]
_install_package() {
    local package="$1"
    local description="${2:-package $package}"
    _detect_system || return 1 # Ensure system detected
    if [[ "$PACKAGE_MANAGER" == "unknown" ]]; then log_error "Unknown package manager. Cannot install $package."; return 1; fi

    _log_debug "Checking installation status of $description..."

    if _is_package_installed "$package"; then
         log_success "$description is already installed."
         return 0
     fi

    log_info "Attempting to install $description using '$PACKAGE_MANAGER'..."

    local cmd_args=() update_needed=false

    # Update index before installing if needed (e.g., on apt first install)
    # Could add a flag to force update: _update_package_index || return 1

    case "$PACKAGE_MANAGER" in
        apt)
            # Ensure non-interactive frontend
            export DEBIAN_FRONTEND=noninteractive
            cmd_args=("apt-get" "install" "-y" "-qq" "--no-install-recommends" "$package")
            ;;
        dnf|yum)
            cmd_args=("$PACKAGE_MANAGER" "install" "-y" "-q" "$package")
            ;;
        pacman)
            # Pacman needs -S, requires update first (-Sy)
            _update_package_index || return 1 # Ensure DB is updated before install
            cmd_args=("pacman" "-S" "--noconfirm" "--needed" "$package") # --needed prevents reinstall
            ;;
        apk)
            cmd_args=("apk" "add" "$package")
            ;;
        *) log_error "Unsupported package manager: '$PACKAGE_MANAGER'"; return 1 ;;
    esac

    # Run with sudo if not root
    local sudo_prefix=""
    [[ $EUID -ne 0 ]] && _have_cmd sudo && sudo_prefix="sudo "

    # Attempt installation
    if _run_command "Install $description" $sudo_prefix "${cmd_args[@]}"; then
        # Verify installation after command succeeds
        if _is_package_installed "$package"; then
             # Success logged by _run_command implicitly
             return 0
        else
             log_error "Installation command ran but package '$package' still not detected after installation."
             return 1
        fi
    else
        # Error logged by _run_command
        return 1
    fi
}

# Checks if a package is installed
_is_package_installed() {
    local package="$1"
    _detect_system || return 1 # Ensure system detected
    # No need to log debug here, called frequently

    case "$PACKAGE_MANAGER" in
        apt) dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "ok installed" ;;
        dnf) dnf list installed "$package" >/dev/null 2>&1 ;;
        yum) yum list installed "$package" >/dev/null 2>&1 ;;
        pacman) pacman -Q "$package" >/dev/null 2>&1 ;;
        apk) apk -e info "$package" >/dev/null 2>&1 ;;
        *) log_warn "Cannot check package status for unknown package manager '$PACKAGE_MANAGER'"; return 1 ;; # Return error for unknown PM
    esac
    # Return code of the check command determines install status (0=installed, non-0=not installed/error)
}

# --- Service Management ---

# Wrapper for systemctl actions
_run_systemctl() {
    # Check if systemd is the manager
    if [[ "$SERVICE_MANAGER" != "systemctl" ]]; then
        log_error "Service management requires systemd, but detected '$SERVICE_MANAGER'."
        return 1
    fi

    local action="$1"
    local service_name="$2"
    local description="$3"

    # Run with sudo if not root
    local sudo_prefix=""
    [[ $EUID -ne 0 ]] && _have_cmd sudo && sudo_prefix="sudo "

    # Use _run_command for logging and error handling
    _run_command "$description" ${sudo_prefix}systemctl "$action" "$service_name"
}

# Enable a service to start on boot
_enable_service() { _run_systemctl "enable" "$1" "Enable service '$1'"; }
# Start a service immediately
_start_service() { _run_systemctl "start" "$1" "Start service '$1'"; }
# Stop a service immediately
_stop_service() { _run_systemctl "stop" "$1" "Stop service '$1'"; }
# Reload service configuration (e.g., systemctl reload nginx)
_reload_service() { _run_systemctl "reload" "$1" "Reload service '$1'"; }
# Restart a service (stop then start)
_restart_service() { _run_systemctl "restart" "$1" "Restart service '$1'"; }

# Get service status string (active, inactive, failed, not-found, unknown)
_get_service_status() {
    local service_name="$1"
    if [[ "$SERVICE_MANAGER" != "systemctl" ]]; then echo "unknown"; return; fi

    # Use is-active first (fastest)
    if systemctl is-active --quiet "$service_name"; then echo "active"
    # Check is-failed only if not active
    elif systemctl is-failed --quiet "$service_name"; then echo "failed"
    # Check if the unit exists at all using status (slower)
    elif systemctl status "$service_name" >/dev/null 2>&1; then echo "inactive" # Exists but not active/failed
    else echo "not-found"; fi # Unit file likely doesn't exist
}

# --- Docker Compose Helpers ---

# Check if a specific Docker Compose service is running
# Usage: _compose_service_running <service_name>
_compose_service_running() {
    local service_name="$1"
    # Get project name from env var if set by config.sh, else default
    local compose_project_name="${COMPOSE_PROJECT_NAME:-vaultwarden}"

    _log_debug "Checking if Docker Compose service '$service_name' (project: $compose_project_name) is running..."
    # Ensure docker and compose plugin are available
    if ! _have_cmd docker || ! docker compose version >/dev/null 2>&1; then
        log_error "Docker or Docker Compose plugin not available. Cannot check service status."; return 1;
    fi

    # Use docker compose ps with filters for efficiency and parse JSON output
    local container_info status compose_ps_cmd
    # Command to get status of a specific service in JSON format
    compose_ps_cmd=(docker compose -p "$compose_project_name" ps --format json "$service_name")

    if ! container_info=$("${compose_ps_cmd[@]}" 2>/dev/null); then
        _log_debug("Command '${compose_ps_cmd[*]}' failed. Assuming service '$service_name' not found or compose error.")
        return 1 # Command failed, assume not running or error
    fi

    # Check if output is valid JSON and represents a single service (jq handles empty/multiple)
    if ! command -v jq >/dev/null; then
         log_warn "jq command not found. Cannot accurately parse compose status. Using basic check."
         # Fallback: Check if 'running' appears in non-JSON output
         if docker compose -p "$compose_project_name" ps "$service_name" 2>/dev/null | grep -q 'running'; then
              _log_debug("Service '$service_name' appears to be running (basic check).")
              return 0
         else
              _log_debug("Service '$service_name' not running or not found (basic check).")
              return 1
         fi
    fi

    # Use jq to extract the state of the first (and likely only) container for the service
    status=$(echo "$container_info" | jq -r '.[0].State // empty')

    if [[ "$status" == "running" ]]; then
        _log_debug("Service '$service_name' is running.")
        return 0 # Success (running)
    else
        _log_debug("Service '$service_name' not running (State: '$status').")
        return 1 # Failure (not running or error)
    fi
}

# --- Filesystem Helpers ---

# Create directory with specific permissions and owner (requires sudo if not owner)
# Usage: _create_directory_secure <dir_path> [permissions] [owner:group]
_create_directory_secure() {
    local dir="$1"
    # Use constants if available, else defaults
    local default_perm="750" # Default: u=rwx, g=rx, o=
    local perm="${2:-${DEFAULT_DIR_PERMISSIONS:-$default_perm}}"
    local owner="${3:-$(id -u):$(id -g)}" # Default to current user:group

    local sudo_prefix="" msg_suffix=""
    # Determine if sudo is needed based on target dir parent ownership/permissions
    local parent_dir
    parent_dir=$(dirname "$dir")
    # Need sudo if: not root AND (parent doesn't exist OR parent not writable by current user)
    if [[ $EUID -ne 0 ]] && { [[ ! -d "$parent_dir" ]] || [[ ! -w "$parent_dir" ]]; }; then
        if _have_cmd sudo; then
            sudo_prefix="sudo "
            msg_suffix=" (using sudo)"
        else
            log_error "Cannot create directory '$dir': Need root or sudo, but sudo not found."
            return 1
        fi
    fi

    if [[ ! -d "$dir" ]]; then
        log_info "Creating directory: $dir$msg_suffix"
        # Create directory with sudo if needed
        if ! ${sudo_prefix}mkdir -p "$dir"; then log_error "Failed to create directory: $dir"; return 1; fi
        log_success "Directory created: $dir"
        # Set owner/group immediately after creation if sudo was used or owner specified
        if [[ -n "$sudo_prefix" || "$owner" != "$(id -u):$(id -g)" ]]; then
             if ! ${sudo_prefix}chown "$owner" "$dir"; then log_warn "Failed to set owner '$owner' on $dir"; fi
        fi
        # Set permissions after potential ownership change
        if ! ${sudo_prefix}chmod "$perm" "$dir"; then log_warn "Failed to set permissions '$perm' on $dir"; fi
    else
        _log_debug "Directory already exists: $dir. Ensuring permissions/owner."
        # Ensure owner and permissions are correct even if directory exists
        local current_owner current_perms
        current_owner=$(stat -c "%u:%g" "$dir" 2>/dev/null)
        current_perms=$(stat -c "%a" "$dir" 2>/dev/null)

        if [[ "$current_owner" != "$owner" ]]; then
             if ! ${sudo_prefix}chown "$owner" "$dir"; then log_warn "Failed to set owner '$owner' on existing $dir"; fi
        fi
        if [[ "$current_perms" != "$perm" ]]; then
             if ! ${sudo_prefix}chmod "$perm" "$dir"; then log_warn "Failed to set permissions '$perm' on existing $dir"; fi
        fi
    fi

    return 0
}


# Create file with specific permissions, owner, and optional content
# Usage: _create_file_secure <file_path> [permissions] [content] [owner:group]
_create_file_secure() {
    local file="$1"
    local default_perm="640" # Default: u=rw, g=r, o=
    local perm="${2:-${DEFAULT_FILE_PERMISSIONS:-$default_perm}}"
    local content="${3:-}" # Optional content
    local owner="${4:-$(id -u):$(id -g)}" # Default to current user:group

    _log_debug "Ensuring secure file exists: $file (perms: $perm, owner: $owner)"

    # Ensure parent directory exists first
    _create_directory_secure "$(dirname "$file")" || return 1 # Use default perms/owner for parent dir

    local sudo_prefix="" msg_suffix=""
    # Determine if sudo needed for file creation/modification
    local target_dir
    target_dir=$(dirname "$file")
    # Need sudo if: not root AND (file doesn't exist AND dir not writable OR file exists AND file not writable)
    if [[ $EUID -ne 0 ]] && \
       { { [[ ! -e "$file" ]] && [[ ! -w "$target_dir" ]]; } || \
         { [[ -e "$file" ]] && [[ ! -w "$file" ]]; }; }; then
        if _have_cmd sudo; then
            sudo_prefix="sudo "
            msg_suffix=" (using sudo)"
        else
            log_error "Cannot create/modify file '$file': Need root or sudo, but sudo not found."
            return 1
        fi
    fi

    # Create file if it doesn't exist
    if [[ ! -f "$file" ]]; then
         log_info "Creating file: $file$msg_suffix"
         # Use touch with sudo if needed
         if ! ${sudo_prefix}touch "$file"; then log_error "Failed to create file: $file"; return 1; fi
         log_success "File created: $file"
         # Set owner/group immediately if sudo used or owner specified
         if [[ -n "$sudo_prefix" || "$owner" != "$(id -u):$(id -g)" ]]; then
             if ! ${sudo_prefix}chown "$owner" "$file"; then log_warn "Failed to set owner '$owner' on $file"; fi
         fi
         # Set permissions after potential ownership change
         if ! ${sudo_prefix}chmod "$perm" "$file"; then log_warn "Failed to set permissions '$perm' on new $file"; fi
    else
         _log_debug "File already exists: $file. Ensuring content/permissions/owner."
    fi

    # Write content if provided (potentially overwrites existing content)
    if [[ -n "$content" ]]; then
         _log_debug "Writing content to file: $file$msg_suffix"
         # Use printf with sudo tee for writing content as root if needed
         if ! printf '%s' "$content" | ${sudo_prefix}tee "$file" > /dev/null; then
             log_error "Failed to write content to file: $file"; return 1;
         fi
         _log_debug "Content written."
    fi

    # Ensure owner and permissions are correct on existing or newly written file
    local current_owner current_perms
    current_owner=$(stat -c "%u:%g" "$file" 2>/dev/null)
    current_perms=$(stat -c "%a" "$file" 2>/dev/null)

    if [[ "$current_owner" != "$owner" ]]; then
         if ! ${sudo_prefix}chown "$owner" "$file"; then log_warn "Failed to set owner '$owner' on existing $file"; fi
    fi
    if [[ "$current_perms" != "$perm" ]]; then
         if ! ${sudo_prefix}chmod "$perm" "$file"; then log_warn "Failed to set permissions '$perm' on existing $file"; fi
    fi

    return 0
}


# Backup a file with timestamp
_backup_file() {
    local file="$1"
    local suffix="${2:-.backup.$(date +%Y%m%d_%H%M%S)}"
    if [[ ! -f "$file" ]]; then log_warn "File not found for backup: $file"; return 1; fi

    local dst="${file}${suffix}"
    log_info "Backing up '$file' to '$dst'..."
    # Use cp -a to preserve permissions/ownership if possible
    local sudo_prefix=""
    # Need sudo if reading original requires root or writing backup requires root
    if [[ $EUID -ne 0 ]] && { [[ ! -r "$file" ]] || [[ ! -w "$(dirname "$dst")" ]]; }; then
         _have_cmd sudo && sudo_prefix="sudo "
    fi

    if ${sudo_prefix}cp -a "$file" "$dst"; then
         log_success "Backup successful: $dst"
         return 0
    else
         log_error "Failed to backup file: $file to $dst"
         return 1
    fi
}

# --- Network Helpers ---

# Test basic internet connectivity by pinging a reliable target
_test_connectivity() {
    local host="${1:-1.1.1.1}" # Default to Cloudflare DNS
    local timeout="${2:-3}" # Default 3 second timeout
    _log_debug "Testing network connectivity (ping $host, timeout ${timeout}s)..."

    # Check if ping command exists
    if ! _have_cmd ping; then
         log_warn "ping command not found. Cannot test connectivity."
         return 1 # Indicate failure to test
    fi

    # Use ping with count=1, deadline/timeout
    if ping -c 1 -W "$timeout" "$host" >/dev/null 2>&1; then
        _log_debug "Ping successful."
        return 0 # Success
    else
        _log_debug "Ping failed."
        return 1 # Failure
    fi
}


# --- Initialization & Self-Test ---
# Run initial detection when library is sourced
if ! _detect_system; then
    log_warn "System detection failed during library load. Some functions may be limited."
fi
# Set flag indicating library loaded successfully
SYSTEM_LIB_AVAILABLE=true

# Self-test code runs only if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/system.sh is a library and should be sourced, not executed directly."
     _log_info "Running self-tests..."
     export DEBUG=true # Enable debug logs for test

     _log_section "System Detection Test"
     _detect_system && log_success "System detected successfully."

     _log_section "Command Check Test"
     _have_cmd "bash" && log_success "Self-test: _have_cmd works for 'bash'."
     ! _have_cmd "nonexistentcommand123" && log_success "Self-test: _have_cmd works for non-existent command."

     _log_section "Package Status Test (requires apt/dnf/yum)"
     # Check for a core package likely to be installed
     local core_pkg="bash" # Default
     [[ "$PACKAGE_MANAGER" == "dnf" || "$PACKAGE_MANAGER" == "yum" ]] && core_pkg="bash"
     [[ "$PACKAGE_MANAGER" == "pacman" ]] && core_pkg="bash"
     [[ "$PACKAGE_MANAGER" == "apk" ]] && core_pkg="bash" # Alpine has bash usually
     _is_package_installed "$core_pkg" && log_success "Self-test: _is_package_installed works for '$core_pkg'."
     ! _is_package_installed "nonexistentpackage123" && log_success "Self-test: _is_package_installed works for non-existent package."

     _log_section "Connectivity Test"
     _test_connectivity && log_success "Self-test: _test_connectivity to 1.1.1.1 passed." || log_warn "Self-test: _test_connectivity failed (Network issue or firewall?)."

     _log_section "Filesystem Helpers Test (requires write permission in /tmp)"
     local test_dir="/tmp/system_lib_test_$$"
     local test_file="$test_dir/test.txt"
     _create_directory_secure "$test_dir" "700" && log_success "Self-test: _create_directory_secure created $test_dir"
     _create_file_secure "$test_file" "600" "Hello" && log_success "Self-test: _create_file_secure created $test_file"
     _backup_file "$test_file" && log_success "Self-test: _backup_file created backup."
     rm -rf "$test_dir"* # Clean up test files/dirs

     # Service status test (requires systemd and a known service like sshd or cron)
     _log_section "Service Status Test (requires systemd)"
     if [[ "$SERVICE_MANAGER" == "systemctl" ]]; then
          local test_svc="cron" # Try cron service
          if systemctl status "$test_svc" >/dev/null 2>&1; then # Check if service exists
              local status
              status=$(_get_service_status "$test_svc")
              log_success "Self-test: _get_service_status for '$test_svc' returned '$status'."
          else
              log_warn "Skipping service status test: '$test_svc' service not found."
          fi
     else
          log_info "Skipping service status test (not using systemd)."
     fi

     _log_info "Self-tests complete."
     # Exit with 0 if tests ran (potential issues logged as warnings/errors)
     exit 0
fi
