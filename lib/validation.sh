#!/usr/bin/env bash
# lib/validation.sh - System and prerequisite validation library

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
    log_info() { echo "[validation.sh][INFO] $*"; }
    log_warn() { echo "[validation.sh][WARN] $*"; }
    log_error() { echo "[validation.sh][ERROR] $*" >&2; }
    log_success() { echo "[validation.sh][SUCCESS] $*"; }
    _log_debug() { :; }
    _log_section() { echo "--- $* ---"; }
    log_header() { echo "=== $* ==="; } # Added fallback
fi

# Source system library for OS detection and command checks
if [[ ! -f "$LIB_DIR/system.sh" ]]; then
    log_error "Critical library not found: lib/system.sh"
    exit 1 # Critical dependency
fi
# shellcheck source=/dev/null
source "$LIB_DIR/system.sh"

# --- Library functions follow ---

_set_log_prefix "validation" # Use internal function from logging.sh


# --- Configuration ---
MIN_RAM_MB=1024   # Minimum required RAM in MB (increased to 1GB for better stability)
MIN_DISK_GB=10    # Minimum free disk space in GB on root/project partition (increased)
REQUIRED_COMMANDS=(
    "curl" "jq" "docker" "sqlite3" "age" "sops" "tar" "gzip" "openssl" "flock"
    "envsubst" "stat" "find" "chmod" "chown" "mkdir" "rm" "mv" "awk" "sed" "grep" "date"
    "shred" # Added shred
)
# Systemd check is separate
SUPPORTED_OS=("ubuntu" "debian") # Define supported OS IDs from /etc/os-release

# --- Input Validation Functions ---

# Validate email format using regex
validate_email_format() {
    local email="${1:-}" # Ensure variable exists even if empty
    _log_debug "Validating email format: '$email'"

    # Security: Check for empty input
    if [[ -z "$email" ]]; then
        log_error "Email cannot be empty (security requirement)"
        return 1
    fi

    # Security: Check for maximum length (prevent buffer overflow, RFC 5321 limit + practical limits)
    if [[ ${#email} -gt 254 ]]; then # Practical limit often cited
        log_error "Email too long (max 254 characters): $email"
        return 1
    fi

    # Security: Check for basic format validity (improved regex)
    # Allows common characters, requires @, domain part with at least one dot, TLD >= 2 letters
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid email format: $email"
        log_info "Expected format: user@domain.com (e.g., RFC 5322 basic)"
        return 1
    fi

    # Security: Additional validation for common attack patterns (stricter)
    # Disallow shell metacharacters, HTML tags, semicolons, backticks, dollar signs in typical emails
    if [[ "$email" =~ [<>\'\"\\;&\`$()] ]]; then
        log_error "Email contains potentially dangerous characters: $email"
        return 1
    fi

    # Security: Check for null bytes (added check)
    if [[ "$email" == *$'\0'* ]]; then
        log_error "Email contains null bytes (security risk): $email"
        return 1
    fi

    log_success "Email format valid and secure: $email"
    return 0
}

# Validate domain format using regex (no protocol allowed, RFC 1123 compliant)
validate_domain_format() {
    local domain="${1:-}" # Ensure variable exists
    _log_debug "Validating domain format: '$domain'"
    local clean_domain="$domain" # Work with a copy

    # Security: Check for empty input
    if [[ -z "$clean_domain" ]]; then
        log_error "Domain cannot be empty (security requirement)"
        return 1
    fi

    # Security: Remove protocol if present (with warning)
    if [[ "$clean_domain" =~ ^https?:// ]]; then
        log_warn "Security: Removing protocol from domain: $clean_domain"
        clean_domain="${clean_domain#http://}"
        clean_domain="${clean_domain#https://}"
        log_info "Using sanitized domain: $clean_domain"
        # Export or make available the cleaned domain if needed by caller
        export CLEAN_DOMAIN="$clean_domain" # Example: export for init-setup.sh
    else
         # Ensure CLEAN_DOMAIN is set even if no stripping occurred
         export CLEAN_DOMAIN="$clean_domain"
    fi

    # Security: Remove trailing slash if present
    if [[ "$clean_domain" == */ ]]; then
         log_warn "Security: Removing trailing slash from domain: $clean_domain"
         clean_domain="${clean_domain%/}"
         export CLEAN_DOMAIN="$clean_domain"
         log_info "Using sanitized domain: $clean_domain"
    fi

    # Security: Check for maximum length (DNS limit)
    if [[ ${#clean_domain} -gt 253 ]]; then
        log_error "Domain too long (max 253 characters): $domain"
        return 1
    fi

    # Security: Check for dangerous characters (stricter: allow only alphanum, hyphen, dot)
    if [[ "$clean_domain" =~ [^a-zA-Z0-9.-] ]]; then
        log_error "Domain contains invalid characters: $domain (only A-Z, a-z, 0-9, hyphen, dot allowed)"
        return 1
    fi
     # Further refine check for characters disallowed by RFCs if needed (e.g., spaces)
     if [[ "$clean_domain" =~ [<>\'\"\\;&\`$()[:space:]] ]]; then
         log_error "Domain contains dangerous or disallowed characters: $domain"
         return 1
     fi

    # Security: Check for null bytes (added check)
    if [[ "$clean_domain" == *$'\0'* ]]; then
        log_error "Domain contains null bytes (security risk): $domain"
        return 1
    fi

    # Security: Validate domain format (RFC 1123/952 compliant)
    # Starts/ends with alphanum. Labels (between dots) 1-63 chars, contain alphanum/hyphen.
    if [[ ! "$clean_domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format: $domain"
        log_info "Expected format: vault.example.com (RFC 1123)"
        return 1
    fi

    # Security: Check for consecutive dots or hyphens adjacent to dots
    if [[ "$clean_domain" == *".."* || "$clean_domain" == *.-* || "$clean_domain" == *-.* ]]; then
        log_error "Domain contains invalid sequences (.., .- or -.): $domain"
        return 1
    fi

    # Security: Validate TLD requirements (at least one dot, last part >= 2 letters)
    if [[ ! "$clean_domain" =~ \.[a-zA-Z]{2,}$ ]]; then
        log_error "Invalid Top-Level Domain (TLD) or missing dot: $domain (min 2 letters)"
        return 1
    fi

    # Security: Check for localhost/internal domains in production (WARN only)
    # Improved regex for private IPs
    if [[ "$clean_domain" =~ ^(localhost|127\.[0-9.]+|10\.[0-9.]+|192\.168\.[0-9.]+|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9.]+)$ ]]; then
        log_warn "Security warning: Using internal/localhost domain or IP: $clean_domain"
        log_info "This may not work for Let's Encrypt certificates or external access."
    fi

    log_success "Domain format valid and secure: $clean_domain"
    return 0
}


# --- Existing Validation Functions ---

# Check if running as root or with sudo
_validate_running_as_root() {
    _log_debug "Validating root privileges..."
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        log_error "This operation requires root privileges."
        log_info "Please run the command using 'sudo'."
        return 1
    fi
    _log_debug("Root privileges confirmed.")
    return 0
}

# Validate OS compatibility based on /etc/os-release
_validate_os_compatibility() {
    _log_debug "Validating OS compatibility..."
    local os_id os_version="" detected=false

    # DETECTED_OS should be set by system.sh sourcing
    if [[ -z "${DETECTED_OS:-}" ]]; then
         # Try to detect here if system.sh failed or wasn't sourced yet
         if ! _detect_system; then
              log_error "Could not detect operating system ID."
              return 1
         fi
    fi
    os_id="$DETECTED_OS" # Use variable set by system.sh

    # Check if OS ID is in the supported list
    for supported in "${SUPPORTED_OS[@]}"; do
        if [[ "$os_id" == "$supported" ]]; then
            detected=true
            break
        fi
    done

    if [[ "$detected" == "false" ]]; then
        log_error "Unsupported operating system detected: '$os_id'."
        log_info "This project is primarily tested on: ${SUPPORTED_OS[*]}"
        return 1
    fi

    # Get OS version if possible (from /etc/os-release, sourced by system.sh)
    os_version="${DETECTED_OS_VERSION:-unknown}" # Use DETECTED_OS_VERSION from system.sh

    log_success "Operating System: $os_id $os_version (Supported)"
    return 0
}


_validate_systemd_availability() {
    _log_debug "Validating systemd availability..."
    # SERVICE_MANAGER should be set by system.sh
    if [[ "${SERVICE_MANAGER:-unknown}" != "systemctl" ]]; then
        log_error "systemd not available or not detected as the active service manager."
        log_info "This project requires a systemd-based Linux distribution for service management."
        return 1
    fi

    # Double check PID 1 if SERVICE_MANAGER was somehow set incorrectly
    if [[ "$(readlink /proc/1/exe)" != */systemd ]]; then
         log_error "systemd command found, but it does not appear to be the active init system (PID 1)."
         return 1
    fi

    if [[ ! -d "/etc/systemd/system" ]]; then
        log_warn "Standard systemd system unit directory '/etc/systemd/system' not found, but systemd seems active."
    fi
    log_success "systemd is available and active."
    return 0
}

# Validate system resources (RAM, Disk, Arch)
_validate_system_resources() {
    _log_debug "Validating system resources..."
    local ram_mb disk_gb arch errors=0

    # RAM Check
    if ram_info=$(free -m 2>/dev/null); then
        ram_mb=$(echo "$ram_info" | awk '/^Mem:/ {print $2}')
        if [[ "${ram_mb:-0}" -lt "$MIN_RAM_MB" ]]; then
            log_error "Insufficient RAM: ${ram_mb}MB detected (minimum recommended: ${MIN_RAM_MB}MB)."
            ((errors++))
        else
            log_success "RAM: ${ram_mb}MB (Meets minimum requirement of ${MIN_RAM_MB}MB)"
        fi
    else
        log_warn "Could not determine available RAM via 'free -m'. Skipping RAM check."
    fi

    # Disk Space Check (check both root and project state dir if different)
    # Load config if needed to get PROJECT_STATE_DIR
    if [[ -z "${PROJECT_STATE_DIR:-}" ]] && declare -f load_config > /dev/null; then
         load_config >/dev/null 2>&1 || log_warn "Could not load config for PROJECT_STATE_DIR."
    fi
    local project_state_dir="${PROJECT_STATE_DIR:-/var/lib/vaultwarden}" # Get from config or default
    local paths_to_check=("/" "$project_state_dir")
    local unique_paths=($(printf "%s\n" "${paths_to_check[@]}" | sort -u))

    for path in "${unique_paths[@]}"; do
        # Ensure path exists before checking disk space
        if [[ ! -e "$path" ]]; then
             # Try creating project state dir if it's missing
             if [[ "$path" == "$project_state_dir" ]]; then
                 log_warn "Project state directory '$path' not found. Attempting to create."
                 # Requires root potentially
                 if [[ $EUID -eq 0 ]]; then
                     mkdir -p "$path" || log_error "Failed to create directory '$path' as root."
                 elif _have_cmd sudo; then
                      sudo mkdir -p "$path" || log_error "Failed to create directory '$path' using sudo."
                 else
                     log_error "Cannot create directory '$path'. Skipping disk check for it."
                     continue # Skip df check for this path
                 fi
             else
                 log_warn "Path '$path' not found. Skipping disk check for it."
                 continue # Skip df check for this path
             fi
        fi

        local path_label disk_info available_kb available_gb
        path_label=$( [[ "$path" == "/" ]] && echo "Root Filesystem" || echo "Project Storage ($path)" )

        # Use POSIX df options for better compatibility
        if disk_info=$(df -Pk "$path" 2>/dev/null | awk 'NR==2'); then
            available_kb=$(echo "$disk_info" | awk '{ print $4 }')
            available_gb=$(( available_kb / 1024 / 1024 )) # Integer division GB

            if [[ "${available_gb:-0}" -lt "$MIN_DISK_GB" ]]; then
                log_error "Insufficient disk space on '$path': ~${available_gb}GB free (minimum recommended: ${MIN_DISK_GB}GB)."
                ((errors++))
            else
                log_success "Disk Space ($path): ~${available_gb}GB free (Meets minimum requirement of ${MIN_DISK_GB}GB)"
            fi
        else
            log_warn "Could not determine disk space for '$path'. Check permissions or mount status."
        fi
    done

    # Architecture Check
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) log_success "Architecture: $arch (Supported)";;
        aarch64|arm64) log_success "Architecture: $arch (Supported)";;
        *) log_warn "Architecture: $arch (Untested, may encounter issues with pre-built binaries or Docker images)";; # Warning, not error
    esac

    return $errors # Return 0 if no errors, >0 otherwise
}

# Validate presence of required commands
_validate_required_commands() {
    _log_debug "Validating required commands..."
    local missing=() errors=0
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if _have_cmd "$cmd"; then # Use function from system.sh
            _log_debug "Command available: $cmd"
        else
            _log_debug "Command missing: $cmd"
            missing+=("$cmd")
            ((errors++))
        fi
    done
    if [[ $errors -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        log_info "Please install the corresponding packages (e.g., using 'sudo apt install <package_name>'). Refer to install-deps.sh."
        return 1
    fi
    log_success "All required commands are available."
    return 0
}

# Validate basic network connectivity and DNS
_validate_network_connectivity() {
    _log_debug "Validating network connectivity..."
    local internet_ok=false dns_ok=false errors=0

    # Test connectivity (using function from system.sh if available)
    if declare -f _test_connectivity >/dev/null; then
        if _test_connectivity "1.1.1.1" 3; then # Test against Cloudflare DNS
            log_success "Internet connectivity check passed (ping 1.1.1.1)."
            internet_ok=true
        else
            log_error "Internet connectivity check failed (ping 1.1.1.1). Check network/firewall."
            ((errors++))
        fi
    else
        log_warn "Cannot perform connectivity test: _test_connectivity function missing (from system.sh?). Skipping ping check."
        # Assume connectivity might exist, try DNS anyway but warn
        internet_ok=true # Tentatively allow DNS check
    fi

    # Test DNS resolution
    if $internet_ok; then # Only test DNS if internet seems reachable or check skipped
        # Use getent for standard library check, timeout for robustness
        if timeout 5 getent hosts google.com >/dev/null 2>&1; then
            log_success "DNS resolution check passed (resolve google.com)."
            dns_ok=true
        else
            log_error "DNS resolution check failed (resolve google.com). Check /etc/resolv.conf or network settings."
            ((errors++))
        fi
    else
        log_info "Skipping DNS check due to failed internet connectivity."
    fi

    return $errors
}

# Validate port availability
_validate_port_availability() {
    local port="$1"
    local description="${2:-Port $port}"
    _log_debug "Validating availability of TCP port $port..."

    local listen_cmd="" check_output rc
    # Prefer ss, fallback to netstat
    if _have_cmd ss; then
        # Check for LISTEN state on specified port (TCP)
        check_output=$(ss -tlpn sport = :"$port" 2>/dev/null)
        rc=$?
    elif _have_cmd netstat; then
         # Check for LISTEN state on specified port (TCP)
         check_output=$(netstat -tlpn 2>/dev/null | grep -E ":${port}[[:space:]]+" | grep LISTEN)
         rc=$?
    else
        log_warn "Cannot check port availability: 'ss' or 'netstat' command not found. Install 'iproute2' or 'net-tools'."
        return 0 # Skip check, not a fatal error for validation library itself
    fi

    # Check output and return code
    if [[ $rc -eq 0 && -n "$check_output" ]]; then
         # Extract process info if possible
         local process_info=""
         if [[ "$listen_cmd" == *"ss"* ]]; then
              process_info=$(echo "$check_output" | grep -oP 'users:\(\("\K[^"]+') || process_info="Unknown process"
         elif [[ "$listen_cmd" == *"netstat"* ]]; then
               process_info=$(echo "$check_output" | awk '{print $NF}') || process_info="Unknown process"
         fi
        log_error "$description ($port/TCP) is already in use by another process: $process_info"
        return 1
    else
        log_success "$description ($port/TCP) appears to be available."
        return 0
    fi
}


# --- Docker Validations ---

_validate_docker_daemon() {
    _log_debug "Validating Docker daemon..."
    if ! _have_cmd docker; then
        log_error "Docker command not found. Please install Docker Engine (see install-deps.sh)."
        return 1
    fi
    # Use timeout for docker info in case daemon is hung
    if ! timeout 10 docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running or user lacks permissions."
        log_info "Try: 'sudo systemctl start docker' or add user to 'docker' group (and relogin)."
        return 1
    fi
    local docker_version
    docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")"
    log_success "Docker daemon is running (Server Version: $docker_version)"

    # Basic functionality test (optional, adds overhead)
    # _log_debug "Running Docker hello-world test..."
    # if timeout 30 docker run --rm hello-world >/dev/null 2>&1; then
    #     log_success "Docker functionality test (hello-world) passed."
    # else
    #     log_error "Docker functionality test (hello-world) failed. Daemon might have issues."
    #     return 1
    # fi
    return 0
}

_validate_docker_compose() {
    _log_debug "Validating Docker Compose plugin..."
    # Use the function from system.sh if available
    if declare -f _compose_service_running >/dev/null; then
         # Check if docker compose version works as a proxy for plugin check
         if docker compose version >/dev/null 2>&1; then
             local compose_version
             compose_version="$(docker compose version --short 2>/dev/null || echo "unknown")"
             log_success "Docker Compose plugin available (Version: $compose_version)"
             return 0
         else
             log_error "Docker Compose plugin (v2) not found or not working."
             log_info "Install it via 'sudo apt install docker-compose-plugin' or Docker Desktop."
             if _have_cmd docker-compose; then
                 log_warn "Legacy 'docker-compose' (v1) found, but plugin (v2) is required by scripts."
             fi
             return 1
         fi
    else
         # Fallback check if system.sh not sourced fully
          if _have_cmd docker && docker compose version >/dev/null 2>&1; then
              log_success "Docker Compose plugin available (Version check passed)."
              return 0
          else
              log_error "Docker Compose plugin (v2) not found or not working."
              return 1
          fi
    fi
}

_validate_compose_file() {
    local compose_file="$1"
    _log_debug "Validating Docker Compose file syntax: $compose_file"
    if [[ ! -f "$compose_file" ]]; then
        log_error "Docker Compose file not found: '$compose_file'"
        return 1
    fi
    # Use timeout in case config command hangs
    if ! timeout 15 docker compose -f "$compose_file" config --quiet >/dev/null 2>&1; then
        log_error "Docker Compose file '$compose_file' has invalid syntax or command failed."
        log_info "Run 'docker compose -f \"$compose_file\" config' manually to see errors."
        return 1
    fi
    log_success "Docker Compose file '$compose_file' syntax is valid."
    return 0
}

# --- File/Directory Helpers ---

_validate_file_exists() {
  local file_path="$1"; local description="${2:-File}"
  _log_debug("Checking existence: $description at '$file_path'")
  if [[ -f "$file_path" ]]; then
    log_success "$description exists: $file_path"
    return 0
  else
    log_error "$description not found: $file_path"
    return 1
  fi
}

_validate_directory_exists() {
  local dir_path="$1"; local description="${2:-Directory}"
   _log_debug("Checking existence: $description at '$dir_path'")
  if [[ -d "$dir_path" ]]; then
    log_success "$description exists: $dir_path"
    return 0
  else
    log_error "$description not found: $dir_path"
    return 1
  fi
}

_validate_file_permissions() {
  local file_path="$1"; local expected_perms="$2"; local description="${3:-File}"
  _log_debug("Checking permissions ($expected_perms): $description at '$file_path'")
  if [[ ! -e "$file_path" ]]; then # Check if exists first
    log_error "$description not found, cannot check permissions: $file_path"
    return 1
  fi
  local actual_perms; actual_perms="$(stat -c "%a" "$file_path" 2>/dev/null)" || { log_error "Cannot stat file '$file_path'"; return 1; }
  if [[ "$actual_perms" == "$expected_perms" ]]; then
    log_success "$description has correct permissions ($actual_perms): $file_path"
    return 0
  else
    log_error "$description has incorrect permissions (expected: $expected_perms, actual: $actual_perms): $file_path"
    return 1
  fi
}


# --- Full System Validation Suite ---
validate_full_system() {
    log_header "VaultWarden-NG System Prerequisite Validation"
    local total_errors=0 critical_errors=0

    _log_section "System Checks"
    # _validate_running_as_root || ((total_errors++)) # Only if needed by calling script
    _validate_os_compatibility || ((critical_errors++)) # OS compat is critical
    _validate_systemd_availability || ((critical_errors++)) # Systemd is critical
    _validate_system_resources || ((total_errors++)) # Resources warnings are not critical failure yet
    _validate_required_commands || ((critical_errors++)) # Missing commands are critical

    _log_section "Network Checks"
    _validate_network_connectivity || ((total_errors++)) # Network failure is warning for now
    _validate_port_availability 80 "HTTP Port" || ((total_errors++)) # Port conflict is warning
    _validate_port_availability 443 "HTTPS Port" || ((total_errors++)) # Port conflict is warning

    _log_section "Docker Checks"
    _validate_docker_daemon || ((critical_errors++)) # Docker daemon is critical
    _validate_docker_compose || ((critical_errors++)) # Compose plugin is critical

    # Add compose file validation if called from context where it's expected
    # Example: if [[ -n "$COMPOSE_FILE" ]]; then _validate_compose_file "$COMPOSE_FILE" || ((critical_errors++)); fi


    _log_section "Validation Summary"
    total_errors=$(( total_errors + critical_errors )) # Sum critical and non-critical

    if [[ $critical_errors -eq 0 ]]; then
        if [[ $total_errors -eq 0 ]]; then
            log_success "All system validations passed successfully."
            return 0
        else
            log_warn "$total_errors non-critical warning(s) detected. System might operate with limitations."
            return 0 # Return success even with warnings
        fi
    else
        log_error "System validation failed with $critical_errors critical error(s) and $((total_errors - critical_errors)) warning(s)."
        return 1 # Return failure only if critical errors occurred
    fi
}

# --- Script Execution ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
     _log_warning "lib/validation.sh is a library and should typically be sourced, not executed directly."
     _log_info "Running full system validation..."
     # Ensure config is loaded if available for state dir check
     if declare -f load_config > /dev/null; then load_config >/dev/null 2>&1; fi
     validate_full_system
     exit $?
else
      _log_debug "lib/validation.sh loaded successfully as a library."
fi
