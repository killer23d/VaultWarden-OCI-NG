#!/usr/bin/env bash
# lib/system.sh - System operations and utilities library

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/logging.sh" ]]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/logging.sh"
else
  echo "Missing lib/logging.sh for system logging" >&2
  exit 1
fi

DETECTED_OS=""
PACKAGE_MANAGER=""
SERVICE_MANAGER="systemctl"

_have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

_detect_system() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    DETECTED_OS="$ID"
    case "$ID" in
      ubuntu|debian) PACKAGE_MANAGER="apt" ;;
      centos|rhel|fedora)
        PACKAGE_MANAGER="yum"
        command -v dnf >/dev/null 2>&1 && PACKAGE_MANAGER="dnf"
        ;;
      arch) PACKAGE_MANAGER="pacman" ;;
      alpine) PACKAGE_MANAGER="apk" ;;
      *)
        _log_warning "Unknown OS detected: $ID"
        if command -v apt >/dev/null 2>&1; then PACKAGE_MANAGER="apt"
        elif command -v yum >/dev/null 2>&1; then PACKAGE_MANAGER="yum"
        elif command -v dnf >/dev/null 2>&1; then PACKAGE_MANAGER="dnf"
        elif command -v pacman >/dev/null 2>&1; then PACKAGE_MANAGER="pacman"
        elif command -v apk >/dev/null 2>&1; then PACKAGE_MANAGER="apk"
        fi
        ;;
    esac
  else
    _log_error "Cannot detect operating system"
    return 1
  fi
  _log_debug "Detected OS: $DETECTED_OS"
  _log_debug "Package manager: $PACKAGE_MANAGER"
  return 0
}

_update_package_index() {
  _log_info "Updating package index..."
  [[ -z "$PACKAGE_MANAGER" ]] && _detect_system
  case "$PACKAGE_MANAGER" in
    apt) _log_command "apt update" "Updating APT package index" ;;
    yum|dnf) _log_command "$PACKAGE_MANAGER check-update || true" "Updating package index" ;;
    pacman) _log_command "pacman -Sy" "Updating pacman package index" ;;
    apk) _log_command "apk update" "Updating APK package index" ;;
    *) _log_error "Unknown package manager: $PACKAGE_MANAGER"; return 1 ;;
  esac
}

_install_package() {
  local package="$1"; local description="${2:-$package}"
  _log_info "Installing package: $description"
  [[ -z "$PACKAGE_MANAGER" ]] && _detect_system
  if _is_package_installed "$package"; then
    _log_success "Package already installed: $package"
    return 0
  fi
  case "$PACKAGE_MANAGER" in
    apt) _log_command "apt install -y $package" "Installing $package via APT" ;;
    yum|dnf) _log_command "$PACKAGE_MANAGER install -y $package" "Installing $package via $PACKAGE_MANAGER" ;;
    pacman) _log_command "pacman -S --noconfirm $package" "Installing $package via pacman" ;;
    apk) _log_command "apk add $package" "Installing $package via APK" ;;
    *) _log_error "Unknown package manager: $PACKAGE_MANAGER"; return 1 ;;
  esac
  if _is_package_installed "$package"; then
    _log_success "Package installed successfully: $package"
  else
    _log_error "Package installation failed: $package"
    return 1
  fi
}

_is_package_installed() {
  local package="$1"
  [[ -z "$PACKAGE_MANAGER" ]] && _detect_system
  case "$PACKAGE_MANAGER" in
    apt) dpkg -l "$package" >/dev/null 2>&1 ;;
    yum|dnf) "$PACKAGE_MANAGER" list installed "$package" >/dev/null 2>&1 ;;
    pacman) pacman -Q "$package" >/dev/null 2>&1 ;;
    apk) apk info -e "$package" >/dev/null 2>&1 ;;
    *) _log_warning "Cannot check package installation for: $PACKAGE_MANAGER"; return 1 ;;
  esac
}

_remove_package() {
  local package="$1"; local description="${2:-$package}"
  _log_info "Removing package: $description"
  [[ -z "$PACKAGE_MANAGER" ]] && _detect_system
  if ! _is_package_installed "$package"; then
    _log_info "Package not installed: $package"
    return 0
  fi
  case "$PACKAGE_MANAGER" in
    apt) _log_command "apt remove -y $package" "Removing $package via APT" ;;
    yum|dnf) _log_command "$PACKAGE_MANAGER remove -y $package" "Removing $package via $PACKAGE_MANAGER" ;;
    pacman) _log_command "pacman -R --noconfirm $package" "Removing $package via pacman" ;;
    apk) _log_command "apk del $package" "Removing $package via APK" ;;
    *) _log_error "Unknown package manager: $PACKAGE_MANAGER"; return 1 ;;
  esac
}

_enable_service() {
  local name="$1"
  _log_info "Enabling service: $name"
  if systemctl enable "$name"; then _log_success "Service enabled: $name"; else _log_error "Failed to enable service: $name"; return 1; fi
}

_disable_service() {
  local name="$1"
  _log_info "Disabling service: $name"
  if systemctl disable "$name"; then _log_success "Service disabled: $name"; else _log_warning "Failed to disable service (may not exist): $name"; fi
}

_start_service() {
  local name="$1"
  _log_info "Starting service: $name"
  if systemctl start "$name"; then _log_success "Service started: $name"; else _log_error "Failed to start service: $name"; return 1; fi
}

_stop_service() {
  local name="$1"
  _log_info "Stopping service: $name"
  if systemctl stop "$name"; then _log_success "Service stopped: $name"; else _log_warning "Failed to stop service (may not be running): $name"; fi
}

_restart_service() {
  local name="$1"
  _log_info "Restarting service: $name"
  if systemctl restart "$name"; then _log_success "Service restarted: $name"; else _log_error "Failed to restart service: $name"; return 1; fi
}

_get_service_status() {
  local name="$1"
  if systemctl is-active --quiet "$name"; then echo "active"
  elif systemctl is-failed --quiet "$name"; then echo "failed"
  else echo "inactive"; fi
}

_wait_for_service() {
  local name="$1"; local max_wait="${2:-30}"; local interval="${3:-2}"
  _log_info "Waiting for service to be active: $name"
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    if systemctl is-active --quiet "$name"; then
      _log_success "Service is active: $name"
      return 0
    fi
    sleep "$interval"
    elapsed=$((elapsed + interval))
    _log_debug "Waiting for $name... (${elapsed}/${max_wait}s)"
  done
  _log_error "Service failed to become active within ${max_wait}s: $name"
  return 1
}

_update_systemd_secret_ocid() {
    local new_ocid="$1"
    local env_file="$2" # Path must be provided by caller

    if [[ -z "$env_file" ]]; then
      _log_error "Systemd environment file path is required."
      return 1
    fi

    if [[ -f "$env_file" ]]; then
        _log_info "Updating systemd environment file..."
        sed -i "s/^OCI_SECRET_OCID=.*/OCI_SECRET_OCID=$new_ocid/" "$env_file"
        systemctl daemon-reload
        _log_success "Environment updated. Restart service to apply changes."
    else
        _log_warning "Systemd environment file not found: $env_file"
    fi
}

_restart_service_safely() {
    local service_name="$1" # Service name must be provided by caller

    if [[ -z "$service_name" ]]; then
      _log_error "Service name is required for restart."
      return 1
    fi

    if systemctl is-active --quiet "$service_name"; then
        _log_info "Performing rolling restart of $service_name..."
        systemctl restart "$service_name"

        local retry_count=0
        while [[ $retry_count -lt 30 ]]; do
            if systemctl is-active --quiet "$service_name"; then
                _log_success "Service restarted successfully"
                return 0
            fi
            sleep 2
            ((retry_count++))
        done

        _log_error "Service failed to restart properly"
        return 1
    else
        _log_info "Service not running. Use: systemctl start $service_name"
    fi
}

_create_directory_secure() {
  local dir="$1"; local perm="${2:-755}"; local owner="${3:-root:root}"
  if [[ ! -d "$dir" ]]; then
    _log_info "Creating directory: $dir"
    mkdir -p "$dir" || { _log_error "Failed to create directory: $dir"; return 1; }
    _log_success "Directory created: $dir"
  else
    _log_debug "Directory already exists: $dir"
  fi
  chmod "$perm" "$dir"
  chown "$owner" "$dir" 2>/dev/null || true
  _log_debug "Directory permissions set: $dir ($perm, $owner)"
}

_create_file_secure() {
  local file="$1"; local perm="${2:-644}"; local content="${3:-}"; local owner="${4:-root:root}"
  _log_info "Creating file: $file"
  local parent; parent="$(dirname "$file")"
  [[ -d "$parent" ]] || _create_directory_secure "$parent"
  if [[ -n "$content" ]]; then printf '%s' "$content" > "$file"; else : > "$file"; fi
  chmod "$perm" "$file"
  chown "$owner" "$file" 2>/dev/null || true
  _log_success "File created: $file ($perm, $owner)"
}

_backup_file() {
  local file="$1"; local suffix="${2:-.backup.$(date +%Y%m%d_%H%M%S)}"
  if [[ ! -f "$file" ]]; then _log_warning "File not found for backup: $file"; return 1; fi
  local dst="${file}${suffix}"
  if cp "$file" "$dst"; then _log_success "File backed up: $file -> $dst"; else _log_error "Failed to backup file: $file"; return 1; fi
}

_safe_replace_file() {
  local file="$1"; local content="$2"; local perm="${3:-}"
  _backup_file "$file" || _log_warning "Could not create backup"
  if [[ -z "$perm" && -f "$file" ]]; then perm="$(stat -c "%a" "$file")"; fi
  perm="${perm:-644}"
  local tmp; tmp="$(mktemp)"
  printf '%s' "$content" > "$tmp" || { rm -f "$tmp"; _log_error "Failed to write temporary file for: $file"; return 1; }
  if mv "$tmp" "$file"; then chmod "$perm" "$file"; _log_success "File replaced safely: $file"; else rm -f "$tmp"; _log_error "Failed to replace file: $file"; return 1; fi
}

_kill_process_by_name() {
  local name="$1"; local signal="${2:-TERM}"
  local pids; pids="$(pgrep -f "$name" || true)"
  if [[ -z "$pids" ]]; then _log_info "No processes found matching: $name"; return 0; fi
  _log_info "Sending $signal signal to processes: $name"
  for pid in $pids; do
    kill -"$signal" "$pid" 2>/dev/null && _log_debug "Signal sent to PID $pid" || _log_warning "Failed to send signal to PID $pid"
  done
  sleep 2
  local remain; remain="$(pgrep -f "$name" || true)"
  if [[ -n "$remain" ]]; then _log_warning "Some processes still running after $signal signal: $remain"; return 1; else _log_success "All matching processes terminated"; return 0; fi
}

_wait_for_process() {
  local name="$1"; local max_wait="${2:-30}"; local interval="${3:-2}"
  _log_info "Waiting for process to start: $name"
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    if pgrep -f "$name" >/dev/null; then _log_success "Process is running: $name"; return 0; fi
    sleep "$interval"; elapsed=$((elapsed + interval)); _log_debug "Waiting for $name... (${elapsed}/${max_wait}s)"
  done
  _log_error "Process failed to start within ${max_wait}s: $name"
  return 1
}

_get_system_info() {
  local what="$1"
  case "$what" in
    hostname) hostname ;;
    kernel) uname -r ;;
    arch) uname -m ;;
    uptime) uptime -p 2>/dev/null || uptime ;;
    load) awk '{print $1, $2, $3}' /proc/loadavg ;;
    memory_usage) free -m | awk 'NR==2{printf "%.1f%% (%s/%s MB)\n", $3*100/$2, $3, $2}' ;;
    disk_usage) df -h / | awk 'NR==2{printf "%s (%s)\n", $5, $4}' ;;
    *) _log_error "Unknown system info type: $what"; return 1 ;;
  esac
}

_display_system_summary() {
  _log_section "System Information"
  _print_key_value "Hostname" "$(_get_system_info hostname)"
  _print_key_value "Kernel" "$(_get_system_info kernel)"
  _print_key_value "Architecture" "$(_get_system_info arch)"
  _print_key_value "Uptime" "$(_get_system_info uptime)"
  _print_key_value "Load Average" "$(_get_system_info load)"
  _print_key_value "Memory Usage" "$(_get_system_info memory_usage)"
  _print_key_value "Disk Usage" "$(_get_system_info disk_usage)"
}

_get_public_ip() {
  local method="${1:-auto}"
  case "$method" in
    auto)
      curl -s ifconfig.me 2>/dev/null || curl -s ipecho.net/plain 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "Unable to determine public IP"
      ;;
    ifconfig.me) curl -s ifconfig.me ;;
    ipecho) curl -s ipecho.net/plain ;;
    icanhazip) curl -s icanhazip.com ;;
    *) _log_error "Unknown IP detection method: $method"; return 1 ;;
  esac
}

_test_port_connectivity() {
  local host="$1"; local port="$2"; local timeout="${3:-5}"
  if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
    _log_success "Port $port is open on $host"
    return 0
  else
    _log_error "Port $port is closed or filtered on $host"
    return 1
  fi
}

_cleanup_temp_files() {
  local pattern="${1:-/tmp/*}"; local days="${2:-7}"
  _log_info "Cleaning up temporary files older than $days days"
  local count; count="$(find /tmp -name "${pattern##*/}" -type f -mtime "+$days" 2>/dev/null | wc -l)"
  if [[ $count -gt 0 ]]; then
    find /tmp -name "${pattern##*/}" -type f -mtime "+$days" -delete 2>/dev/null || true
    _log_success "Cleaned up $count temporary files"
  else
    _log_info "No temporary files found for cleanup"
  fi
}

_cleanup_log_files() {
  local dir="$1"; local days="${2:-30}"; local max_mb="${3:-100}"
  if [[ ! -d "$dir" ]]; then _log_warning "Log directory not found: $dir"; return 1; fi
  _log_info "Cleaning up log files in: $dir"
  local old; old="$(find "$dir" -name "*.log*" -type f -mtime "+$days" 2>/dev/null | wc -l)"
  if [[ $old -gt 0 ]]; then
    find "$dir" -name "*.log*" -type f -mtime "+$days" -delete 2>/dev/null || true
    _log_success "Removed $old old log files"
  fi
  find "$dir" -name "*.log" -type f -size "+${max_mb}M" -exec truncate -s 0 {} \; 2>/dev/null || true
  _log_info "Truncated oversized log files (>${max_mb} MB)"
}

_test_connectivity() {
  local host="${1:-8.8.8.8}"; local timeout="${2:-5}"
  _log_debug "Testing network connectivity to $host..."
  if ping -c 1 -W "$timeout" "$host" >/dev/null 2>&1; then return 0; else return 1; fi
}

_compose_service_running() {
  local service_name="$1"
  if docker compose ps --format json 2>/dev/null | jq -e ".[] | select(.Service==\"$service_name\") | .State == \"running\"" >/dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}

_detect_system

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  _log_debug "lib/system.sh loaded successfully (OS: $DETECTED_OS, PM: $PACKAGE_MANAGER)"
else
  _log_warning "lib/system.sh should be sourced, not executed directly"
  _display_system_summary
fi