#!/usr/bin/env bash
# lib/validation.sh - System and prerequisite validation library

set -euo pipefail

# Dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/logging.sh" ]]; then
  source "$SCRIPT_DIR/logging.sh"
else
  echo "Missing lib/logging.sh for validation logging" >&2
  exit 1
fi

if [[ -f "$SCRIPT_DIR/system.sh" ]]; then
  source "$SCRIPT_DIR/system.sh"
else
  echo "Missing lib/system.sh for validation helpers" >&2
  exit 1
fi

# Config
MIN_RAM_MB=512
MIN_DISK_GB=5
REQUIRED_COMMANDS=("curl" "jq" "docker" "systemctl")

_validate_running_as_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    _log_error "This script must be run as root"
    _log_info "Try: sudo $0 $*"
    return 1
  fi
  _log_debug "Root privileges confirmed"
  return 0
}

_validate_os_compatibility() {
  # ... (function is unchanged)
}

_validate_systemd_availability() {
    _log_debug "Validating systemd availability..."
    if ! _have_cmd systemctl >/dev/null 2>&1; then
        _log_error "systemd not available - this system is not supported"
        _log_info "This project requires a systemd-based Linux distribution (like Ubuntu, Debian, CentOS)"
        return 1
    fi
    if [[ ! -d "/etc/systemd/system" ]]; then
        _log_error "systemd system directory not found at /etc/systemd/system"
        return 1
    fi
    _log_success "systemd is available"
    return 0
}

# System resources
_validate_system_resources() {
  _log_debug "Validating system resources..."
  local ram_mb disk_gb arch
  ram_mb="$(free -m | awk '/^Mem:/ {print $2}')"
  if [[ "${ram_mb:-0}" -lt "$MIN_RAM_MB" ]]; then
    _log_error "Insufficient RAM: ${ram_mb}MB (minimum: ${MIN_RAM_MB}MB)"
    return 1
  else
    _log_success "RAM: ${ram_mb}MB (sufficient)"
  fi

  disk_gb="$(df / | tail -1 | awk '{print int($4/1024/1024)}')"
  if [[ "${disk_gb:-0}" -lt "$MIN_DISK_GB" ]]; then
    _log_error "Insufficient disk space: ${disk_gb}GB (minimum: ${MIN_DISK_GB}GB)"
    return 1
  else
    _log_success "Disk space: ${disk_gb}GB (sufficient)"
  fi

  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) _log_success "Architecture: $arch (supported)";;
    aarch64|arm64) _log_success "Architecture: $arch (supported - ARM)";;
    *) _log_warning "Architecture: $arch (may not be supported)";;
  esac
  return 0
}

# Commands
_validate_required_commands() {
  _log_debug "Validating required commands..."
  local missing=()
  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if _have_cmd "$cmd"; then
      _log_debug "Command available: $cmd"
    else
      _log_debug "Command missing: $cmd"
      missing+=("$cmd")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    _log_error "Missing required commands: ${missing[*]}"
    _log_info "Install missing packages and try again"
    return 1
  fi
  _log_success "All required commands are available"
  return 0
}

# Network
_validate_network_connectivity() {
  _log_debug "Validating network connectivity..."
  local test_hosts=("8.8.8.8" "1.1.1.1" "google.com")
  local success=0
  for host in "${test_hosts[@]}"; do
    if timeout 5 ping -c 1 "$host" >/dev/null 2>&1; then
      ((success++))
      _log_debug "Connectivity to $host: OK"
    else
      _log_debug "Connectivity to $host: Failed"
    fi
  done
  if [[ $success -eq 0 ]]; then
    _log_error "No network connectivity detected"
    return 1
  elif [[ $success -lt 2 ]]; then
    _log_warning "Limited network connectivity (${success}/${#test_hosts[@]} hosts reachable)"
  else
    _log_success "Network connectivity validated"
  fi
  return 0
}

_validate_dns_resolution() {
  local domain="${1:-google.com}"
  _log_debug "Testing DNS resolution for: $domain"
  if nslookup "$domain" >/dev/null 2>&1; then
    _log_success "DNS resolution working"
    return 0
  else
    _log_error "DNS resolution failed for: $domain"
    return 1
  fi
}

_validate_port_availability() {
  local port="$1"
  local description="${2:-Port}"
  if ss -tln | grep -q ":$port "; then
    _log_error "$description ($port) is already in use"
    return 1
  else
    _log_success "$description ($port) is available"
    return 0
  fi
}

# Docker
_validate_docker_daemon() {
  _log_debug "Validating Docker daemon..."
  if ! _have_cmd docker; then
    _log_error "Docker is not installed"
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    _log_error "Docker daemon is not running"
    _log_info "Try: systemctl start docker"
    return 1
  fi
  local docker_version
  docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")"
  _log_success "Docker daemon is running (version: $docker_version)"
  if docker run --rm hello-world >/dev/null 2>&1; then
    _log_success "Docker functionality test passed"
  else
    _log_error "Docker functionality test failed"
    return 1
  fi
  return 0
}

_validate_docker_compose() {
  _log_debug "Validating Docker Compose..."
  if docker compose version >/dev/null 2>&1; then
    local compose_version
    compose_version="$(docker compose version --short 2>/dev/null || echo "unknown")"
    _log_success "Docker Compose plugin available (version: $compose_version)"
    return 0
  elif _have_cmd docker-compose; then
    local compose_version
    compose_version="$(docker-compose version --short 2>/dev/null || echo "unknown")"
    _log_warning "Using legacy docker-compose (version: $compose_version)"
    _log_info "Consider upgrading to Docker Compose plugin"
    return 0
  else
    _log_error "Docker Compose is not available"
    return 1
  fi
}

_validate_compose_file() {
  local compose_file="$1"
  _log_debug "Validating Docker Compose file: $compose_file"
  if [[ ! -f "$compose_file" ]]; then
    _log_error "Compose file not found: $compose_file"
    return 1
  fi
  if ! docker compose -f "$compose_file" config >/dev/null 2>&1; then
    _log_error "Invalid Docker Compose file syntax"
    return 1
  fi
  _log_success "Docker Compose file is valid"
  return 0
}

# File helpers
_validate_file_exists() {
  local file_path="$1"; local description="${2:-File}"
  if [[ -f "$file_path" ]]; then
    _log_success "$description exists: $file_path"
    return 0
  else
    _log_error "$description not found: $file_path"
    return 1
  fi
}

_validate_directory_exists() {
  local dir_path="$1"; local description="${2:-Directory}"
  if [[ -d "$dir_path" ]]; then
    _log_success "$description exists: $dir_path"
    return 0
  else
    _log_error "$description not found: $dir_path"
    return 1
  fi
}

_validate_file_permissions() {
  local file_path="$1"; local expected_perms="$2"; local description="${3:-File}"
  if [[ ! -f "$file_path" ]]; then
    _log_error "$description not found: $file_path"
    return 1
  fi
  local actual_perms; actual_perms="$(stat -c "%a" "$file_path")"
  if [[ "$actual_perms" == "$expected_perms" ]]; then
    _log_success "$description has correct permissions ($actual_perms)"
    return 0
  else
    _log_error "$description has incorrect permissions (expected: $expected_perms, actual: $actual_perms)"
    return 1
  fi
}

_validate_directory_writable() {
  local dir_path="$1"; local description="${2:-Directory}"
  if [[ ! -d "$dir_path" ]]; then
    _log_error "$description not found: $dir_path"
    return 1
  fi
  if [[ -w "$dir_path" ]]; then
    _log_success "$description is writable"
    return 0
  else
    _log_error "$description is not writable"
    return 1
  fi
}

# JSON helpers
_validate_json_file() {
  local json_file="$1"; local description="${2:-JSON file}"
  if [[ ! -f "$json_file" ]]; then
    _log_error "$description not found: $json_file"
    return 1
  fi
  if jq . "$json_file" >/dev/null 2>&1; then
    _log_success "$description has valid JSON syntax"
    return 0
  else
    _log_error "$description contains invalid JSON"
    return 1
  fi
}

_validate_json_keys() {
  local json_file="$1"; shift
  local -a required_keys=("$@")
  if [[ ! -f "$json_file" ]]; then
    _log_error "JSON file not found: $json_file"
    return 1
  fi
  local missing=()
  for key in "${required_keys[@]}"; do
    if jq -e "has(\"$key\")" "$json_file" >/dev/null 2>&1; then
      _log_debug "Required key found: $key"
    else
      missing+=("$key")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    _log_error "Missing required JSON keys: ${missing[*]}"
    return 1
  fi
  _log_success "All required JSON keys are present"
  return 0
}

# Services
_validate_service_exists() {
  local service_name="$1"
  if systemctl list-unit-files | grep -q "^$service_name"; then
    _log_success "Service exists: $service_name"
    return 0
  else
    _log_error "Service not found: $service_name"
    return 1
  fi
}

_validate_service_running() {
  local service_name="$1"
  if systemctl is-active --quiet "$service_name"; then
    _log_success "Service is running: $service_name"
    return 0
  else
    _log_error "Service is not running: $service_name"
    return 1
  fi
}

_validate_service_enabled() {
  local service_name="$1"
  if systemctl is-enabled --quiet "$service_name"; then
    _log_success "Service is enabled: $service_name"
    return 0
  else
    _log_warning "Service is not enabled: $service_name"
    return 1
  fi
}

# Security
_validate_secure_permissions() {
  local file_path="$1"; local max_perms="${2:-600}"; local description="${3:-File}"
  if [[ ! -f "$file_path" ]]; then
    _log_error "$description not found: $file_path"
    return 1
  fi
  local actual_perms; actual_perms="$(stat -c "%a" "$file_path")"
  if [[ "${actual_perms: -1}" == "0" ]] && [[ "${actual_perms: -2:1}" -le "6" ]]; then
    _log_success "$description has secure permissions ($actual_perms)"
    return 0
  else
    _log_error "$description has insecure permissions ($actual_perms)"
    return 1
  fi
}

_validate_no_world_writable() {
  local dir_path="$1"; local description="${2:-Directory}"
  if [[ ! -d "$dir_path" ]]; then
    _log_error "$description not found: $dir_path"
    return 1
  fi
  local ww
  ww="$(find "$dir_path" -type f -perm -002 2>/dev/null | head -10 || true)"
  if [[ -n "$ww" ]]; then
    _log_error "World-writable files found in $description:"
    while read -r f; do _log_error " $f"; done <<<"$ww"
    return 1
  fi
  _log_success "$description has no world-writable files"
  return 0
}

# Full system validation
_validate_full_system() {
  _log_header "System Validation"
  local errs=0

  _log_section "Core System Requirements"
  _validate_running_as_root || ((errs++))
  _validate_os_compatibility || ((errs++))
  _validate_system_resources || ((errs++))
  _validate_required_commands || ((errs++))

  _log_section "Network Connectivity"
  _validate_network_connectivity || ((errs++))
  _validate_dns_resolution || ((errs++))

  _log_section "Docker Environment"
  _validate_docker_daemon || ((errs++))
  _validate_docker_compose || ((errs++))

  _log_section "Port Availability"
  _validate_port_availability 80 "HTTP" || ((errs++))
  _validate_port_availability 443 "HTTPS" || ((errs++))

  if [[ $errs -eq 0 ]]; then
    _log_success "All system validations passed"
    return 0
  else
    _log_error "System validation failed ($errs errors)"
    return 1
  fi
}

# Source guard
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  _log_debug "lib/validation.sh loaded successfully"
else
  _log_warning "lib/validation.sh should be sourced, not executed directly"
  _validate_full_system
fi