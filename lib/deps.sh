#!/usr/bin/env bash
# lib/deps.sh - Dependency checking library

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/logging.sh"

_set_log_prefix "deps"

is_installed() {
  command -v "$1" >/dev/null 2>&1
}

check_required_deps() {
  local -a deps=("$@")
  local missing=0
  _log_section "Validating Required Dependencies"
  for dep in "${deps[@]}"; do
    if is_installed "$dep"; then
      _log_success "✓ $dep is installed."
    else
      _log_error "✗ $dep is NOT installed."
      ((missing++))
    fi
  done

  if [[ $missing -gt 0 ]]; then
    _log_error "$missing required dependencies are missing."
    _log_info "Please run './tools/install-deps.sh' as root to install them."
    return 1
  fi
  _log_success "All required dependencies are present."
  return 0
}
